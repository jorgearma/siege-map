import ipaddress
import re
from datetime import datetime
from typing import Optional
from .models import SSHEvent

# Nginx combined log format
NGINX_LOG_RE = re.compile(
    # IPv4 o IPv6 (Cloudflare pasa la IPv6 del visitante en CF-Connecting-IP)
    r'(?P<ip>[0-9A-Fa-f:.]+) - \S+ \[(?P<timestamp>[^\]]+)\] '
    r'"(?P<request>[^"]*)" (?P<status>\d{3}) \d+ '
    r'"[^"]*" "(?P<ua>[^"]*)"'
)

# Threat classification by path pattern (order matters — first match wins)
THREAT_PATHS = [
    (re.compile(r'\.git(?:/|$|config|ignore)', re.I),                         'git_exposure'),
    (re.compile(r'\.env(?:\.|$)', re.I),                                       'secret_probe'),
    (re.compile(r'wp-config|\.htpasswd|id_rsa|authorized_keys|secrets\.yml|database\.yml', re.I), 'secret_probe'),
    (re.compile(r'wp-admin|wp-login\.php|xmlrpc\.php|phpmyadmin|adminer\.php', re.I), 'cms_scan'),
    (re.compile(r'\.\./|%2e%2e|/etc/passwd|/etc/shadow|/proc/self',           re.I), 'path_traversal'),
    (re.compile(r'\.htaccess|\.ssh/',                                          re.I), 'secret_probe'),
    (re.compile(r'shell\.php|cmd\.php|webshell|backdoor|c99\.php|r57\.php',   re.I), 'php_probe'),
    (re.compile(r'config\.php|settings\.py',                                   re.I), 'secret_probe'),
]

SCANNER_UA_FRAGMENTS = [
    'sqlmap', 'nikto', 'masscan', 'nmap', 'zgrab', 'dirbuster',
    'gobuster', 'wfuzz', 'nuclei', 'visionheight', '/scan',
]

# Bots/crawlers — traffic but not human
BOT_UA_FRAGMENTS = [
    'googlebot', 'bingbot', 'yandexbot', 'baiduspider', 'twitterbot',
    'facebookexternalhit', 'linkedinbot', 'slackbot', 'discordbot',
    'applebot', 'duckduckbot', 'semrushbot', 'ahrefsbot', 'mj12bot',
    'dotbot', 'petalbot', 'bytespider', 'gptbot', 'claudebot',
    'bot/', '/bot', 'crawler', 'spider',
]

# Automated tools — suspicious but not necessarily scanners
AUTO_UA_FRAGMENTS = [
    'python-requests', 'go-http-client', 'wget/', 'curl/',
    'java/', 'libwww', 'httpx', 'axios',
]

# Static assets — shown as visit but not as page view
STATIC_EXTENSIONS = re.compile(
    r'\.(js|css|png|jpg|jpeg|gif|svg|ico|woff|woff2|ttf|eot|map|webp|avif)(\?|$)',
    re.I
)

# Mobile/tablet detection
MOBILE_RE = re.compile(r'Mobile|Android|iPhone|iPod', re.I)
TABLET_RE = re.compile(r'iPad|Tablet|tablet', re.I)


def _parse_ts(raw: str) -> str:
    """'13/Apr/2026:19:23:31 +0200' -> ISO"""
    try:
        dt = datetime.strptime(raw.split(' ')[0], '%d/%b/%Y:%H:%M:%S')
        return dt.isoformat()
    except Exception:
        return datetime.now().isoformat()


def _extract_path(request: str) -> str:
    parts = request.split(' ', 2)
    if len(parts) >= 2:
        return parts[1].split('?')[0]
    return request[:100]


def _extract_method(request: str) -> str:
    parts = request.split(' ', 2)
    return parts[0] if parts else '?'


def _detect_device(ua: str) -> str:
    if TABLET_RE.search(ua):
        return 'tablet'
    if MOBILE_RE.search(ua):
        return 'mobile'
    return 'desktop'


def parse_nginx_line(line: str) -> Optional[SSHEvent]:
    line = line.strip()
    if not line:
        return None

    m = NGINX_LOG_RE.match(line)
    if not m:
        return None

    ip = m.group('ip')
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    if not addr.is_global:  # privadas, loopback, link-local, reservadas (v4 y v6)
        return None

    request = m.group('request')
    status = int(m.group('status'))
    ua = m.group('ua')
    raw_ts = m.group('timestamp')
    path = _extract_path(request)
    method = _extract_method(request)
    ua_lower = ua.lower()

    # ── 1. Binary/exploit payload ─────────────────────────────
    if '\\x' in request or (status == 400 and len(request.strip()) < 4):
        return SSHEvent(
            timestamp=_parse_ts(raw_ts),
            ip=ip, username='(payload)',
            event_type='exploit_attempt',
            raw_line=line, source='http', http_status=status,
        )

    # ── 2. Known scanner user-agent ───────────────────────────
    if any(s in ua_lower for s in SCANNER_UA_FRAGMENTS):
        return SSHEvent(
            timestamp=_parse_ts(raw_ts),
            ip=ip, username=path[:80],
            event_type='scanner',
            raw_line=line, source='http', http_status=status,
        )

    # ── 3. Sensitive path probe ───────────────────────────────
    for pattern, etype in THREAT_PATHS:
        if pattern.search(path):
            return SSHEvent(
                timestamp=_parse_ts(raw_ts),
                ip=ip, username=path[:80],
                event_type=etype,
                raw_line=line, source='http', http_status=status,
            )

    # ── 4. Suspicious POST (not to a known safe page) ────────
    if method == 'POST':
        return SSHEvent(
            timestamp=_parse_ts(raw_ts),
            ip=ip, username=f'POST {path[:75]}',
            event_type='post_probe',
            raw_line=line, source='http', http_status=status,
        )

    # ── 5. Crawlers/bots (Googlebot, etc.) ────────────────────
    if any(b in ua_lower for b in BOT_UA_FRAGMENTS):
        return SSHEvent(
            timestamp=_parse_ts(raw_ts),
            ip=ip, username=path[:80],
            event_type='crawler',
            raw_line=line, source='http', http_status=status,
        )

    # ── 6. Automated tools (curl, python-requests, etc.) ──────
    if any(a in ua_lower for a in AUTO_UA_FRAGMENTS):
        return SSHEvent(
            timestamp=_parse_ts(raw_ts),
            ip=ip, username=path[:80],
            event_type='auto_tool',
            raw_line=line, source='http', http_status=status,
        )

    # ── 7. 4xx errors (probing non-existent paths) ───────────
    if 400 <= status < 500:
        return SSHEvent(
            timestamp=_parse_ts(raw_ts),
            ip=ip, username=path[:80],
            event_type='http_error',
            raw_line=line, source='http', http_status=status,
        )

    # ── 8. Static assets — skip (css, js, images) ────────────
    if STATIC_EXTENSIONS.search(path):
        return None

    # ── 9. Real human visit ───────────────────────────────────
    if len(ua.strip()) < 20:
        return None

    device = _detect_device(ua)

    return SSHEvent(
        timestamp=_parse_ts(raw_ts),
        ip=ip,
        username=path[:80] or '/',
        event_type=f'visit_{device}',
        raw_line=line,
        source='http',
        http_status=status,
    )
