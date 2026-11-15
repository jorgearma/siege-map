import ipaddress
import json
import re
from datetime import datetime
from typing import Optional
from urllib.parse import urlsplit

from .config import settings
from .models import SSHEvent
from .signatures import match_signature
from .ua import parse_ua

# Nginx combined log format
NGINX_LOG_RE = re.compile(
    # IPv4 o IPv6 (Cloudflare pasa la IPv6 del visitante en CF-Connecting-IP)
    r'(?P<ip>[0-9A-Fa-f:.]+) - \S+ \[(?P<timestamp>[^\]]+)\] '
    r'"(?P<request>[^"]*)" (?P<status>\d{3}) \d+ '
    r'"(?P<referer>[^"]*)" "(?P<ua>[^"]*)"'
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

SEARCH_ENGINES = ('google.', 'bing.', 'duckduckgo.', 'yandex.', 'baidu.', 'ecosia.', 'brave.', 'yahoo.', 'startpage.')
SOCIAL = {
    'linkedin.com': 'linkedin', 'lnkd.in': 'linkedin',
    'github.com': 'github', 'github.io': 'github',
    't.co': 'twitter/x', 'twitter.com': 'twitter/x', 'x.com': 'twitter/x',
    'facebook.com': 'facebook', 'instagram.com': 'instagram',
    'reddit.com': 'reddit', 'youtube.com': 'youtube',
    'news.ycombinator.com': 'hackernews', 't.me': 'telegram',
    'whatsapp.com': 'whatsapp', 'infojobs.net': 'infojobs',
}


def _parse_ts(raw: str) -> str:
    """'13/Apr/2026:19:23:31 +0200' or ISO 8601 -> naive ISO"""
    try:
        if raw[:4].isdigit():
            return datetime.fromisoformat(raw).replace(tzinfo=None).isoformat()
        dt = datetime.strptime(raw.split(' ')[0], '%d/%b/%Y:%H:%M:%S')
        return dt.isoformat()
    except Exception:
        return datetime.now().isoformat()


def _split_request(request: str) -> tuple[str, str, str]:
    """'GET /a?b=1 HTTP/1.1' -> (method, path, full uri)"""
    parts = request.split(' ', 2)
    if len(parts) >= 2:
        return parts[0], parts[1].split('?')[0], parts[1]
    return (parts[0] if parts else '?'), request[:100], request[:100]


def classify_referrer(referer: str, host: str = '') -> str:
    """
    Reduce a referrer to its source. Only the SITE is kept, never the full
    URL: enough to know people arrive from LinkedIn, not which page they read.
    """
    if not referer or referer == '-':
        return 'direct'
    try:
        domain = (urlsplit(referer).hostname or '').lower()
    except ValueError:
        return 'other'
    if not domain:
        return 'other'
    if domain.startswith('www.'):
        domain = domain[4:]
    own = settings.own_domains | ({host.lower()} if host else set())
    if any(domain == d or domain.endswith('.' + d) for d in own if d):
        return 'internal'
    for known, label in SOCIAL.items():
        if domain == known or domain.endswith('.' + known):
            return label
    for engine in SEARCH_ENGINES:
        if domain.startswith(engine) or ('.' + engine) in domain:
            return 'search:' + engine.rstrip('.')
    return domain[:60]


def primary_language(accept_language: str) -> str:
    """'es-ES,es;q=0.9,en;q=0.8' -> 'es'"""
    if not accept_language or accept_language == '-':
        return ''
    first = accept_language.split(',')[0].split(';')[0].strip().lower()
    code = first.split('-')[0]
    return code if code.isalpha() and 2 <= len(code) <= 3 else ''


def _parse_json_line(line: str) -> Optional[dict]:
    """
    Structured access log (see docs/nginx-log-format.md):
      {"time","ip","method","uri","status","ua","referer","lang","country","host","rt"}
    """
    try:
        d = json.loads(line)
    except ValueError:
        return None
    if not isinstance(d, dict) or 'ip' not in d:
        return None
    uri = str(d.get('uri') or d.get('request_uri') or '/')
    try:
        status = int(d.get('status') or 0)
    except (TypeError, ValueError):
        status = 0
    return {
        'ip': str(d['ip']),
        'timestamp': str(d.get('time') or ''),
        'method': str(d.get('method') or '?'),
        'path': uri.split('?')[0],
        'uri': uri,
        'request': f"{d.get('method', '?')} {uri}",
        'status': status,
        'ua': str(d.get('ua') or ''),
        'referer': str(d.get('referer') or ''),
        'lang': str(d.get('lang') or ''),
        'host': str(d.get('host') or ''),
        'has_lang': True,   # this format always logs the header (empty = missing)
    }


def _parse_combined_line(line: str) -> Optional[dict]:
    m = NGINX_LOG_RE.match(line)
    if not m:
        return None
    request = m.group('request')
    method, path, uri = _split_request(request)
    return {
        'ip': m.group('ip'),
        'timestamp': m.group('timestamp'),
        'method': method,
        'path': path,
        'uri': uri,
        'request': request,
        'status': int(m.group('status')),
        'ua': m.group('ua'),
        'referer': m.group('referer'),
        'lang': '',
        'host': '',
        'has_lang': False,
    }


def is_static_asset(path: str) -> bool:
    return bool(STATIC_EXTENSIONS.search(path))


def parse_nginx_fields(line: str) -> Optional[dict]:
    """Raw fields of an access-log line (JSON or combined), public IPs only."""
    line = line.strip()
    if not line:
        return None
    f = _parse_json_line(line) if line.startswith('{') else _parse_combined_line(line)
    if not f:
        return None
    try:
        addr = ipaddress.ip_address(f['ip'])
    except ValueError:
        return None
    if not addr.is_global:  # privadas, loopback, link-local, reservadas (v4 y v6)
        return None
    return f


def parse_nginx_line(line: str) -> Optional[SSHEvent]:
    f = parse_nginx_fields(line)
    if not f:
        return None
    return classify_request(f, line.strip())


def classify_request(f: dict, raw_line: str = '') -> Optional[SSHEvent]:
    ip, status, ua = f['ip'], f['status'], f['ua']
    path, method, request = f['path'], f['method'], f['request']
    ua_lower = ua.lower()
    ts = _parse_ts(f['timestamp'])

    def event(etype: str, label: str, visitor: str, extra: Optional[dict] = None) -> SSHEvent:
        meta = {'visitor': visitor}
        sig = match_signature(f['uri'])
        if sig and visitor != 'human':
            meta['sig'] = sig.id
            meta['sig_name'] = sig.name
            meta['sig_product'] = sig.product
            meta['sig_kind'] = sig.kind
        if extra:
            meta.update(extra)
        return SSHEvent(
            timestamp=ts, ip=ip, username=label, event_type=etype,
            raw_line=raw_line, source='http', http_status=status, meta=meta,
        )

    # ── 1. Binary/exploit payload ─────────────────────────────
    binary = '\\x' in request or any(ord(c) < 32 for c in request)
    if binary or (status == 400 and len(request.strip()) < 4):
        return event('exploit_attempt', '(payload)', 'scanner')

    # ── 2. Known scanner user-agent ───────────────────────────
    if any(s in ua_lower for s in SCANNER_UA_FRAGMENTS):
        return event('scanner', path[:80], 'scanner')

    # ── 3. Sensitive path probe ───────────────────────────────
    for pattern, etype in THREAT_PATHS:
        if pattern.search(path):
            return event(etype, path[:80], 'scanner')

    # ── 3b. Known exploit / product probe (signatures.py) ─────
    sig = match_signature(f['uri'])
    if sig and sig.kind in ('exploit', 'c2'):
        return event('exploit_probe', path[:80], 'scanner')

    # ── 4. Suspicious POST (not to a known safe page) ────────
    if method == 'POST':
        return event('post_probe', f'POST {path[:75]}', 'scanner')

    # ── 5. Crawlers/bots (Googlebot, etc.) ────────────────────
    if any(b in ua_lower for b in BOT_UA_FRAGMENTS):
        return event('crawler', path[:80], 'crawler')

    # ── 6. Automated tools (curl, python-requests, etc.) ──────
    if any(a in ua_lower for a in AUTO_UA_FRAGMENTS):
        return event('auto_tool', path[:80], 'tool')

    # ── 7. 4xx errors (probing non-existent paths) ───────────
    if 400 <= status < 500:
        return event('http_error', path[:80], 'scanner')

    # ── 8. Static assets — skip (css, js, images) ────────────
    if STATIC_EXTENSIONS.search(path):
        return None

    # ── 9. Browser-looking request ────────────────────────────
    if len(ua.strip()) < 20:
        return None

    info = parse_ua(ua)
    lang = primary_language(f['lang'])
    # Headless/automation frameworks, impossible browser versions, or a
    # "browser" that sends no Accept-Language: a script wearing a browser UA.
    if info.automated or (f['has_lang'] and not lang):
        return event('fake_browser', path[:80], 'fake_browser', {
            'os': info.os, 'browser': info.browser,
        })

    extra = {
        'device': info.device,
        'os': info.os,
        'browser': info.browser,
        'ref': classify_referrer(f['referer'], f['host']),
    }
    if lang:
        extra['lang'] = lang
    return event(f'visit_{info.device}', path[:80] or '/', 'human', extra)
