import ipaddress
import re
from datetime import datetime
from typing import Optional
from .models import SSHEvent

# Timestamp patterns:
#   Classic syslog:  Apr 13 19:18:25
#   Systemd/Ubuntu 24.04: 2026-04-13T19:18:25.691118+02:00
_TS = r"(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[\d.+:Z-]*|\w{3}\s+\d+\s+\d+:\d+:\d+)"

# OpenSSH >= 9.8 splits the daemon: lines come from "sshd-session[pid]"
# (and "sshd-auth[pid]" in 10.x) instead of "sshd[pid]".
_PROC = r"\s+\S+\s+sshd(?:-session|-auth)?\[\d+\]:\s+"

# IPv4 or IPv6 — validated afterwards with ipaddress
_IP = r"(?P<ip>[0-9A-Fa-f:.]+)"

_USER_PREFIX = r"(?:(?:invalid|authenticating) user (?P<username>\S+)\s+)?"

# Patterns for SSH bot activity (order matters — first match wins)
PATTERNS = [
    {
        "regex": re.compile(
            _TS + _PROC
            + r"Failed password for (?:invalid user )?(?P<username>\S+)\s+from\s+" + _IP
        ),
        "event_type": "failed_password",
    },
    {
        "regex": re.compile(
            _TS + _PROC + r"Invalid user (?P<username>\S+)\s+from\s+" + _IP
        ),
        "event_type": "invalid_user",
    },
    {
        "regex": re.compile(
            _TS + _PROC + r"Connection closed by " + _USER_PREFIX + _IP + r"\s+port"
        ),
        "event_type": "connection_closed",
    },
    {
        "regex": re.compile(
            _TS + _PROC + r"Disconnected from " + _USER_PREFIX + _IP + r"\s+port"
        ),
        "event_type": "disconnected",
    },
    {
        "regex": re.compile(
            _TS + _PROC
            + r"error: maximum authentication attempts exceeded for (?:invalid user )?(?P<username>\S+)\s+from\s+" + _IP
        ),
        "event_type": "max_auth_exceeded",
    },
    {
        "regex": re.compile(
            _TS + _PROC + r"Received disconnect from " + _IP + r".*?(?:\[preauth\])"
        ),
        "event_type": "received_disconnect",
    },
    {
        # What the client sent instead of an SSH banner (HTTP requests, RDP, TLS...)
        "regex": re.compile(
            _TS + _PROC
            + r"Bad protocol version identification (?:'(?P<banner>.*)' )?.*?from\s+" + _IP
        ),
        "event_type": "bad_protocol",
    },
    {
        # OpenSSH >= 8.x wording of the same thing
        "regex": re.compile(
            _TS + _PROC
            + r"(?:error: kex_exchange_identification: |banner exchange: )"
            r"Connection from " + _IP + r" port \d+: (?P<banner>.*)"
        ),
        "event_type": "bad_protocol",
    },
    {
        # Legacy clients/bots: reveals which algorithms the tool offers
        "regex": re.compile(
            _TS + _PROC
            + r"Unable to negotiate with " + _IP + r" port \d+: no matching (?P<kex_kind>[\w ]+?) found\."
            r"(?: Their offer: (?P<kex>\S+))?"
        ),
        "event_type": "kex_mismatch",
    },
    {
        "regex": re.compile(
            _TS + _PROC + r"Did not receive identification string from " + _IP
        ),
        "event_type": "no_banner",
    },
]


def is_private_ip(ip: str) -> bool:
    """True for anything that is not a routable public address (v4 or v6)."""
    try:
        return not ipaddress.ip_address(ip).is_global
    except ValueError:
        return True


def normalize_timestamp(raw_ts: str) -> str:
    """Convert syslog or systemd timestamp to ISO format."""
    now = datetime.now()
    # Systemd format: 2026-04-13T19:18:25.691118+02:00
    if raw_ts and raw_ts[0].isdigit():
        try:
            # Naive local time: every other timestamp in the app is naive
            return datetime.fromisoformat(raw_ts).replace(tzinfo=None).isoformat()
        except ValueError:
            pass
    # Classic syslog format: Apr 13 19:18:25
    try:
        parsed = datetime.strptime(raw_ts.strip(), "%b %d %H:%M:%S")
        parsed = parsed.replace(year=now.year)
        if parsed.month > now.month + 1:
            parsed = parsed.replace(year=now.year - 1)
        return parsed.isoformat()
    except ValueError:
        return now.isoformat()


def _clean(text: str, limit: int = 60) -> str:
    """Printable, bounded version of attacker-controlled text."""
    return "".join(c if 32 <= ord(c) < 127 else "?" for c in text)[:limit]


def parse_line(line: str) -> Optional[SSHEvent]:
    """Parse a single log line and return an SSHEvent if it matches known patterns."""
    line = line.strip()
    if not line:
        return None

    if "sshd" not in line:
        return None

    for pattern in PATTERNS:
        match = pattern["regex"].search(line)
        if match:
            groups = match.groupdict()
            ip = (groups.get("ip") or "").rstrip(".:")
            if not ip or is_private_ip(ip):
                return None

            username = groups.get("username") or ""
            timestamp = normalize_timestamp(groups.get("timestamp", ""))

            meta = {}
            if groups.get("banner"):
                meta["banner"] = _clean(groups["banner"])
            if groups.get("kex"):
                meta["kex"] = _clean(groups["kex"], 120)
            if groups.get("kex_kind"):
                meta["kex_kind"] = _clean(groups["kex_kind"], 40)

            return SSHEvent(
                timestamp=timestamp,
                ip=ip,
                username=_clean(username, 64) or "(none)",
                event_type=pattern["event_type"],
                raw_line=line,
                meta=meta,
            )

    return None
