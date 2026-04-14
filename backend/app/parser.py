import re
from datetime import datetime
from typing import Optional
from .models import SSHEvent

# Timestamp patterns:
#   Classic syslog:  Apr 13 19:18:25
#   Systemd/Ubuntu 24.04: 2026-04-13T19:18:25.691118+02:00
_TS = r"(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[\d.+:Z-]*|\w{3}\s+\d+\s+\d+:\d+:\d+)"

# Patterns for SSH bot activity
PATTERNS = [
    {
        "name": "failed_password",
        "regex": re.compile(
            _TS + r"\s+\S+\s+sshd\[\d+\]:\s+"
            r"Failed password for (?:invalid user )?(?P<username>\S+)\s+from\s+(?P<ip>\d+\.\d+\.\d+\.\d+)"
        ),
        "event_type": "failed_password",
    },
    {
        "name": "invalid_user",
        "regex": re.compile(
            _TS + r"\s+\S+\s+sshd\[\d+\]:\s+"
            r"Invalid user (?P<username>\S+)\s+from\s+(?P<ip>\d+\.\d+\.\d+\.\d+)"
        ),
        "event_type": "invalid_user",
    },
    {
        "name": "connection_closed_preauth",
        "regex": re.compile(
            _TS + r"\s+\S+\s+sshd\[\d+\]:\s+"
            r"Connection closed by (?:authenticating user (?P<username>\S+)\s+)?(?P<ip>\d+\.\d+\.\d+\.\d+)"
        ),
        "event_type": "connection_closed",
    },
    {
        "name": "disconnected_preauth",
        "regex": re.compile(
            _TS + r"\s+\S+\s+sshd\[\d+\]:\s+"
            r"Disconnected from (?:authenticating user (?P<username>\S+)\s+)?(?P<ip>\d+\.\d+\.\d+\.\d+)"
        ),
        "event_type": "disconnected",
    },
    {
        "name": "max_auth_exceeded",
        "regex": re.compile(
            _TS + r"\s+\S+\s+sshd\[\d+\]:\s+"
            r"error: maximum authentication attempts exceeded for (?:invalid user )?(?P<username>\S+)\s+from\s+(?P<ip>\d+\.\d+\.\d+\.\d+)"
        ),
        "event_type": "max_auth_exceeded",
    },
    {
        "name": "received_disconnect",
        "regex": re.compile(
            _TS + r"\s+\S+\s+sshd\[\d+\]:\s+"
            r"Received disconnect from (?P<ip>\d+\.\d+\.\d+\.\d+).*?(?:\[preauth\])"
        ),
        "event_type": "received_disconnect",
    },
    {
        "name": "bad_protocol",
        "regex": re.compile(
            _TS + r"\s+\S+\s+sshd\[\d+\]:\s+"
            r"Bad protocol version identification.*from\s+(?P<ip>\d+\.\d+\.\d+\.\d+)"
        ),
        "event_type": "bad_protocol",
    },
]

# IPv4 regex for extracting IPs when no pattern matches specifically
IP_REGEX = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")

# Private/reserved IP ranges to skip
PRIVATE_RANGES = [
    re.compile(r"^10\."),
    re.compile(r"^172\.(1[6-9]|2\d|3[01])\."),
    re.compile(r"^192\.168\."),
    re.compile(r"^127\."),
    re.compile(r"^0\."),
]


def is_private_ip(ip: str) -> bool:
    return any(r.match(ip) for r in PRIVATE_RANGES)


def normalize_timestamp(raw_ts: str) -> str:
    """Convert syslog or systemd timestamp to ISO format."""
    now = datetime.now()
    # Systemd format: 2026-04-13T19:18:25.691118+02:00
    if raw_ts and raw_ts[0].isdigit():
        try:
            return datetime.fromisoformat(raw_ts).isoformat()
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
            ip = groups.get("ip", "")
            if not ip or is_private_ip(ip):
                return None

            username = groups.get("username", "")
            timestamp = normalize_timestamp(groups.get("timestamp", ""))

            return SSHEvent(
                timestamp=timestamp,
                ip=ip,
                username=username or "(none)",
                event_type=pattern["event_type"],
                raw_line=line,
            )

    return None
