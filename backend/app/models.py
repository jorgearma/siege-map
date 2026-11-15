from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Optional


# Only techniques this sensor can actually observe. sshd never logs the
# password that was tried, so T1110.004 (credential stuffing) cannot be told
# apart from guessing and is deliberately absent.
MITRE_TTPS: dict[str, dict] = {
    "T1110":     {"name": "Brute Force", "tactic": "Credential Access"},
    "T1110.001": {"name": "Password Guessing", "tactic": "Credential Access"},
    "T1110.003": {"name": "Password Spraying", "tactic": "Credential Access"},
    "T1595":     {"name": "Active Scanning", "tactic": "Reconnaissance"},
    "T1595.002": {"name": "Vulnerability Scanning", "tactic": "Reconnaissance"},
    "T1190":     {"name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
    "T1078":     {"name": "Valid Accounts", "tactic": "Initial Access"},
}

MITRE_URLS: dict[str, str] = {
    t: "https://attack.mitre.org/techniques/" + t.replace(".", "/") + "/" for t in MITRE_TTPS
}


@dataclass
class GeoInfo:
    country: str = "Unknown"
    country_code: str = "XX"
    city: str = "Unknown"
    lat: float = 0.0
    lon: float = 0.0
    asn: str = ""
    org: str = ""
    # hosting | mobile | proxy | residential | unknown
    net_type: str = "unknown"
    # Cloud/hosting brand derived from the ASN name ("AWS", "DigitalOcean"...)
    cloud: str = ""


@dataclass
class SSHEvent:
    timestamp: str
    ip: str
    username: str
    event_type: str
    raw_line: str
    id: str = ""
    geo: Optional[GeoInfo] = None
    attack_pattern: str = ""
    mitre_ttps: list = field(default_factory=list)
    source: str = "ssh"
    http_status: int = 0
    # Log lines merged into this event (same ip/user/type within a minute)
    count: int = 1
    # Real authentication attempts represented (SSH only, see attempts.py)
    attempts: int = 0
    # Extra telemetry: device/os/browser/lang/ref/visitor/sig (HTTP),
    # banner/kex (SSH), tags
    meta: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        d = {
            "id": self.id,
            "timestamp": self.timestamp,
            "ip": self.ip,
            "username": self.username,
            "event_type": self.event_type,
            "raw_line": self.raw_line,
            "source": self.source,
        }
        if self.http_status:
            d["http_status"] = self.http_status
        if self.geo:
            d["geo"] = asdict(self.geo)
        if self.attack_pattern:
            d["attack_pattern"] = self.attack_pattern
        if self.mitre_ttps:
            d["mitre_ttps"] = self.mitre_ttps
        if self.meta:
            d["meta"] = self.meta
        return d


@dataclass
class AttackerProfile:
    ip: str
    total_attempts: int
    unique_usernames: int
    first_seen: str
    last_seen: str
    attack_pattern: str
    attack_speed: str
    requests_per_minute: float
    mitre_ttps: list
    usernames_attempted: list
    geo: Optional[GeoInfo]
    threat_score: int
    severity: str = "LOW"                      # LOW | MEDIUM | HIGH | CRITICAL
    score_breakdown: list = field(default_factory=list)  # [{factor, points, max, detail}]
    auth_attempts: int = 0
    abuse_confidence: int = 0
    abuse_total_reports: int = 0
    abuse_isp: str = ""
    shodan_ports: list = field(default_factory=list)
    shodan_os: str = ""
    http_routes: list = field(default_factory=list)  # [{path, status, count}]
    # Long-term data from SQLite (survives restarts)
    net_type: str = ""
    cloud: str = ""
    tags: list = field(default_factory=list)
    days_active: int = 0
    first_seen_ever: str = ""
    campaign: str = ""
    campaign_size: int = 0

    def to_dict(self) -> dict:
        return asdict(self)
