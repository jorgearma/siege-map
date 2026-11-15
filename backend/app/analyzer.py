"""
Per-address behaviour analysis: attack pattern, MITRE ATT&CK mapping and an
explainable threat score.

What the sensor can and cannot see matters for the labels:

  * sshd logs WHICH USER was tried, never the password. So an attack is
    classified by its shape (how many accounts, how many tries per account),
    not by its credentials. Credential stuffing (T1110.004) is not
    observable from here and is never claimed.
  * HTTP addresses arrive truncated to /24 (anonymize.py): an HTTP "address"
    is a small network, not one host.

Patterns
  SINGLE_PROBE        one or two lines, then gone
  PASSWORD_GUESSING   few accounts, many tries each            T1110.001
  PASSWORD_SPRAYING   many accounts, one or two tries each     T1110.003
  DICTIONARY_ATTACK   many accounts AND many tries each        T1110.001
  SSH_SCANNING        talks to sshd but never tries a user     T1595
  WEB_SCANNING        HTTP probes / exploit attempts           T1595.002 (+T1190)
"""
import math
from collections import Counter, defaultdict
from datetime import datetime
from typing import Optional

from .cache import TTLCache
from .models import AttackerProfile, MITRE_TTPS
from .store import store as _store

_CACHE_TTL = 30.0
_profile_cache = TTLCache(maxsize=5000, ttl=_CACHE_TTL)

# An address trying this many different accounts is working through a list
MANY_ACCOUNTS = 6
# Up to this many tries per account still looks like "one password each"
SPRAY_TRIES_PER_ACCOUNT = 3.0

SEVERITIES = ("LOW", "MEDIUM", "HIGH", "CRITICAL")
_BEHAVIOUR_MAX = 85
_REPUTATION_MAX = 15


def severity_for(score: int) -> str:
    if score >= 75:
        return "CRITICAL"
    if score >= 50:
        return "HIGH"
    if score >= 25:
        return "MEDIUM"
    return "LOW"


def _log_scale(value: float, saturates_at: float) -> float:
    """0..1, logarithmic: the first units matter more than the last."""
    if value <= 0:
        return 0.0
    return min(1.0, math.log1p(value) / math.log1p(saturates_at))


def classify(
    n_users: int, attempts: int, lines: int,
    http_lines: int = 0, exploit: bool = False,
) -> tuple[str, list[str]]:
    """Attack pattern + MITRE techniques from the shape of the activity."""
    ttps: list[str] = []
    if http_lines:
        ttps.append("T1595.002")
        if exploit:
            ttps.append("T1190")

    if n_users == 0:
        if http_lines:
            return "WEB_SCANNING", ttps
        if lines <= 2:
            return "SINGLE_PROBE", ["T1595"]
        return "SSH_SCANNING", ["T1595"]

    if lines <= 2:
        return "SINGLE_PROBE", ["T1110"] + ttps

    tries_per_account = (attempts or lines) / n_users
    if n_users >= MANY_ACCOUNTS:
        if tries_per_account <= SPRAY_TRIES_PER_ACCOUNT:
            return "PASSWORD_SPRAYING", ["T1110.003"] + ttps
        return "DICTIONARY_ATTACK", ["T1110.001"] + ttps
    return "PASSWORD_GUESSING", ["T1110.001"] + ttps


def classify_speed(rpm: float) -> str:
    if rpm > 10:
        return "BRUTE_FORCE"
    if rpm >= 2:
        return "MODERATE"
    return "SLOW_SCAN"


def score_ip(
    volume: int, rpm: float, breadth: int,
    days_active: int = 1, exploit: bool = False, multi_vector: bool = False,
    abuse_confidence: Optional[int] = None,
) -> dict:
    """
    Threat score 0-100 with its breakdown.

    85 points come from what the address DID here (always available), 15 from
    public reputation (AbuseIPDB). When the reputation is unknown it is treated
    as neutral — it gets the same share the behaviour earned — so an address
    is never capped just because nobody looked it up.
    """
    parts = [
        ("volume", 25 * _log_scale(volume, 500), 25, f"{volume} attempts"),
        ("rate", 20 * _log_scale(rpm, 30), 20, f"{rpm:.1f}/min"),
        ("breadth", 15 * _log_scale(breadth, 50), 15, f"{breadth} distinct targets"),
        ("persistence", min(15.0, 3.0 * max(0, days_active - 1)), 15,
         f"active on {days_active} day(s)"),
        ("intent", (6 if exploit else 0) + (4 if multi_vector else 0), 10,
         ", ".join(x for x, on in (("exploit signature", exploit),
                                   ("SSH + HTTP", multi_vector)) if on) or "—"),
    ]
    behaviour = sum(p[1] for p in parts)
    if abuse_confidence is None:
        reputation = behaviour / _BEHAVIOUR_MAX * _REPUTATION_MAX
        rep_detail = "unknown (neutral)"
    else:
        reputation = abuse_confidence / 100 * _REPUTATION_MAX
        rep_detail = f"AbuseIPDB {abuse_confidence}%"
    parts.append(("reputation", reputation, _REPUTATION_MAX, rep_detail))

    score = max(0, min(100, round(behaviour + reputation)))
    return {
        "score": score,
        "severity": severity_for(score),
        "breakdown": [
            {"factor": name, "points": round(pts, 1), "max": top, "detail": detail}
            for name, pts, top, detail in parts
        ],
    }


class Analyzer:

    # ── Public API ────────────────────────────────────────────

    def get_attacker_profile(
        self,
        ip: str,
        window: Optional[int] = None,
        abuse_data: Optional[dict] = None,
    ) -> Optional[AttackerProfile]:
        cache_key = (ip, window)
        if not abuse_data:
            cached = _profile_cache.get(cache_key)
            if cached is not None:
                return cached

        events = _store.events_for_ip(ip, window)
        if not events:
            return None

        events_sorted = sorted(events, key=lambda e: e.timestamp)
        # HTTP events reuse `username` for the path: only SSH ones are usernames
        unique_usernames = {
            e.username for e in events_sorted
            if e.source == "ssh" and e.username and e.username != "(none)"
        }
        total = sum(e.count for e in events_sorted)
        attempts = sum(e.attempts for e in events_sorted)
        http_lines = sum(e.count for e in events_sorted if e.source == "http")
        exploit = any(e.meta.get("sig_kind") == "exploit" for e in events_sorted)

        rpm = self._calc_rpm(events_sorted)
        pattern, ttps = classify(len(unique_usernames), attempts, total, http_lines, exploit)

        # HTTP routes with status codes
        route_statuses: dict[str, Counter] = defaultdict(Counter)
        for e in events_sorted:
            if e.source == "http":
                route_statuses[e.username][e.http_status] += e.count
        http_routes = []
        for path, statuses in sorted(route_statuses.items(), key=lambda x: -sum(x[1].values())):
            top = statuses.most_common(1)
            http_routes.append({
                "path": path,
                "status": top[0][0] if top else 0,
                "count": sum(statuses.values()),
            })

        abuse_confidence = abuse_data.get("abuse_confidence") if abuse_data else None
        scored = score_ip(
            volume=attempts or total, rpm=rpm,
            breadth=len(unique_usernames) or len(http_routes),
            exploit=exploit, multi_vector=bool(unique_usernames and http_lines),
            abuse_confidence=abuse_confidence,
        )

        profile = AttackerProfile(
            ip=ip,
            total_attempts=total,
            auth_attempts=attempts,
            unique_usernames=len(unique_usernames),
            first_seen=events_sorted[0].timestamp,
            last_seen=events_sorted[-1].timestamp,
            attack_pattern=pattern,
            attack_speed=classify_speed(rpm),
            requests_per_minute=round(rpm, 2),
            mitre_ttps=ttps,
            usernames_attempted=sorted(unique_usernames)[:50],
            geo=events_sorted[-1].geo,
            threat_score=scored["score"],
            severity=scored["severity"],
            score_breakdown=scored["breakdown"],
            abuse_confidence=abuse_confidence or 0,
            abuse_total_reports=(abuse_data or {}).get("total_reports", 0),
            abuse_isp=(abuse_data or {}).get("isp", ""),
            http_routes=http_routes,
        )

        _profile_cache.set(cache_key, profile)
        return profile

    def get_all_profiles(
        self, window: Optional[int] = None, limit: int = 20
    ) -> list[AttackerProfile]:
        profiles = []
        for ip in _store.ips(window):
            p = self.get_attacker_profile(ip, window)
            if p:
                profiles.append(p)

        profiles.sort(key=lambda p: p.threat_score, reverse=True)
        return profiles[:limit]

    def get_attack_pattern_summary(self, window: Optional[int] = None) -> dict:
        """Addresses per attack pattern (same classifier as the profiles)."""
        patterns: Counter = Counter()
        for ip in _store.ips(window):
            p = self.get_attacker_profile(ip, window)
            if p:
                patterns[p.attack_pattern] += 1
        return dict(patterns)

    def get_mitre_summary(self, window: Optional[int] = None) -> list[dict]:
        """Addresses using each ATT&CK technique, most used first."""
        counts: Counter = Counter()
        for ip in _store.ips(window):
            p = self.get_attacker_profile(ip, window)
            if p:
                counts.update(p.mitre_ttps)
        return [
            {"id": ttp, "name": MITRE_TTPS.get(ttp, {}).get("name", ttp),
             "tactic": MITRE_TTPS.get(ttp, {}).get("tactic", ""), "count": n}
            for ttp, n in counts.most_common()
        ]

    def get_asn_summary(
        self, window: Optional[int] = None, limit: int = 10
    ) -> list[dict]:
        events = _store._filter_by_window(window)
        counter: Counter = Counter()
        for e in events:
            if e.geo and e.geo.org:
                counter[e.geo.org] += e.count
        return [{"asn": k, "count": v} for k, v in counter.most_common(limit)]

    def get_heatmap(self, window: Optional[int] = None) -> list[list[int]]:
        """7×24 grid: [day_of_week (0=Mon)][hour] → event count."""
        effective_window = window or (7 * 86400)
        events = _store._filter_by_window(effective_window)
        grid = [[0] * 24 for _ in range(7)]
        for e in events:
            try:
                dt = datetime.fromisoformat(e.timestamp)
                grid[dt.weekday()][dt.hour] += e.count
            except Exception:
                pass
        return grid

    def quick_classify(self, ip: str) -> tuple[str, list[str]]:
        """O(1) WS enrichment — only uses warm cache, skips if cold."""
        profile = _profile_cache.get((ip, None))
        if profile is not None:
            return profile.attack_pattern, profile.mitre_ttps
        return "", []

    # ── Internals ────────────────────────────────────────────

    def _calc_rpm(self, events: list) -> float:
        if len(events) < 2:
            return 0.0
        try:
            t0 = datetime.fromisoformat(events[0].timestamp)
            t1 = datetime.fromisoformat(events[-1].timestamp)
            elapsed_min = (t1 - t0).total_seconds() / 60
            if elapsed_min < 0.05:
                return float(sum(e.count for e in events))
            return sum(e.count for e in events) / elapsed_min
        except Exception:
            return 0.0


analyzer = Analyzer()
