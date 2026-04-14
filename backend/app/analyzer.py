import time
from collections import Counter, defaultdict
from datetime import datetime
from typing import Optional

from .models import AttackerProfile, MITRE_TTPS
from .store import store as _store

_profile_cache: dict[str, tuple[AttackerProfile, float]] = {}
_CACHE_TTL = 30.0


class Analyzer:

    # ── Public API ────────────────────────────────────────────

    def get_attacker_profile(
        self,
        ip: str,
        window: Optional[int] = None,
        abuse_data: Optional[dict] = None,
    ) -> Optional[AttackerProfile]:
        cache_key = f"{ip}:{window}"
        now = time.time()
        if cache_key in _profile_cache and not abuse_data:
            profile, cached_at = _profile_cache[cache_key]
            if now - cached_at < _CACHE_TTL:
                return profile

        events = _store.events_for_ip(ip, window)
        if not events:
            return None

        events_sorted = sorted(events, key=lambda e: e.timestamp)
        unique_usernames = {e.username for e in events_sorted if e.username and e.username != "(none)"}
        total = len(events_sorted)
        first_seen = events_sorted[0].timestamp
        last_seen = events_sorted[-1].timestamp

        rpm = self._calc_rpm(events_sorted)
        pattern, ttps = self._classify_pattern(unique_usernames, rpm, total)
        speed = self._classify_speed(rpm)

        abuse_confidence = 0
        abuse_total_reports = 0
        abuse_isp = ""
        if abuse_data:
            abuse_confidence = abuse_data.get("abuse_confidence", 0)
            abuse_total_reports = abuse_data.get("total_reports", 0)
            abuse_isp = abuse_data.get("isp", "")

        score = self.calc_threat_score(rpm, pattern, total, abuse_confidence)
        geo = events_sorted[-1].geo

        # HTTP routes with status codes
        route_statuses: dict[str, Counter] = defaultdict(Counter)
        for e in events_sorted:
            if e.source == "http":
                route_statuses[e.username][e.http_status] += 1
        http_routes = []
        for path, statuses in sorted(route_statuses.items(), key=lambda x: -sum(x[1].values())):
            top = statuses.most_common(1)
            http_routes.append({
                "path": path,
                "status": top[0][0] if top else 0,
                "count": sum(statuses.values()),
            })

        profile = AttackerProfile(
            ip=ip,
            total_attempts=total,
            unique_usernames=len(unique_usernames),
            first_seen=first_seen,
            last_seen=last_seen,
            attack_pattern=pattern,
            attack_speed=speed,
            requests_per_minute=round(rpm, 2),
            mitre_ttps=ttps,
            usernames_attempted=sorted(unique_usernames)[:50],
            geo=geo,
            threat_score=score,
            abuse_confidence=abuse_confidence,
            abuse_total_reports=abuse_total_reports,
            abuse_isp=abuse_isp,
            http_routes=http_routes,
        )

        _profile_cache[cache_key] = (profile, now)
        return profile

    def get_all_profiles(
        self, window: Optional[int] = None, limit: int = 20
    ) -> list[AttackerProfile]:
        events = _store._filter_by_window(window)
        ip_set = {e.ip for e in events}

        profiles = []
        for ip in ip_set:
            p = self.get_attacker_profile(ip, window)
            if p:
                profiles.append(p)

        profiles.sort(key=lambda p: p.threat_score, reverse=True)
        return profiles[:limit]

    def get_attack_pattern_summary(self, window: Optional[int] = None) -> dict:
        events = _store._filter_by_window(window)

        # Detect CREDENTIAL_STUFFING: same username from >3 distinct IPs
        username_ips: dict[str, set] = defaultdict(set)
        for e in events:
            if e.username and e.username != "(none)":
                username_ips[e.username].add(e.ip)
        cred_stuff_usernames = {u for u, ips in username_ips.items() if len(ips) > 3}

        ip_events: dict[str, list] = defaultdict(list)
        for e in events:
            ip_events[e.ip].append(e)

        patterns: dict[str, int] = defaultdict(int)
        for ip, evts in ip_events.items():
            ip_users = {e.username for e in evts if e.username != "(none)"}
            n = len(evts)
            if n <= 2:
                patterns["SINGLE_PROBE"] += 1
            elif ip_users & cred_stuff_usernames and len(ip_users) <= 3:
                patterns["CREDENTIAL_STUFFING"] += 1
            elif len(ip_users) > 5:
                patterns["DICTIONARY_ATTACK"] += 1
            else:
                patterns["PASSWORD_SPRAYING"] += 1

        return dict(patterns)

    def get_asn_summary(
        self, window: Optional[int] = None, limit: int = 10
    ) -> list[dict]:
        events = _store._filter_by_window(window)
        counter: Counter = Counter()
        for e in events:
            if e.geo and e.geo.org:
                counter[e.geo.org] += 1
        return [{"asn": k, "count": v} for k, v in counter.most_common(limit)]

    def get_heatmap(self, window: Optional[int] = None) -> list[list[int]]:
        """7×24 grid: [day_of_week (0=Mon)][hour] → event count."""
        effective_window = window or (7 * 86400)
        events = _store._filter_by_window(effective_window)
        grid = [[0] * 24 for _ in range(7)]
        for e in events:
            try:
                dt = datetime.fromisoformat(e.timestamp)
                grid[dt.weekday()][dt.hour] += 1
            except Exception:
                pass
        return grid

    def quick_classify(self, ip: str) -> tuple[str, list[str]]:
        """O(1) WS enrichment — only uses warm cache, skips if cold."""
        cache_key = f"{ip}:None"
        now = time.time()
        if cache_key in _profile_cache:
            profile, cached_at = _profile_cache[cache_key]
            if now - cached_at < _CACHE_TTL:
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
                return float(len(events))
            return len(events) / elapsed_min
        except Exception:
            return 0.0

    def _classify_pattern(
        self, unique_usernames: set, rpm: float, total: int
    ) -> tuple[str, list[str]]:
        ttps = ["T1021.004"]
        n = len(unique_usernames)

        if total <= 2:
            return "SINGLE_PROBE", ttps

        if n > 5:
            ttps.append("T1110.001")
            return "DICTIONARY_ATTACK", ttps

        if n <= 3:
            ttps.append("T1110.003")
            return "PASSWORD_SPRAYING", ttps

        ttps.append("T1110.001")
        return "DICTIONARY_ATTACK", ttps

    def _classify_speed(self, rpm: float) -> str:
        if rpm > 10:
            return "BRUTE_FORCE"
        if rpm >= 2:
            return "MODERATE"
        return "SLOW_SCAN"

    def calc_threat_score(
        self, rpm: float, pattern: str, attempts: int, abuse_confidence: int
    ) -> int:
        speed_score = {"BRUTE_FORCE": 80, "MODERATE": 40, "SLOW_SCAN": 20}.get(
            self._classify_speed(rpm), 20
        )
        pattern_score = {
            "DICTIONARY_ATTACK": 60,
            "CREDENTIAL_STUFFING": 70,
            "PASSWORD_SPRAYING": 50,
            "SINGLE_PROBE": 10,
        }.get(pattern, 20)
        volume_score = min(attempts / 10 * 100, 100)

        score = (
            abuse_confidence * 0.4
            + speed_score * 0.25
            + pattern_score * 0.25
            + volume_score * 0.1
        )
        return min(100, int(score))


analyzer = Analyzer()
