"""
Alerting: turn detections into a short list a person can act on.

Rules (every threshold is an env var, see config.py):

  login_success    an address that was failing logins got one ACCEPTED   CRITICAL
  exploit_2xx      a known exploit path was answered with 2xx            HIGH
  high_score       an active address reached the score threshold         by score
  campaign         a MEDIUM/HIGH-confidence campaign is active           by campaign
  burst            traffic far above this sensor's own baseline          MEDIUM/HIGH
  country_surge    many new addresses from one country at once           MEDIUM
  user_spray       one address trying a large number of accounts         MEDIUM

Noise control — the part that makes it usable:

  * One alert per (rule, subject). While the condition keeps holding, the
    existing alert is UPDATED (hits, last_seen), not repeated.
  * It is resolved once the condition has been absent for ALERT_COOLDOWN
    seconds. Only after that can the same subject raise a new alert.
  * A raised alert is re-announced only if its severity goes up.
  * Volume rules compare against the sensor's own recent history (mean + 3σ,
    or a multiple of the median), never against a fixed "N events": an
    exposed server has a permanent background of bots.
"""
import statistics
import uuid
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Callable, Optional

from .analyzer import SEVERITIES
from .config import settings

SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITIES)}

BURST_WINDOW_MIN = 5
SURGE_BUCKET_MIN = 10
# The country's share of the active addresses must grow at least this much
SURGE_SHARE_LIFT = 2.0


def _minute(ts: str) -> Optional[datetime]:
    try:
        return datetime.fromisoformat(ts[:16])
    except ValueError:
        return None


class AlertEngine:
    def __init__(self, store, analyzer, cooldown: Optional[float] = None,
                 persist: Optional[Callable[[dict], None]] = None):
        self.store = store
        self.analyzer = analyzer
        self.cooldown = settings.ALERT_COOLDOWN if cooldown is None else cooldown
        self.persist = persist or (lambda alert: None)
        # (rule, key) -> alert that is currently raised
        self.active: dict[tuple[str, str], dict] = {}

    # ── state ────────────────────────────────────────────────

    def restore(self, alerts: list[dict]) -> None:
        """Re-raise what was active before a restart."""
        for a in alerts:
            self.active[(a["rule"], a["key"])] = a

    def raise_alert(self, cand: dict, now: Optional[datetime] = None) -> Optional[dict]:
        """
        Raise or refresh one alert. Returns it only when it should be
        ANNOUNCED (new, or more severe than before); otherwise None.
        """
        now = now or datetime.now()
        stamp = now.isoformat(timespec="seconds")
        ident = (cand["rule"], cand["key"])
        current = self.active.get(ident)
        if current is not None:
            current["last_seen"] = stamp
            current["hits"] += 1
            current["detail"] = cand.get("detail", current["detail"])
            escalated = SEVERITY_RANK[cand["severity"]] > SEVERITY_RANK[current["severity"]]
            if escalated:
                current["severity"] = cand["severity"]
                current["title"] = cand["title"]
            self.persist(current)
            return self._with_private(current, cand) if escalated else None

        alert = {
            "id": uuid.uuid4().hex[:12],
            "ts": stamp,
            "last_seen": stamp,
            "rule": cand["rule"],
            "key": cand["key"],
            "severity": cand["severity"],
            "title": cand["title"],
            "detail": cand.get("detail", ""),
            "ip": cand.get("ip", ""),
            "mitre": cand.get("mitre", []),
            "hits": 1,
            "status": "active",
        }
        self.active[ident] = alert
        self.persist(alert)
        return self._with_private(alert, cand)

    @staticmethod
    def _with_private(alert: dict, cand: dict) -> dict:
        # `private` goes to the operator's webhook only: it is never stored
        # nor served by the public API
        return {**alert, "private": cand["private"]} if cand.get("private") else alert

    def resolve_stale(self, now: Optional[datetime] = None) -> list[dict]:
        now = now or datetime.now()
        limit = (now - timedelta(seconds=self.cooldown)).isoformat(timespec="seconds")
        resolved = []
        for ident, alert in list(self.active.items()):
            if alert["last_seen"] < limit:
                alert["status"] = "resolved"
                self.persist(alert)
                del self.active[ident]
                resolved.append(alert)
        return resolved

    def active_alerts(self) -> list[dict]:
        return sorted(list(self.active.values()),
                      key=lambda a: (SEVERITY_RANK[a["severity"]], a["last_seen"]), reverse=True)

    # ── evaluation ───────────────────────────────────────────

    def evaluate(self, campaigns: Optional[list[dict]] = None,
                 now: Optional[datetime] = None) -> list[dict]:
        """Run every periodic rule. Returns the alerts to announce."""
        now = now or datetime.now()
        candidates: list[dict] = []
        candidates += self._rule_high_score()
        candidates += self._rule_user_spray()
        candidates += self._rule_exploit_2xx()
        candidates += self._rule_burst(now)
        candidates += self._rule_country_surge(now)
        candidates += self._rule_campaign(campaigns or [])

        announce = []
        for cand in candidates:
            alert = self.raise_alert(cand, now)
            if alert:
                announce.append(alert)
        self.resolve_stale(now)
        return announce

    # ── rules ────────────────────────────────────────────────

    def _rule_high_score(self) -> list[dict]:
        out = []
        for ip in self.store.ips(900):
            p = self.analyzer.get_attacker_profile(ip)
            if p and p.threat_score >= settings.ALERT_SCORE_THRESHOLD:
                where = p.geo.country if p.geo else "unknown"
                out.append({
                    "rule": "high_score", "key": ip, "ip": ip, "severity": p.severity,
                    "title": f"Threat score {p.threat_score} — {ip}",
                    "detail": f"{p.attack_pattern.replace('_', ' ').lower()}, "
                              f"{p.auth_attempts or p.total_attempts} attempts, "
                              f"{p.unique_usernames} usernames, from {where}",
                    "mitre": p.mitre_ttps,
                })
        return out

    def _rule_user_spray(self) -> list[dict]:
        out = []
        for ip in self.store.ips(600):
            users = {e.username for e in self.store.events_for_ip(ip, 600)
                     if e.source == "ssh" and e.username != "(none)"}
            if len(users) >= settings.ALERT_SPRAY_USERS:
                out.append({
                    "rule": "user_spray", "key": ip, "ip": ip, "severity": "MEDIUM",
                    "title": f"{len(users)} accounts tried in 10 min — {ip}",
                    "detail": "sample: " + ", ".join(sorted(users)[:8]),
                    "mitre": ["T1110.003"],
                })
        return out

    def _rule_exploit_2xx(self) -> list[dict]:
        if not settings.ALERT_EXPLOIT_2XX:
            return []
        out = []
        for e in self.store._filter_by_window(300):
            if (e.source == "http" and e.meta.get("sig_kind") == "exploit"
                    and 200 <= e.http_status < 300):
                sig = e.meta.get("sig", "")
                out.append({
                    "rule": "exploit_2xx", "key": f"{sig}:{e.username}"[:120], "ip": e.ip,
                    "severity": "HIGH",
                    "title": f"Exploit path answered {e.http_status} — {sig or 'signature'}",
                    "detail": f"{e.meta.get('sig_name', '')} · {e.username} from {e.ip}. "
                              "Check it is not a catch-all page answering 200 to everything.",
                    "mitre": ["T1190"],
                })
        return out

    def _rule_burst(self, now: datetime) -> list[dict]:
        """Last 5 minutes against the previous 24 h of 5-minute blocks."""
        per_minute: dict[datetime, int] = defaultdict(int)
        for e in self.store._filter_by_window(86400):
            m = _minute(e.timestamp)
            if m:
                per_minute[m] += e.count
        if not per_minute:
            return []
        edge = now.replace(second=0, microsecond=0) - timedelta(minutes=BURST_WINDOW_MIN - 1)
        current = sum(n for m, n in per_minute.items() if m >= edge)
        if current < settings.ALERT_BURST_MIN:
            return []

        start = min(per_minute)
        blocks: dict[int, int] = defaultdict(int)
        for m, n in per_minute.items():
            if m < edge:
                blocks[int((edge - m).total_seconds() // (BURST_WINDOW_MIN * 60))] += n
        n_blocks = int((edge - start).total_seconds() // (BURST_WINDOW_MIN * 60))
        if n_blocks < 12:        # under an hour of history: no baseline yet
            return []
        history = [blocks.get(i, 0) for i in range(n_blocks)]
        mean = statistics.fmean(history)
        std = statistics.pstdev(history)
        if current <= mean + 3 * std:
            return []
        severe = current > mean + 6 * std
        return [{
            "rule": "burst", "key": "global", "severity": "HIGH" if severe else "MEDIUM",
            "title": f"Traffic burst: {current} events in {BURST_WINDOW_MIN} min",
            "detail": f"usual is {mean:.0f} ± {std:.0f} per {BURST_WINDOW_MIN} min "
                      f"({(current - mean) / std if std else 0:.1f}σ above)",
        }]

    def _rule_country_surge(self, now: datetime) -> list[dict]:
        """Distinct SSH addresses per country, this 10 minutes vs its usual."""
        span = SURGE_BUCKET_MIN * 60
        buckets: dict[str, dict[int, set]] = defaultdict(lambda: defaultdict(set))
        for e in self.store._filter_by_window(86400):
            if e.source != "ssh" or not e.geo or e.geo.country_code in ("", "XX"):
                continue
            m = _minute(e.timestamp)
            if m is None:
                continue
            age = int((now - m).total_seconds() // span)
            if age >= 0:
                buckets[e.geo.country_code][age].add(e.ip)

        # Addresses per slot over all countries: a surge must be about THIS
        # country. When everything grows at once (a global burst) every
        # country triples and none of them is the story — the burst rule is.
        now_total = sum(len(by_age.get(0, ())) for by_age in buckets.values())
        past_total = sum(len(ips) for by_age in buckets.values()
                         for age, ips in by_age.items() if age > 0)

        out = []
        for code, by_age in buckets.items():
            current = len(by_age.get(0, ()))
            if current < settings.ALERT_COUNTRY_IPS:
                continue
            previous = [len(ips) for age, ips in by_age.items() if age > 0]
            if len(previous) < 6:
                continue
            usual = statistics.median(previous)
            if current < 3 * usual:
                continue
            share_now = current / now_total
            share_usual = sum(previous) / past_total if past_total else 0.0
            if share_usual and share_now < SURGE_SHARE_LIFT * share_usual:
                continue
            out.append({
                "rule": "country_surge", "key": code, "severity": "MEDIUM",
                "title": f"{current} addresses from {code} in {SURGE_BUCKET_MIN} min",
                "detail": f"its usual is {usual:g} per {SURGE_BUCKET_MIN} min; "
                          f"{share_now:.0%} of all active addresses (usually {share_usual:.0%})",
            })
        return out

    def _rule_campaign(self, campaigns: list[dict]) -> list[dict]:
        out = []
        for c in campaigns:
            if c.get("level") not in ("MEDIUM", "HIGH") or not c.get("active"):
                continue
            if c["ips"] < settings.ALERT_CAMPAIGN_MIN_IPS:
                continue
            users = ", ".join(c["usernames"][:4])
            out.append({
                "rule": "campaign", "key": c["fingerprint"], "severity": c["severity"],
                "title": f"Campaign {c['fingerprint']} — {c['label']}, {c['ips']} addresses",
                "detail": f"confidence {c['confidence']}/100 · targets {users} · "
                          + "; ".join(c.get("evidence", [])[:2]),
                "mitre": ["T1110.003" if c.get("kind") == "distributed_spray" else "T1110"],
            })
        return out

    # ── event-driven rule ────────────────────────────────────

    def on_accepted_login(self, ip: str, username: str, method: str,
                          now: Optional[datetime] = None) -> Optional[dict]:
        """
        Called for every "Accepted ..." line. Alerts only when the same address
        had been failing logins: that is a brute force that worked. A clean
        login (the owner) is ignored and never stored anywhere.
        """
        failed = sum(e.attempts for e in self.store.events_for_ip(ip))
        if failed < settings.ALERT_LOGIN_MIN_FAILS:
            return None
        return self.raise_alert({
            "rule": "login_success", "key": ip, "ip": ip, "severity": "CRITICAL",
            "title": f"SSH login ACCEPTED after {failed} failed attempts — {ip}",
            # The account name stays out of the public record
            "detail": f"method: {method}. A brute-forcing address authenticated: "
                      "treat the account as compromised.",
            "private": f"account: {username}",
            "mitre": ["T1110", "T1078"],
        }, now)
