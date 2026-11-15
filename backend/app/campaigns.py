"""
Campaign detection with a confidence level.

Two addresses that try the same usernames in the same order share a wordlist.
That proves they run the same TOOL, not that one operator controls both: the
default list of a popular scanner is shared by thousands of unrelated bots.
Calling every shared prefix a "campaign" is the classic false positive.

So a group is only a candidate. Its confidence comes from independent signals,
each one measured against what the rest of the traffic looks like:

  specificity   how rare the wordlist prefix is. For each username: what share
                of the addresses OUTSIDE the group also try it? "root, admin"
                is tried by everyone (worth nothing); a prefix nobody else
                uses is strong evidence.
  timing        do the members show up together? Share of the group whose
                first contact falls inside its busiest hour. A botnet being
                pointed at the server arrives in a burst; a public wordlist
                trickles in over weeks.
  network       do the members share infrastructure? Share of the group that
                sits in a /24 with another member (a rented range), or one
                network owning almost all of it.

A group is reported as a coordinated campaign (HIGH) only when at least two
of those signals agree; one signal alone tops out at MEDIUM. Small groups are
damped: two addresses "arriving in the same hour" is weak evidence.

The second detector covers what the prefix cannot see: a distributed spray
where each address tries one or two users and never builds a prefix. There
the signal is many different addresses hitting the SAME username in the same
ten minutes, well above that username's own baseline.

Not used: the SSH client version. sshd does not log it at the default
LogLevel, so it would be a signal that is almost always missing.
"""
import hashlib
import math
import statistics
from collections import Counter
from datetime import datetime, timedelta
from typing import Optional

from .cache import TTLCache

# A username tried by this share of the other addresses is "everyone's"
COMMON_SHARE = 0.05
WEIGHTS = {"specificity": 45, "timing": 35, "network": 20}
SIGNAL_OK = 0.5            # a signal "agrees" from here
HIGH_AT, MEDIUM_AT = 65, 40
MAX_MEMBERS = 2000         # members inspected per group

# Distributed spray
BURST_BUCKET_MIN = 10
BURST_MIN_IPS = 5
BURST_OVER_BASELINE = 4.0
# ...and its share of all the addresses active in that slot must have grown
# this much. Without it a general traffic spike (every username gets more
# visitors at once) would be reported as one "spray" per username.
BURST_SHARE_LIFT = 3.0

LEVEL_LABEL = {
    "HIGH": "coordinated campaign",
    "MEDIUM": "probable campaign",
    "LOW": "shared tooling",
}

_cache = TTLCache(maxsize=8, ttl=60)


# ── signals (pure functions, unit-tested) ─────────────────────

def rarity(outside_users: int, outside_total: int) -> float:
    """1.0 = nobody else tries this username, 0.0 = COMMON_SHARE or more do."""
    if outside_total <= 0:
        return 0.5   # nothing to compare against: neutral, not evidence
    share = outside_users / outside_total
    return max(0.0, 1.0 - share / COMMON_SHARE)


def timing_signal(first_seen: list[str], window_minutes: int = 60) -> float:
    """Largest share of members whose first contact fits in one window."""
    times = sorted(_parse(t) for t in first_seen if t)
    times = [t for t in times if t is not None]
    if len(times) < 2:
        return 0.0
    span = timedelta(minutes=window_minutes)
    best, start = 1, 0
    for end in range(len(times)):
        while times[end] - times[start] > span:
            start += 1
        best = max(best, end - start + 1)
    return best / len(times)


def network_signal(masked: list[str], orgs: list[str]) -> float:
    """Members sharing a /24 with another member, or one network owning the group."""
    n = len(masked)
    if n < 2:
        return 0.0
    per_net = Counter(masked)
    shared = sum(c for c in per_net.values() if c >= 2) / n
    top_org = Counter(o for o in orgs if o).most_common(1)
    org_share = top_org[0][1] / n if top_org else 0.0
    # One provider owning the group is weaker evidence than a shared /24:
    # a handful of clouds host most of the internet's bots
    return max(shared, 0.6 * org_share if org_share >= 0.8 and n >= 3 else 0.0)


def size_damping(n: int) -> float:
    """0.67 for a pair, 1.0 from eight members on."""
    return 0.5 + 0.5 * min(1.0, math.log2(max(n, 2)) / 3)


def confidence(signals: dict[str, float], members: int) -> tuple[int, str]:
    raw = sum(WEIGHTS[k] * signals.get(k, 0.0) for k in WEIGHTS)
    score = round(raw * size_damping(members))
    agreeing = sum(1 for k in WEIGHTS if signals.get(k, 0.0) >= SIGNAL_OK)
    if score >= HIGH_AT and agreeing >= 2:
        return score, "HIGH"
    if score >= MEDIUM_AT:
        # One strong signal alone is never a "coordinated campaign"
        return min(score, HIGH_AT - 1) if agreeing < 2 else score, "MEDIUM"
    return score, "LOW"


def _parse(ts: str) -> Optional[datetime]:
    try:
        return datetime.fromisoformat(ts)
    except (ValueError, TypeError):
        return None


def _severity(level: str, ips: int) -> str:
    if level == "HIGH":
        return "CRITICAL" if ips >= 20 else "HIGH"
    return level


# ── wordlist groups ───────────────────────────────────────────

def wordlist_campaigns(db, limit: int = 20, min_ips: int = 2) -> list[dict]:
    groups = db._q(
        "SELECT fingerprint, fp_users, count(*) AS ips, sum(attempts) AS attempts, "
        "min(first_seen) AS first_seen, max(last_seen) AS last_seen, "
        "count(DISTINCT country_code) AS countries, count(DISTINCT org) AS networks "
        "FROM ips WHERE fingerprint IS NOT NULL AND fingerprint != '' "
        "GROUP BY fingerprint HAVING ips >= ? ORDER BY ips DESC, attempts DESC LIMIT ?",
        (min_ips, max(limit * 3, 60)),
    )
    if not groups:
        return []

    total_ips = db._q("SELECT count(*) AS n FROM ips WHERE source = 'ssh' AND user_count > 0")[0]["n"]
    usernames = {u for g in groups for u in (g["fp_users"] or "").split(", ") if u}
    marks = ",".join("?" * len(usernames))
    usage = {
        r["username"]: r["n"]
        for r in db._q(
            f"SELECT username, count(*) AS n FROM ip_users WHERE username IN ({marks}) "
            "GROUP BY username", tuple(usernames),
        )
    } if usernames else {}
    hour_ago = (datetime.now() - timedelta(hours=1)).isoformat()

    out = []
    for g in groups:
        c = dict(g)
        fp = c["fingerprint"]
        prefix = [u for u in (c.pop("fp_users") or "").split(", ") if u]
        members = db._q(
            "SELECT ip, ip_masked, org, country_code, first_seen, attempts FROM ips "
            "WHERE fingerprint = ? ORDER BY attempts DESC LIMIT ?", (fp, MAX_MEMBERS),
        )
        n = c["ips"]
        outside_total = total_ips - n
        per_user = [
            {"username": u,
             "outside_share": round(max(0, usage.get(u, 0) - n) / outside_total, 4)
             if outside_total > 0 else None,
             "rarity": round(rarity(max(0, usage.get(u, 0) - n), outside_total), 2)}
            for u in prefix
        ]
        signals = {
            "specificity": round(statistics.fmean(p["rarity"] for p in per_user), 2) if per_user else 0.0,
            "timing": round(timing_signal([m["first_seen"] for m in members]), 2),
            "network": round(network_signal([m["ip_masked"] for m in members],
                                            [m["org"] for m in members]), 2),
        }
        score, level = confidence(signals, n)

        rare = sum(1 for p in per_user if p["rarity"] >= SIGNAL_OK)
        evidence = [
            f"{rare} of {len(per_user)} usernames in the prefix are rare "
            f"(tried by under {COMMON_SHARE:.0%} of the other addresses)",
            f"{round(signals['timing'] * len(members))} of {len(members)} addresses "
            "first appeared within the same hour",
            f"{round(signals['network'] * 100)}% of the group shares a /24 or a single network",
        ]
        countries = Counter(m["country_code"] for m in members if m["country_code"])
        c.update({
            "kind": "wordlist",
            "usernames": prefix,
            "username_rarity": per_user,
            "signals": signals,
            "confidence": score,
            "level": level,
            "label": LEVEL_LABEL[level],
            "severity": _severity(level, n),
            "evidence": evidence,
            "active": bool(c["last_seen"] and c["last_seen"] >= hour_ago),
            "top_countries": [{"country_code": k, "ips": v} for k, v in countries.most_common(5)],
            "sample_ips": [m["ip"] for m in members[:5]],
        })
        out.append(c)

    out.sort(key=lambda c: (c["confidence"], c["ips"]), reverse=True)
    return out[:limit]


# ── distributed spray ─────────────────────────────────────────

def _bucket_time(bucket: str) -> Optional[datetime]:
    # bucket = first 15 chars of an ISO timestamp: "2026-11-15T10:3"
    return _parse(bucket + "0:00")


def distributed_bursts(db, hours: int = 24, limit: int = 20) -> list[dict]:
    """
    Many addresses hitting the same username inside ten minutes, far above
    what that username normally gets. Catches the botnet that gives each
    machine one or two tries (no wordlist prefix to fingerprint).
    """
    since = (datetime.now() - timedelta(hours=hours)).isoformat()
    candidates = db._q(
        "SELECT username, substr(ts, 1, 15) AS bucket, count(DISTINCT ip) AS ips, "
        "sum(attempts) AS attempts, min(ts) AS first_seen, max(ts) AS last_seen "
        "FROM events WHERE source = 'ssh' AND username != '(none)' AND ts >= ? "
        "GROUP BY username, bucket HAVING ips >= ?",
        (since, BURST_MIN_IPS),
    )
    if not candidates:
        return []

    names = sorted({r["username"] for r in candidates})
    marks = ",".join("?" * len(names))
    history: dict[str, dict[str, int]] = {}
    for r in db._q(
        "SELECT username, substr(ts, 1, 15) AS bucket, count(DISTINCT ip) AS ips "
        f"FROM events WHERE source = 'ssh' AND username IN ({marks}) GROUP BY username, bucket",
        tuple(names),
    ):
        history.setdefault(r["username"], {})[r["bucket"]] = r["ips"]
    # Every address active in each slot, whatever it tried
    totals = {
        r["bucket"]: r["ips"] for r in db._q(
            "SELECT substr(ts, 1, 15) AS bucket, count(DISTINCT ip) AS ips "
            "FROM events WHERE source = 'ssh' GROUP BY bucket")
    }

    hits = []
    for r in candidates:
        own = history.get(r["username"], {})
        baseline = statistics.median(own.values()) if own else 1
        threshold = max(BURST_MIN_IPS, BURST_OVER_BASELINE * baseline)
        # The burst itself is in the history: with too little of it the
        # median IS the burst and nothing can stand out — that is intended
        if r["ips"] < threshold:
            continue
        # Share of the slot's addresses that went for this username, against
        # its usual share in every other slot
        share_now = r["ips"] / max(1, totals.get(r["bucket"], r["ips"]))
        other = [b for b in totals if b != r["bucket"]]
        usual_total = sum(totals[b] for b in other)
        usual_share = sum(own.get(b, 0) for b in other) / usual_total if usual_total else 0.0
        lift = share_now / usual_share if usual_share else float("inf")
        if lift < BURST_SHARE_LIFT:
            continue
        hits.append((dict(r, lift=lift), baseline, threshold))

    # Consecutive buckets of the same username are one burst
    hits.sort(key=lambda h: (h[0]["username"], h[0]["bucket"]))
    merged: list[tuple[dict, float, float, list[str]]] = []
    for row, baseline, threshold in hits:
        last = merged[-1] if merged else None
        if last and last[0]["username"] == row["username"]:
            a, b = _bucket_time(last[3][-1]), _bucket_time(row["bucket"])
            if a and b and b - a <= timedelta(minutes=BURST_BUCKET_MIN):
                last[0]["ips"] = max(last[0]["ips"], row["ips"])
                last[0]["lift"] = max(last[0]["lift"], row["lift"])
                last[0]["attempts"] += row["attempts"] or 0
                last[0]["last_seen"] = row["last_seen"]
                last[3].append(row["bucket"])
                continue
        merged.append((row, baseline, threshold, [row["bucket"]]))

    hour_ago = (datetime.now() - timedelta(hours=1)).isoformat()
    out = []
    for row, baseline, threshold, _ in merged:
        members = db._q(
            "SELECT e.ip AS ip, i.country_code AS country_code, i.ip_masked AS ip_masked, "
            "i.org AS org FROM events e LEFT JOIN ips i ON i.ip = e.ip "
            "WHERE e.source = 'ssh' AND e.username = ? AND e.ts >= ? AND e.ts <= ? "
            "GROUP BY e.ip ORDER BY sum(e.attempts) DESC LIMIT ?",
            (row["username"], row["first_seen"], row["last_seen"], MAX_MEMBERS),
        )
        n = len(members) or row["ips"]
        over = min(1.0, (row["ips"] / threshold - 1) / 2)       # 3x the threshold = full
        focus = min(1.0, (row["lift"] - BURST_SHARE_LIFT) / (3 * BURST_SHARE_LIFT))
        signals = {
            # How far above its own baseline this username went, and how much
            # of the slot's traffic concentrated on it
            "specificity": round(0.4 + 0.3 * over + 0.3 * focus, 2),
            "timing": 1.0,   # by construction: inside ten-minute buckets
            "network": round(network_signal([m["ip_masked"] or "" for m in members],
                                            [m["org"] or "" for m in members]), 2),
        }
        score, level = confidence(signals, n)
        countries = Counter(m["country_code"] for m in members if m["country_code"])
        out.append({
            "kind": "distributed_spray",
            "fingerprint": hashlib.sha1(
                f"{row['username']}\x1f{row['first_seen'][:13]}".encode()).hexdigest()[:10],
            "usernames": [row["username"]],
            "ips": n,
            "attempts": row["attempts"] or 0,
            "first_seen": row["first_seen"],
            "last_seen": row["last_seen"],
            "countries": len(countries),
            "networks": len({m["org"] for m in members if m["org"]}),
            "baseline_ips": baseline,
            "signals": signals,
            "confidence": score,
            "level": level,
            "label": "distributed spray" if level != "LOW" else "username spike",
            "severity": _severity(level, n),
            "evidence": [
                f"{row['ips']} addresses tried '{row['username']}' within {BURST_BUCKET_MIN} minutes; "
                f"its usual is {baseline:g}",
                "its share of the active addresses grew "
                + (f"{row['lift']:.1f}x" if row["lift"] != float("inf") else "from nothing"),
                f"{round(signals['network'] * 100)}% of them share a /24 or a single network",
            ],
            "active": row["last_seen"] >= hour_ago,
            "top_countries": [{"country_code": k, "ips": v} for k, v in countries.most_common(5)],
            "sample_ips": [m["ip"] for m in members[:5]],
        })
    out.sort(key=lambda c: (c["confidence"], c["ips"]), reverse=True)
    return out[:limit]


# ── public ────────────────────────────────────────────────────

def detect(db, limit: int = 20, min_ips: int = 2, use_cache: bool = True) -> list[dict]:
    """Both detectors, best evidence first. Cached for a minute."""
    key = (limit, min_ips)
    if use_cache:
        cached = _cache.get(key)
        if cached is not None:
            return cached
    found = wordlist_campaigns(db, limit, min_ips) + distributed_bursts(db, limit=limit)
    found.sort(key=lambda c: (c["confidence"], c["ips"]), reverse=True)
    found = found[:limit]
    _cache.set(key, found)
    return found
