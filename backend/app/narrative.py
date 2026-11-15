"""
The story of one address, in order: what it did, what we know about it and
what the sensor concluded. Built from facts already computed elsewhere — this
module only puts them in a readable sequence.
"""
from typing import Optional

_PATTERN_TEXT = {
    "PASSWORD_GUESSING": "password guessing against a few accounts",
    "PASSWORD_SPRAYING": "password spraying across many accounts",
    "DICTIONARY_ATTACK": "a dictionary attack (many accounts, many tries each)",
    "SSH_SCANNING": "SSH scanning without trying any account",
    "WEB_SCANNING": "web scanning",
    "SINGLE_PROBE": "a single probe",
}


def _step(ts: str, kind: str, text: str) -> dict:
    return {"ts": ts or "", "kind": kind, "text": text}


def build(profile: dict, info: Optional[dict] = None, campaign: Optional[dict] = None,
          alerts: Optional[list[dict]] = None, dual_hits: int = 0) -> list[dict]:
    info = info or {}
    geo = profile.get("geo") or {}
    steps: list[dict] = []

    first = info.get("first_seen") or profile.get("first_seen", "")
    origin = ", ".join(x for x in (geo.get("country"), geo.get("org")) if x and x != "Unknown")
    net = profile.get("cloud") or profile.get("net_type") or ""
    steps.append(_step(first, "contact",
                       f"First contact from {origin or 'an unknown origin'}"
                       + (f" ({net})" if net and net != "unknown" else "")))

    users = profile.get("unique_usernames", 0)
    attempts = profile.get("auth_attempts") or profile.get("total_attempts", 0)
    pattern = _PATTERN_TEXT.get(profile.get("attack_pattern", ""), "activity")
    if users:
        sample = ", ".join(profile.get("usernames_attempted", [])[:5])
        steps.append(_step(profile.get("first_seen", ""), "ssh",
                           f"Tried {users} account(s) in {attempts} attempt(s): {pattern}"
                           + (f" — {sample}" + ("…" if users > 5 else "") if sample else "")))
    elif not profile.get("http_routes"):
        steps.append(_step(profile.get("first_seen", ""), "ssh", f"Activity: {pattern}"))

    rpm = profile.get("requests_per_minute", 0)
    if rpm >= 2:
        steps.append(_step(profile.get("last_seen", ""), "rate",
                           f"Peak rate {rpm:g} lines/min ({profile.get('attack_speed', '').replace('_', ' ').lower()})"))

    routes = profile.get("http_routes") or []
    if routes:
        exploit = "T1190" in (profile.get("mitre_ttps") or [])
        steps.append(_step(profile.get("first_seen", ""), "http",
                           f"Probed {len(routes)} web path(s), e.g. {routes[0]['path']}"
                           + (" — includes a known exploit signature" if exploit else "")))
    if dual_hits:
        steps.append(_step("", "multi",
                           f"Its /24 network also sent {dual_hits} HTTP request(s): "
                           "the same infrastructure works SSH and web"))

    if campaign:
        steps.append(_step(campaign.get("first_seen", ""), "campaign",
                           f"Member of campaign {campaign['fingerprint']} "
                           f"({campaign['label']}, confidence {campaign['confidence']}/100) "
                           f"with {campaign['ips']} addresses"))
    elif info.get("campaign_size", 0) > 1:
        steps.append(_step("", "campaign",
                           f"Shares its wordlist with {info['campaign_size'] - 1} other address(es)"))

    days = info.get("days_active", 0)
    if days > 1:
        steps.append(_step(info.get("last_seen", ""), "persistence",
                           f"Came back on {days} different days"))

    if profile.get("abuse_total_reports"):
        steps.append(_step("", "reputation",
                           f"AbuseIPDB: {profile['abuse_confidence']}% confidence, "
                           f"{profile['abuse_total_reports']} report(s)"))
    if "tor-exit" in (info.get("tags") or []):
        steps.append(_step("", "reputation", "Tor exit node"))

    for a in reversed(alerts or []):
        steps.append(_step(a["ts"], "alert", f"Alert [{a['severity']}] {a['title']}"))

    steps.append(_step(profile.get("last_seen", ""), "verdict",
                       f"Threat score {profile.get('threat_score', 0)}/100 "
                       f"({profile.get('severity', 'LOW')})"))
    return steps
