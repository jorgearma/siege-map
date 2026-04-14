"""STIX 2.1 bundle export — built manually, no stix2 dependency required."""

import uuid
from datetime import datetime, timezone
from typing import Optional

from .config import settings
from .models import MITRE_TTPS

_SENSOR_UUID = f"identity--{uuid.uuid5(uuid.NAMESPACE_DNS, f'ssh-honeypot-{settings.VPS_LABEL}')}"

_MITRE_URLS: dict[str, str] = {
    "T1110.001": "https://attack.mitre.org/techniques/T1110/001/",
    "T1110.003": "https://attack.mitre.org/techniques/T1110/003/",
    "T1110.004": "https://attack.mitre.org/techniques/T1110/004/",
    "T1078":     "https://attack.mitre.org/techniques/T1078/",
    "T1021.004": "https://attack.mitre.org/techniques/T1021/004/",
}


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _uid(type_name: str, seed: Optional[str] = None) -> str:
    uid = str(uuid.uuid5(uuid.NAMESPACE_DNS, seed)) if seed else str(uuid.uuid4())
    return f"{type_name}--{uid}"


def _ts(raw: str) -> str:
    """Normalise ISO timestamp to STIX 2.1 format (ends in Z)."""
    if not raw:
        return _now()
    raw = raw.rstrip("Z")
    if "." not in raw:
        raw += ".000"
    return raw + "Z"


def build_bundle(window: Optional[int] = None, attacker_limit: int = 200) -> dict:
    # Import here to avoid circular imports at module load time
    from .analyzer import analyzer

    now = _now()
    objects: list[dict] = []

    # ── Identity (sensor) ──────────────────────────────────────
    objects.append({
        "type": "identity",
        "spec_version": "2.1",
        "id": _SENSOR_UUID,
        "created": now,
        "modified": now,
        "name": f"SSH Honeypot — {settings.VPS_LABEL}",
        "description": (
            "Low-interaction SSH honeypot sensor collecting authentication "
            "attempt telemetry and classifying attacker behaviour."
        ),
        "identity_class": "system",
        "roles": ["sensor"],
    })

    # ── Attack-pattern objects (MITRE TTPs) ───────────────────
    profiles = analyzer.get_all_profiles(window=window, limit=attacker_limit)

    used_ttps: set[str] = set()
    for p in profiles:
        used_ttps.update(p.mitre_ttps)

    ttp_stix_ids: dict[str, str] = {}
    for ttp in used_ttps:
        info = MITRE_TTPS.get(ttp, {"name": ttp, "tactic": "Unknown"})
        stix_id = _uid("attack-pattern", ttp)
        ttp_stix_ids[ttp] = stix_id
        objects.append({
            "type": "attack-pattern",
            "spec_version": "2.1",
            "id": stix_id,
            "created": now,
            "modified": now,
            "name": info["name"],
            "created_by_ref": _SENSOR_UUID,
            "external_references": [{
                "source_name": "mitre-attack",
                "external_id": ttp,
                "url": _MITRE_URLS.get(ttp, "https://attack.mitre.org/"),
            }],
        })

    # ── Indicators + relationships ────────────────────────────
    for p in profiles:
        ind_id = _uid("indicator", p.ip)
        objects.append({
            "type": "indicator",
            "spec_version": "2.1",
            "id": ind_id,
            "created": _ts(p.first_seen),
            "modified": _ts(p.last_seen),
            "name": f"SSH attacker: {p.ip}",
            "description": (
                f"Pattern: {p.attack_pattern} | Speed: {p.attack_speed} | "
                f"Attempts: {p.total_attempts} | Threat score: {p.threat_score}/100"
            ),
            "pattern": f"[ipv4-addr:value = '{p.ip}']",
            "pattern_type": "stix",
            "valid_from": _ts(p.first_seen),
            "indicator_types": ["malicious-activity"],
            "created_by_ref": _SENSOR_UUID,
            "labels": [p.attack_pattern.lower().replace("_", "-")],
            "extensions": {
                "x-ssh-honeypot": {
                    "extension_type": "property-extension",
                    "attack_pattern": p.attack_pattern,
                    "attack_speed": p.attack_speed,
                    "threat_score": p.threat_score,
                    "requests_per_minute": p.requests_per_minute,
                    "unique_usernames": p.unique_usernames,
                    "country": p.geo.country if p.geo else "Unknown",
                    "country_code": p.geo.country_code if p.geo else "XX",
                    "asn": p.geo.org if p.geo else "",
                },
            },
        })

        for ttp in p.mitre_ttps:
            if ttp in ttp_stix_ids:
                objects.append({
                    "type": "relationship",
                    "spec_version": "2.1",
                    "id": _uid("relationship"),
                    "created": now,
                    "modified": now,
                    "relationship_type": "uses",
                    "source_ref": ind_id,
                    "target_ref": ttp_stix_ids[ttp],
                    "created_by_ref": _SENSOR_UUID,
                })

    return {
        "type": "bundle",
        "id": _uid("bundle"),
        "spec_version": "2.1",
        "objects": objects,
    }


def build_csv(window: Optional[int] = None) -> str:
    from .store import store
    events = store._filter_by_window(window)
    lines = ["timestamp,ip,username,event_type,country,country_code,city,asn"]
    for e in events:
        country = e.geo.country if e.geo else "Unknown"
        country_code = e.geo.country_code if e.geo else "XX"
        city = e.geo.city if e.geo else "Unknown"
        asn = (e.geo.org or "").replace(",", ";") if e.geo else ""
        username = (e.username or "").replace(",", ";")
        lines.append(
            f"{e.timestamp},{e.ip},{username},{e.event_type},"
            f"{country},{country_code},{city},{asn}"
        )
    return "\n".join(lines)


def build_report(window: Optional[int] = None) -> dict:
    from .store import store
    from .analyzer import analyzer
    import uuid as _uuid

    events = store._filter_by_window(window)
    profiles = analyzer.get_all_profiles(window=window, limit=500)
    patterns = analyzer.get_attack_pattern_summary(window=window)
    asns = analyzer.get_asn_summary(window=window, limit=5)

    high_threat = [p for p in profiles if p.threat_score >= 70]

    return {
        "report_id": str(_uuid.uuid4()),
        "generated_at": _now(),
        "sensor": settings.VPS_LABEL,
        "window_seconds": window,
        "summary": {
            "total_events": len(events),
            "unique_ips": len({e.ip for e in events}),
            "unique_usernames": len({e.username for e in events}),
            "high_threat_ips": len(high_threat),
        },
        "attack_patterns": patterns,
        "top_asns": asns,
        "top_attackers": [
            {
                "ip": p.ip,
                "threat_score": p.threat_score,
                "attack_pattern": p.attack_pattern,
                "attack_speed": p.attack_speed,
                "attempts": p.total_attempts,
                "country": p.geo.country if p.geo else "Unknown",
            }
            for p in profiles[:10]
        ],
    }
