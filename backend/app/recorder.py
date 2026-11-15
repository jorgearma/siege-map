"""
Decides what each event adds to the long-term counters (db.daily).

Kept apart from the store so the rule "count everything, show a sample"
lives in one place: the store deduplicates what the live feed shows, this
module counts every line and every real authentication attempt.
"""
from datetime import datetime
from typing import Optional

from .attempts import attempt_counter
from .db import Database
from .intel import tags_for
from .models import SSHEvent
from .usernames import categorize
from .visitors import visitor_tracker


def _epoch(ts: str) -> float:
    try:
        return datetime.fromisoformat(ts).timestamp()
    except ValueError:
        return datetime.now().timestamp()


def _hour_key(ts: str) -> str:
    try:
        dt = datetime.fromisoformat(ts)
        return f"{dt.weekday()}:{dt.hour}"
    except ValueError:
        return ""


def mark_attempt(event: SSHEvent) -> None:
    """Set event.attempts (0 or 1) for an SSH line. Call once per line."""
    if event.source != "ssh":
        return
    if attempt_counter.is_attempt(event.ip, event.username, event.event_type,
                                  _epoch(event.timestamp)):
        event.attempts = 1


def record(database: Database, event: SSHEvent, full_ip: Optional[str] = None) -> None:
    """
    Count one log line. `event.attempts` must already be set for this line
    (mark_attempt); `full_ip` is the unmasked address of an HTTP visitor,
    used only in memory to tell unique visitors apart.
    """
    day = event.timestamp[:10]
    geo = event.geo
    deltas: list[tuple[str, str, int]] = [
        ("event_type", event.event_type, 1),
        ("hour", _hour_key(event.timestamp), 1),
    ]
    if geo:
        deltas.append(("country", geo.country, 1))

    if event.source == "ssh":
        deltas.append(("source", "ssh", 1))
        if geo:
            deltas += [
                ("ssh_country", geo.country, 1),
                ("ssh_org", geo.org or geo.asn, 1),
                ("ssh_net", geo.net_type, 1),
                ("ssh_cloud", geo.cloud, 1),
            ]
        if event.attempts:
            deltas += [
                ("ssh_attempts", "total", event.attempts),
                ("ssh_user", event.username, event.attempts),
                ("ssh_cat", categorize(event.username), event.attempts),
            ]
        if event.meta.get("banner"):
            deltas.append(("ssh_banner", event.meta["banner"], 1))
        if event.meta.get("kex"):
            deltas.append(("ssh_kex", event.meta["kex"], 1))
        database.touch_ip(event, lines=1, attempts=event.attempts,
                          tags=tags_for(event.ip, geo))
    else:
        is_visit = event.event_type.startswith("visit_")
        deltas.append(("source", "visit" if is_visit else "http", 1))
        if is_visit:
            deltas.append(("page", event.username, 1))
        else:
            deltas.append(("http_probe", event.username, 1))
            if geo:
                deltas += [("http_country", geo.country, 1), ("http_net", geo.net_type, 1)]
        if event.meta.get("sig"):
            m = event.meta
            deltas.append((
                "http_sig",
                f"{m['sig']}|{m.get('sig_name', '')}|{m.get('sig_product', '')}|{m.get('sig_kind', '')}",
                1,
            ))
        deltas += visitor_tracker.on_event(event, full_ip or event.ip)
        database.touch_ip(event, lines=1)

    database.bump_many(day, deltas)
