import asyncio
import io
import ipaddress
import json
import logging
import math
import re
import time
import uuid
from collections import Counter
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Optional

from fastapi import FastAPI, HTTPException, Query, WebSocket, WebSocketDisconnect
from fastapi.responses import PlainTextResponse, StreamingResponse

from . import campaigns
from . import narrative
from . import notify
from . import report
from .alerts import AlertEngine
from .analyzer import analyzer, classify, score_ip
from .anonymize import mask_ip
from .config import settings
from .db import db
from .geo import close_client, enrich_ip
from .models import AttackerProfile, GeoInfo
from .parser import parse_accepted_login, parse_line
from . import intel
from . import nginx_parser
from . import stix_export
from . import threat_intel
from .recorder import mark_attempt, record
from .store import store
from .tail import tail_log
from .usernames import categorize
from .visitors import visitor_tracker

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)
# httpx logs every request URL at INFO — and the geo lookup URL contains the
# visitor's full IP. Keep those addresses out of `docker logs`.
logging.getLogger("httpx").setLevel(logging.WARNING)

# Per-client message queues
ws_queues: dict[WebSocket, asyncio.Queue] = {}

# Shared event buffer
_event_buffer: list[dict] = []
_buffer_lock = asyncio.Lock()

# Keep strong references to background tasks
_background_tasks: set[asyncio.Task] = set()

alert_engine = AlertEngine(store, analyzer, persist=db.save_alert)


def _spawn(coro) -> None:
    task = asyncio.create_task(coro)
    _background_tasks.add(task)
    task.add_done_callback(_background_tasks.discard)


def _broadcast(message: dict) -> None:
    """Queue one WebSocket message for every connected client."""
    for q in list(ws_queues.values()):
        try:
            q.put_nowait(message)
        except asyncio.QueueFull:
            pass


def announce(alert: dict) -> None:
    """Show a new alert on every dashboard and send it to the operator."""
    public = {k: v for k, v in alert.items() if k != "private"}
    logger.warning(f"ALERT [{public['severity']}] {public['rule']}: {public['title']}")
    _broadcast({"type": "alert", "data": public})
    if notify.enabled():
        _spawn(notify.send(alert))


async def process_log_lines():
    """Main pipeline: tail → parse → enrich → store → buffer → broadcast."""
    logger.info(f"Starting log ingestion from {settings.SSH_LOG_PATH}")
    lines_seen = 0
    events_parsed = 0

    async for line in tail_log(settings.SSH_LOG_PATH):
        lines_seen += 1
        if lines_seen % 50 == 0:
            logger.info(
                f"Pipeline heartbeat: {lines_seen} lines seen, "
                f"{events_parsed} parsed, {store._total_count} stored"
            )

        event = parse_line(line)
        if event is None:
            # A login that worked is never an event (it may be the owner);
            # it only matters when that address had been failing before
            accepted = parse_accepted_login(line) if settings.ALERTS_ENABLED else None
            if accepted and accepted[0] not in settings.ignore_ips:
                alert = alert_engine.on_accepted_login(*accepted)
                if alert:
                    announce(alert)
            continue

        if event.ip in settings.ignore_ips:
            continue

        events_parsed += 1
        logger.debug(f"Parsed event: {event.event_type} from {event.ip} user={event.username}")

        try:
            event.id = str(uuid.uuid4())[:8]
            event.geo = await enrich_ip(event.ip)

            # Count EVERY line (and every real attempt) in the long-term
            # counters; the store then merges repeats so the feed stays readable.
            mark_attempt(event)
            record(db, event)
            stored, is_new = store.add(event)
            db.save_event(stored)

            if is_new:
                # Fire-and-forget threat intel enrichment
                if threat_intel.should_check_ip(event.ip):
                    _spawn(threat_intel.check_abuseipdb(event.ip))

                # Inline attack classification (uses warm cache only — O(1))
                event_dict = event.to_dict()
                pattern, ttps = analyzer.quick_classify(event.ip)
                if pattern:
                    event_dict["attack_pattern"] = pattern
                    event_dict["mitre_ttps"] = ttps

                async with _buffer_lock:
                    _event_buffer.append(event_dict)

        except Exception as e:
            logger.error(
                f"Error processing event from {event.ip}: {e}", exc_info=True
            )


async def process_nginx_lines(nginx_path: str):
    """Pipeline for nginx access log: tail → parse → enrich → anonymize → store → buffer."""
    logger.info(f"Starting nginx ingestion from {nginx_path}")
    lines_seen = 0
    events_parsed = 0

    async for line in tail_log(nginx_path):
        lines_seen += 1
        if lines_seen % 100 == 0:
            logger.info(
                f"Nginx pipeline: {lines_seen} lines seen, {events_parsed} parsed"
            )

        fields = nginx_parser.parse_nginx_fields(line)
        if fields is None:
            continue
        if fields["ip"] in settings.ignore_ips:
            continue

        event = nginx_parser.classify_request(fields, line.strip())
        if event is None:
            # Not an event, but a successful static file tells us the client
            # behaves like a real browser (see visitors.py)
            if fields["status"] < 400 and nginx_parser.is_static_asset(fields["path"]):
                day = nginx_parser._parse_ts(fields["timestamp"])[:10]
                db.bump_many(day, visitor_tracker.on_asset(fields["ip"], day))
            continue

        events_parsed += 1
        try:
            event.id = str(uuid.uuid4())[:8]
            # Geolocalizar con la IP completa (país/ciudad correctos)...
            event.geo = await enrich_ip(event.ip)
            # ...y anonimizar ANTES de guardar: la IP completa nunca llega
            # al store, la base de datos, la API, el WebSocket ni los exports.
            full_ip = event.ip
            if settings.MASK_HTTP_IPS:
                event.ip = mask_ip(event.ip)
                event.raw_line = ""  # lleva IP, user-agent y referer completos

            # full_ip solo se usa en memoria para contar visitantes únicos
            record(db, event, full_ip=full_ip)
            stored, is_new = store.add(event)
            db.save_event(stored)

            if is_new:
                event_dict = event.to_dict()
                async with _buffer_lock:
                    _event_buffer.append(event_dict)

        except Exception as e:
            logger.error(
                f"Error processing nginx event from {event.ip}: {e}", exc_info=True
            )


async def flush_loop():
    """Periodically flush buffered events to all client queues."""
    while True:
        await asyncio.sleep(settings.WS_BROADCAST_INTERVAL)
        try:
            async with _buffer_lock:
                if not _event_buffer:
                    continue
                events = _event_buffer.copy()
                _event_buffer.clear()

            _broadcast({"type": "events", "data": events})
        except asyncio.CancelledError:
            raise
        except Exception as e:
            logger.error(f"Flush loop error: {e}", exc_info=True)


async def db_flush_loop():
    """Write buffered counters/events to SQLite off the event loop."""
    while True:
        await asyncio.sleep(settings.DB_FLUSH_INTERVAL)
        try:
            await asyncio.to_thread(db.flush)
        except asyncio.CancelledError:
            raise
        except Exception as e:
            logger.error(f"DB flush loop error: {e}", exc_info=True)


async def alert_loop():
    """Evaluate the alert rules every ALERT_INTERVAL seconds."""
    while True:
        await asyncio.sleep(settings.ALERT_INTERVAL)
        try:
            found = await asyncio.to_thread(campaigns.detect, db, 50)
            for alert in alert_engine.evaluate(found):
                announce(alert)
        except asyncio.CancelledError:
            raise
        except Exception as e:
            logger.error(f"Alert loop error: {e}", exc_info=True)


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("SSH Bot Rain Map starting up")
    logger.info(f"VPS location: {settings.VPS_LAT}, {settings.VPS_LON}")
    logger.info(f"Geo provider: {settings.GEO_PROVIDER}")
    logger.info(f"Threat intel enabled: {settings.THREAT_INTEL_ENABLED}")

    logger.info(f"Nginx logs: {settings.nginx_paths or 'none'} (mask HTTP IPs: {settings.MASK_HTTP_IPS})")

    # Refill the live store from disk so a restart does not empty the map
    restored = db.load_recent_events(settings.MAX_EVENTS)
    store.restore(restored, total=db.total("source"))
    logger.info(
        f"Database: {db.stats()} — restored {len(restored)} events, "
        f"{store._total_count} total since {db.first_day() or 'now'}"
    )

    tasks = [
        asyncio.create_task(process_log_lines()),
        asyncio.create_task(flush_loop()),
        asyncio.create_task(db_flush_loop()),
    ]
    if settings.TOR_EXIT_LIST:
        tasks.append(asyncio.create_task(intel.tor_refresh_loop()))
    if settings.ALERTS_ENABLED:
        alert_engine.restore(db.alerts(limit=200, status="active"))
        tasks.append(asyncio.create_task(alert_loop()))
        logger.info(f"Alerting on (notifications: {'on' if notify.enabled() else 'dashboard only'})")
    tasks += [asyncio.create_task(process_nginx_lines(p)) for p in settings.nginx_paths]
    for t in tasks:
        _background_tasks.add(t)
        t.add_done_callback(_background_tasks.discard)

    yield

    for t in tasks:
        t.cancel()
    db.flush()
    await close_client()
    logger.info("Shut down complete")


app = FastAPI(
    title="Passive SSH Honeypot — Threat Intelligence Dashboard",
    description="Real-time SSH bot attack visualization with MITRE ATT&CK classification",
    version="2.0.0",
    lifespan=lifespan,
)

# Sin CORS: el frontend llega a /api y /ws por el mismo origen (nginx en
# producción, proxy de Vite en desarrollo). allow_origins=["*"] permitía a
# cualquier web leer la API desde el navegador de quien la visite.


# ── WebSocket ──────────────────────────────────────────────────

@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    await ws.accept()
    queue: asyncio.Queue = asyncio.Queue(maxsize=50)
    ws_queues[ws] = queue
    logger.info(f"WebSocket client connected ({len(ws_queues)} total)")

    await ws.send_text(json.dumps({
        "type": "config",
        "data": {
            "vps_lat": settings.VPS_LAT,
            "vps_lon": settings.VPS_LON,
            "vps_label": settings.VPS_LABEL,
        },
    }))

    recent = store.recent(limit=100)
    if recent:
        await ws.send_text(json.dumps({"type": "initial", "data": recent}))

    try:
        while True:
            try:
                message = await asyncio.wait_for(queue.get(), timeout=30)
                await ws.send_text(json.dumps(message))
            except asyncio.TimeoutError:
                try:
                    await ws.send_text(json.dumps({"type": "ping"}))
                except Exception:
                    break
    except (WebSocketDisconnect, Exception):
        pass
    finally:
        ws_queues.pop(ws, None)
        logger.info(f"WebSocket client disconnected ({len(ws_queues)} total)")


# ── Helpers ────────────────────────────────────────────────────

def _parse_window(window: Optional[str]) -> Optional[int]:
    if not window:
        return None
    return {"5m": 300, "15m": 900, "1h": 3600, "24h": 86400}.get(window)


_WINDOW_QUERY = Query(None, pattern="^(5m|15m|1h|24h)$")


# ── Basic stats (existing) ─────────────────────────────────────

@app.get("/api/events")
async def get_events(
    limit: int = Query(50, ge=1, le=5000),
    window: Optional[str] = _WINDOW_QUERY,
):
    return {"events": store.recent(limit=limit, window=_parse_window(window))}


@app.get("/api/stats/countries")
async def get_top_countries(
    limit: int = Query(10, ge=1, le=500),
    window: Optional[str] = _WINDOW_QUERY,
):
    return {"countries": store.top_countries(limit=limit, window=_parse_window(window))}


@app.get("/api/stats/ips")
async def get_top_ips(
    limit: int = Query(10, ge=1, le=500),
    window: Optional[str] = _WINDOW_QUERY,
    source: Optional[str] = Query(None, pattern="^(ssh|http|visits)$"),
):
    return {"ips": store.top_ips(limit=limit, window=_parse_window(window), source=source)}


@app.get("/api/stats/usernames")
async def get_top_usernames(
    limit: int = Query(10, ge=1, le=500),
    window: Optional[str] = _WINDOW_QUERY,
):
    return {"usernames": store.top_usernames(limit=limit, window=_parse_window(window))}


@app.get("/api/stats/http-routes")
async def get_http_routes(
    limit: int = Query(10, ge=1, le=500),
    window: Optional[str] = _WINDOW_QUERY,
):
    return {"routes": store.top_http_routes(limit=limit, window=_parse_window(window))}


@app.get("/api/stats/timeline")
async def get_timeline(window: Optional[str] = _WINDOW_QUERY):
    return {"timeline": store.events_per_minute(window=_parse_window(window))}


@app.get("/api/stats/total")
async def get_total(window: Optional[str] = _WINDOW_QUERY):
    return {"total": store.total_count(window=_parse_window(window))}


# ── Threat intelligence (new) ──────────────────────────────────

_MASKED_IP = re.compile(r"^(\d{1,3}\.\d{1,3}\.\d{1,3}\.xxx|[0-9a-f:]{1,30}::xxxx)$")


def _checked_ip(ip: str) -> str:
    """
    The path parameter is public input and ends up in SQL lookups and in the
    URL of an outbound API call: accept only an IP address (or the truncated
    form HTTP visitors are stored in), nothing else.
    """
    if len(ip) <= 45:
        if _MASKED_IP.match(ip):
            return ip
        try:
            return str(ipaddress.ip_address(ip))
        except ValueError:
            pass
    raise HTTPException(status_code=400, detail="Not an IP address")


@app.get("/api/attacker/{ip}")
async def get_attacker_profile(ip: str):
    ip = _checked_ip(ip)
    abuse_data = threat_intel.get_cached_abuse(ip)
    abuse_conf = abuse_data.get("abuse_confidence") if abuse_data else None
    profile = analyzer.get_attacker_profile(ip, abuse_data=abuse_data or None)
    info = await asyncio.to_thread(db.ip_info, ip)

    if not profile and info:
        # Not in the live window any more, but the database remembers it
        users = [u["username"] for u in info["usernames"]]
        is_http = info["source"] == "http"
        pattern, ttps = classify(info["user_count"], info["attempts"], info["lines"],
                                 http_lines=info["lines"] if is_http else 0)
        profile = AttackerProfile(
            ip=ip, total_attempts=info["lines"], auth_attempts=info["attempts"],
            unique_usernames=info["user_count"],
            first_seen=info["first_seen"], last_seen=info["last_seen"],
            attack_pattern=pattern, attack_speed="SLOW_SCAN", requests_per_minute=0.0,
            mitre_ttps=ttps, usernames_attempted=users[:50],
            geo=GeoInfo(country=info["country"] or "Unknown",
                        country_code=info["country_code"] or "XX",
                        org=info["org"] or "", asn=info["org"] or ""),
            threat_score=0,
            abuse_confidence=abuse_conf or 0,
            abuse_total_reports=(abuse_data or {}).get("total_reports", 0),
        )
    if not profile:
        raise HTTPException(status_code=404, detail="No data for this IP")

    out = profile.to_dict()
    dual_hits = 0
    campaign = None
    if info:
        dual_hits = await asyncio.to_thread(db.has_dual_vector, ip)
        out.update({
            "net_type": info["net_type"] or "", "cloud": info["cloud"] or "",
            "tags": info["tags"], "days_active": info["days_active"],
            "first_seen_ever": info["first_seen"],
            "auth_attempts": max(info["attempts"], out["auth_attempts"]),
            "campaign": info["fingerprint"] or "", "campaign_size": info["campaign_size"],
            "campaign_usernames": info["fp_users"] or "",
        })
        if info["fingerprint"]:
            found = await asyncio.to_thread(campaigns.detect, db, 50)
            campaign = next((c for c in found if c["fingerprint"] == info["fingerprint"]), None)
            if campaign:
                out["campaign_confidence"] = campaign["confidence"]
                out["campaign_level"] = campaign["level"]
                out["campaign_label"] = campaign["label"]
    elif profile.geo:
        out["net_type"], out["cloud"] = profile.geo.net_type, profile.geo.cloud

    # Score again with what only the database knows: persistence and SSH+HTTP
    scored = score_ip(
        volume=out["auth_attempts"] or out["total_attempts"],
        rpm=out["requests_per_minute"],
        breadth=out["unique_usernames"] or len(out["http_routes"]),
        days_active=(info or {}).get("days_active", 1) or 1,
        exploit="T1190" in out["mitre_ttps"],
        multi_vector=bool(dual_hits) or bool(out["unique_usernames"] and out["http_routes"]),
        abuse_confidence=abuse_conf,
    )
    out.update(threat_score=scored["score"], severity=scored["severity"],
               score_breakdown=scored["breakdown"])

    alerts = await asyncio.to_thread(db.alerts_for_ip, ip)
    out["alerts"] = alerts
    out["narrative"] = narrative.build(out, info, campaign, alerts, dual_hits)

    # GreyNoise: only for a full IPv4 address this sensor has really seen,
    # so the endpoint cannot be used to burn the daily quota with made-up IPs
    if "xxx" not in ip and ipaddress.ip_address(ip).version == 4:
        gn = await intel.check_greynoise(ip)
        if gn:
            out["greynoise"] = gn
    return out


@app.get("/api/attackers")
async def get_attackers(
    limit: int = Query(20, ge=1, le=100),
    window: Optional[str] = _WINDOW_QUERY,
):
    profiles = analyzer.get_all_profiles(window=_parse_window(window), limit=limit)
    return {"attackers": [p.to_dict() for p in profiles]}


@app.get("/api/stats/patterns")
async def get_attack_patterns(window: Optional[str] = _WINDOW_QUERY):
    return {"patterns": analyzer.get_attack_pattern_summary(window=_parse_window(window))}


@app.get("/api/stats/mitre")
async def get_mitre(window: Optional[str] = _WINDOW_QUERY):
    return {"techniques": analyzer.get_mitre_summary(window=_parse_window(window))}


@app.get("/api/stats/asns")
async def get_asns(
    limit: int = Query(10, ge=1, le=500),
    window: Optional[str] = _WINDOW_QUERY,
):
    return {"asns": analyzer.get_asn_summary(window=_parse_window(window), limit=limit)}


@app.get("/api/stats/heatmap")
def get_heatmap(
    window: Optional[str] = _WINDOW_QUERY,
    range: Optional[str] = Query(None, pattern="^(today|7d|30d|all)$"),
):
    # Without a live window the grid comes from the database (whole history)
    if window:
        return {"heatmap": analyzer.get_heatmap(window=_parse_window(window))}
    return {"heatmap": db.heatmap(_parse_range(range))}


# ── Long-term intelligence (SQLite) ────────────────────────────

_RANGE_QUERY = Query("7d", pattern="^(today|7d|30d|all)$")
_RANGES = {"today": 1, "7d": 7, "30d": 30, "all": None}


def _parse_range(value: Optional[str]) -> Optional[int]:
    return _RANGES.get(value or "all")


def _named(rows: list[dict], name: str = "name") -> list[dict]:
    return [{name: r["key"], "count": r["count"]} for r in rows]


# Dimensions that may be read through the generic endpoint
_PUBLIC_DIMS = {
    "ssh_user", "ssh_cat", "ssh_country", "ssh_org", "ssh_net", "ssh_cloud",
    "ssh_banner", "ssh_kex", "country", "event_type", "source", "http_probe",
    "http_sig", "http_country", "http_net", "page", "visitor", "device", "os",
    "browser", "device_os", "lang", "referrer", "visit_country", "visit_net",
}


@app.get("/api/history/{dim}")
def get_history(
    dim: str,
    range: str = _RANGE_QUERY,
    limit: int = Query(20, ge=1, le=200),
):
    if dim not in _PUBLIC_DIMS:
        raise HTTPException(status_code=404, detail="Unknown dimension")
    return {"dim": dim, "range": range, "items": _named(db.top(dim, _parse_range(range), limit))}


@app.get("/api/intel/visitors")
def intel_visitors(range: str = _RANGE_QUERY):
    """Who visits the sites: devices, systems, browsers, languages, origin."""
    days = _parse_range(range)
    classes = {r["key"]: r["count"] for r in db.top("visitor", days, 20)}
    people = classes.get("browser", 0) + classes.get("browser_verified", 0)
    return {
        "range": range,
        "classes": classes,
        "people": people,
        "verified": classes.get("browser_verified", 0),
        "automated": sum(v for k, v in classes.items() if k not in ("browser", "browser_verified")),
        "devices": _named(db.top("device", days, 5)),
        "os": _named(db.top("os", days, 8)),
        "browsers": _named(db.top("browser", days, 8)),
        "device_os": _named(db.top("device_os", days, 10)),
        "languages": _named(db.top("lang", days, 8)),
        "referrers": _named(db.top("referrer", days, 10)),
        "countries": _named(db.top("visit_country", days, 8)),
        "networks": _named(db.top("visit_net", days, 5)),
        "pages": _named(db.top("page", days, 10)),
    }


@app.get("/api/intel/ssh")
def intel_ssh(range: str = _RANGE_QUERY, limit: int = Query(25, ge=1, le=200)):
    """What the SSH bots try: usernames, categories, networks, client banners."""
    days = _parse_range(range)
    users = db.top("ssh_user", days, limit)
    return {
        "range": range,
        "attempts": db.total("ssh_attempts", days),
        "lines": db.total("source", days, key="ssh"),
        "distinct_usernames": db.distinct_keys("ssh_user", days),
        "usernames": [
            {"username": u["key"], "count": u["count"], "category": categorize(u["key"])}
            for u in users
        ],
        "categories": _named(db.top("ssh_cat", days, 10)),
        "countries": _named(db.top("ssh_country", days, 10)),
        "networks": _named(db.top("ssh_org", days, 10)),
        "net_types": _named(db.top("ssh_net", days, 6)),
        "clouds": _named(db.top("ssh_cloud", days, 8)),
        "banners": _named(db.top("ssh_banner", days, 10)),
        "kex_offers": _named(db.top("ssh_kex", days, 5)),
    }


@app.get("/api/intel/campaigns")
def intel_campaigns(limit: int = Query(15, ge=1, le=100)):
    """Groups of addresses acting together, each with a confidence level."""
    return {
        "prefix_len": settings.CAMPAIGN_PREFIX_LEN,
        "campaigns": campaigns.detect(db, limit=limit),
    }


# ── Alerts ─────────────────────────────────────────────────────

@app.get("/api/alerts")
def get_alerts(
    limit: int = Query(50, ge=1, le=200),
    severity: Optional[str] = Query(None, pattern="^(LOW|MEDIUM|HIGH|CRITICAL)$"),
):
    """Alerts raised right now, the recent history and today's counters."""
    return {
        "enabled": settings.ALERTS_ENABLED,
        "notifications": notify.enabled(),
        "active": [a for a in alert_engine.active_alerts()
                   if not severity or a["severity"] == severity],
        "history": db.alerts(limit=limit, severity=severity),
        "today": db.alert_counts(),
    }


@app.get("/api/intel/persistence")
def intel_persistence(range: str = _RANGE_QUERY):
    days = _parse_range(range)
    return {
        "range": range,
        "new": db.total("ip_new", days, key="ssh"),
        "returning": db.total("ip_returning", days, key="ssh"),
        "totals": db.ip_counts(),
        "persistent": db.persistent_ips(15),
        "dual_vector": db.dual_vector(10),
        "daily": db.daily_series("ip_new", 14),
        "daily_returning": db.daily_series("ip_returning", 14),
    }


@app.get("/api/intel/signatures")
def intel_signatures(range: str = _RANGE_QUERY, limit: int = Query(20, ge=1, le=100)):
    """What the HTTP bots look for, mapped to products and CVEs."""
    days = _parse_range(range)
    items = []
    for r in db.top("http_sig", days, limit):
        sig_id, name, product, kind = (r["key"].split("|") + ["", "", ""])[:4]
        items.append({"id": sig_id, "name": name, "product": product, "kind": kind,
                      "cve": sig_id.startswith("CVE-"), "count": r["count"]})
    return {
        "range": range,
        "signatures": items,
        "probes": _named(db.top("http_probe", days, 15), "path"),
        "event_types": _named(db.top("event_type", days, 20)),
    }


@app.get("/api/intel/sankey")
def intel_sankey(hours: int = Query(24, ge=1, le=168)):
    return db.sankey(hours=hours)


@app.get("/api/intel/trend")
def intel_trend(days: int = Query(30, ge=2, le=365)):
    return {"days": db.daily_series("source", days)}


@app.get("/api/replay")
def get_replay(
    hours: int = Query(24, ge=1, le=168),
    buckets: int = Query(240, ge=24, le=720),
):
    """Down-sampled history for the time-lapse."""
    return db.replay(hours=hours, buckets=buckets)


_summary_cache: tuple[dict, float] = ({}, 0.0)


@app.get("/api/summary")
def get_summary():
    """Headline numbers for the landing screen (cached 15s)."""
    global _summary_cache
    cached, at = _summary_cache
    if cached and time.time() - at < 15:
        return cached
    top_user = db.top("ssh_user", None, 1)
    top_country = db.top("ssh_country", None, 1)
    visitors_all = {r["key"]: r["count"] for r in db.top("visitor", None, 20)}
    ips = db.ip_counts()
    summary = {
        "since": db.first_day(),
        "persistent": db.persistent,
        "sensor": settings.VPS_LABEL,
        "repo_url": settings.REPO_URL,
        "all_time": {
            "ssh_lines": db.total("source", None, key="ssh"),
            "ssh_attempts": db.total("ssh_attempts"),
            "http_probes": db.total("source", None, key="http"),
            "visits": db.total("source", None, key="visit"),
            "unique_ssh_ips": ips["ssh"],
            "countries": db.distinct_keys("ssh_country"),
            "usernames": db.distinct_keys("ssh_user"),
            "people": visitors_all.get("browser", 0) + visitors_all.get("browser_verified", 0),
        },
        "today": {
            "ssh_attempts": db.total("ssh_attempts", 1),
            "ssh_lines": db.total("source", 1, key="ssh"),
            "http_probes": db.total("source", 1, key="http"),
            "new_ips": db.total("ip_new", 1, key="ssh"),
        },
        "top_username": top_user[0] if top_user else None,
        "top_country": top_country[0] if top_country else None,
        "bot_of_the_day": db.bot_of_the_day(),
        "generated_at": datetime.now().isoformat(timespec="seconds"),
    }
    _summary_cache = (summary, time.time())
    return summary


_STARTED_AT = time.time()
_hud_cache: tuple[dict, float] = ({}, 0.0)


def _distance_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Great-circle distance (haversine)."""
    p1, p2 = math.radians(lat1), math.radians(lat2)
    a = (math.sin((p2 - p1) / 2) ** 2
         + math.cos(p1) * math.cos(p2) * math.sin(math.radians(lon2 - lon1) / 2) ** 2)
    return 6371.0 * 2 * math.asin(min(1.0, math.sqrt(a)))


@app.get("/api/stats/hud")
def get_hud():
    """
    Corner read-outs of the globe: sensor clock/uptime and today's records.
    Computed over the live store since local midnight (cached 15s), so on a
    very busy day it covers the last MAX_EVENTS events only.
    """
    global _hud_cache
    cached, at = _hud_cache
    if cached and time.time() - at < 15:
        return {**cached, "uptime_seconds": int(time.time() - _STARTED_AT)}

    now = datetime.now()
    midnight = now.replace(hour=0, minute=0, second=0, microsecond=0)
    events = store._filter_by_window(int((now - midnight).total_seconds()) + 1)

    per_ip: Counter = Counter()
    per_minute: Counter = Counter()
    farthest, farthest_km = None, -1.0
    for e in events:
        per_ip[e.ip] += e.count
        per_minute[e.timestamp[:16]] += e.count
        g = e.geo
        if g and g.country_code != "XX" and (g.lat or g.lon):
            km = _distance_km(settings.VPS_LAT, settings.VPS_LON, g.lat, g.lon)
            if km > farthest_km:
                farthest, farthest_km = e, km

    records: dict = {"farthest": None, "top_ip": None, "busiest_minute": None}
    if farthest:
        records["farthest"] = {
            "ip": farthest.ip,
            "city": farthest.geo.city,
            "country": farthest.geo.country,
            "country_code": farthest.geo.country_code,
            "km": round(farthest_km),
        }
    if per_ip:
        ip, count = per_ip.most_common(1)[0]
        geo = next((e.geo for e in store.events_for_ip(ip) if e.geo), None)
        records["top_ip"] = {"ip": ip, "count": count, "country_code": geo.country_code if geo else ""}
    if per_minute:
        minute, count = per_minute.most_common(1)[0]
        records["busiest_minute"] = {"minute": minute[11:16], "count": count}

    local = now.astimezone()
    hud = {
        "sensor": settings.VPS_LABEL,
        "tz": local.tzname() or "",
        "utc_offset_min": int(local.utcoffset().total_seconds() // 60),
        "today": {"events": sum(per_ip.values()), "unique_ips": len(per_ip)},
        "records": records,
    }
    _hud_cache = (hud, time.time())
    return {**hud, "uptime_seconds": int(time.time() - _STARTED_AT)}


# ── Export endpoints ───────────────────────────────────────────

@app.get("/api/export/stix")
async def export_stix(window: Optional[str] = _WINDOW_QUERY):
    bundle = stix_export.build_bundle(window=_parse_window(window))
    content = json.dumps(bundle, indent=2)
    return StreamingResponse(
        io.StringIO(content),
        media_type="application/json",
        headers={"Content-Disposition": "attachment; filename=stix_bundle.json"},
    )


@app.get("/api/export/csv")
async def export_csv(window: Optional[str] = _WINDOW_QUERY):
    content = stix_export.build_csv(window=_parse_window(window))
    return StreamingResponse(
        io.StringIO(content),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=ssh_events.csv"},
    )


@app.get("/api/export/blocklist")
def export_blocklist(
    days: int = Query(7, ge=1, le=90),
    min_attempts: int = Query(10, ge=1, le=100000),
    format: str = Query("txt", pattern="^(txt|nft)$"),
):
    """SSH addresses with repeated failed logins, ready for a firewall."""
    rows = db.blocklist(days=days, min_attempts=min_attempts)
    return PlainTextResponse(
        stix_export.build_blocklist(rows, format),
        headers={"Content-Disposition": "attachment; filename=siege_blocklist.txt"},
    )


@app.get("/api/export/report.md")
def export_report_markdown(range: str = Query("30d", pattern="^(today|7d|30d|all)$")):
    """Executive report from the long-term database, as Markdown."""
    return PlainTextResponse(
        report.build_markdown(db, _parse_range(range)),
        media_type="text/markdown; charset=utf-8",
        headers={"Content-Disposition": "attachment; filename=threat_report.md"},
    )


@app.get("/api/export/report")
async def export_report(window: Optional[str] = _WINDOW_QUERY):
    return stix_export.build_report(window=_parse_window(window))


# ── Health ─────────────────────────────────────────────────────

@app.get("/api/health")
async def health():
    return {
        "status": "ok",
        "events_stored": len(store.events),
        "total_processed": store._total_count,
        "ws_clients": len(ws_queues),
        "alerts_active": len(alert_engine.active),
        "threat_intel_enabled": settings.THREAT_INTEL_ENABLED,
        "db": db.stats(),
        "geo_provider": settings.GEO_PROVIDER,
        "tor_exits": len(intel._tor_exits),
    }
