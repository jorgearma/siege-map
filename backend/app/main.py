import asyncio
import io
import json
import logging
import time
import uuid
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Optional

from fastapi import FastAPI, HTTPException, Query, WebSocket, WebSocketDisconnect
from fastapi.responses import JSONResponse, StreamingResponse

from .analyzer import analyzer
from .anonymize import mask_ip
from .config import settings
from .db import db
from .geo import close_client, enrich_ip
from .models import AttackerProfile, GeoInfo
from .parser import parse_line
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
                    task = asyncio.create_task(threat_intel.check_abuseipdb(event.ip))
                    _background_tasks.add(task)
                    task.add_done_callback(_background_tasks.discard)

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

            for q in list(ws_queues.values()):
                try:
                    q.put_nowait(events)
                except asyncio.QueueFull:
                    pass
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
                events = await asyncio.wait_for(queue.get(), timeout=30)
                await ws.send_text(json.dumps({"type": "events", "data": events}))
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

@app.get("/api/attacker/{ip}")
async def get_attacker_profile(ip: str):
    abuse_data = threat_intel.get_cached_abuse(ip)
    profile = analyzer.get_attacker_profile(ip, abuse_data=abuse_data or None)
    info = await asyncio.to_thread(db.ip_info, ip)

    if not profile and info:
        # Not in the live window any more, but the database remembers it
        users = [u["username"] for u in info["usernames"]]
        pattern, ttps = analyzer._classify_pattern(set(users), 0.0, info["lines"])
        profile = AttackerProfile(
            ip=ip, total_attempts=info["lines"], unique_usernames=info["user_count"],
            first_seen=info["first_seen"], last_seen=info["last_seen"],
            attack_pattern=pattern, attack_speed="SLOW_SCAN", requests_per_minute=0.0,
            mitre_ttps=ttps, usernames_attempted=users[:50],
            geo=GeoInfo(country=info["country"] or "Unknown",
                        country_code=info["country_code"] or "XX",
                        org=info["org"] or "", asn=info["org"] or ""),
            threat_score=analyzer.calc_threat_score(
                0.0, pattern, info["lines"], (abuse_data or {}).get("abuse_confidence", 0)),
        )
    if not profile:
        raise HTTPException(status_code=404, detail="No data for this IP")

    out = profile.to_dict()
    if info:
        out.update({
            "net_type": info["net_type"] or "", "cloud": info["cloud"] or "",
            "tags": info["tags"], "days_active": info["days_active"],
            "first_seen_ever": info["first_seen"], "auth_attempts": info["attempts"],
            "campaign": info["fingerprint"] or "", "campaign_size": info["campaign_size"],
            "campaign_usernames": info["fp_users"] or "",
        })
    elif profile.geo:
        out["net_type"], out["cloud"] = profile.geo.net_type, profile.geo.cloud
    if "xxx" not in ip:
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
    """Addresses that try the same usernames in the same order: one botnet."""
    return {
        "prefix_len": settings.CAMPAIGN_PREFIX_LEN,
        "campaigns": db.campaigns(limit=limit),
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
        "threat_intel_enabled": settings.THREAT_INTEL_ENABLED,
        "db": db.stats(),
        "geo_provider": settings.GEO_PROVIDER,
        "tor_exits": len(intel._tor_exits),
    }
