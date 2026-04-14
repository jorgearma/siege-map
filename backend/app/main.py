import asyncio
import io
import json
import logging
import uuid
from contextlib import asynccontextmanager
from typing import Optional

from fastapi import FastAPI, HTTPException, Query, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse

from .analyzer import analyzer
from .config import settings
from .geo import close_client, enrich_ip
from .parser import parse_line
from . import nginx_parser
from . import stix_export
from . import threat_intel
from .store import store
from .tail import tail_log

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)

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

        events_parsed += 1
        logger.debug(f"Parsed event: {event.event_type} from {event.ip} user={event.username}")

        try:
            event.id = str(uuid.uuid4())[:8]
            event.geo = await enrich_ip(event.ip)

            if store.add(event):
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


async def process_nginx_lines():
    """Pipeline for nginx access log: tail → parse → enrich → store → buffer."""
    nginx_path = settings.NGINX_LOG_PATH
    if not nginx_path:
        return
    logger.info(f"Starting nginx ingestion from {nginx_path}")
    lines_seen = 0
    events_parsed = 0

    async for line in tail_log(nginx_path):
        lines_seen += 1
        if lines_seen % 100 == 0:
            logger.info(
                f"Nginx pipeline: {lines_seen} lines seen, {events_parsed} parsed"
            )

        event = nginx_parser.parse_nginx_line(line)
        if event is None:
            continue

        events_parsed += 1
        try:
            event.id = str(uuid.uuid4())[:8]
            event.geo = await enrich_ip(event.ip)

            if store.add(event):
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


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("SSH Bot Rain Map starting up")
    logger.info(f"VPS location: {settings.VPS_LAT}, {settings.VPS_LON}")
    logger.info(f"Geo provider: {settings.GEO_PROVIDER}")
    logger.info(f"Threat intel enabled: {settings.THREAT_INTEL_ENABLED}")

    task_ingest = asyncio.create_task(process_log_lines())
    task_nginx = asyncio.create_task(process_nginx_lines())
    task_flush = asyncio.create_task(flush_loop())
    _background_tasks.add(task_ingest)
    _background_tasks.add(task_nginx)
    _background_tasks.add(task_flush)
    task_ingest.add_done_callback(_background_tasks.discard)
    task_nginx.add_done_callback(_background_tasks.discard)
    task_flush.add_done_callback(_background_tasks.discard)

    yield

    task_ingest.cancel()
    task_nginx.cancel()
    task_flush.cancel()
    await close_client()
    logger.info("Shut down complete")


app = FastAPI(
    title="Passive SSH Honeypot — Threat Intelligence Dashboard",
    description="Real-time SSH bot attack visualization with MITRE ATT&CK classification",
    version="2.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


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
    if not profile:
        raise HTTPException(status_code=404, detail="No data for this IP")
    return profile.to_dict()


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
async def get_heatmap(window: Optional[str] = _WINDOW_QUERY):
    return {"heatmap": analyzer.get_heatmap(window=_parse_window(window))}


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
    }
