# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Project Is

Real-time SSH bot attack visualizer. The backend tails an SSH log file, parses events, enriches them with geolocation, and streams them to the frontend via WebSocket. The frontend displays attack origins on a world map with animated arcs.

## Running the Project

### Production (Docker)
```bash
cp .env.example .env  # configure SSH_LOG_PATH, VPS_LAT, VPS_LON
docker compose up -d --build
# Frontend: http://localhost:3000  Backend: http://localhost:8000
```

### Dev mode (mounts ./logs/auth.log instead of host log)
```bash
docker compose -f docker-compose.dev.yml up -d --build
```

### Backend only (local)
```bash
cd backend
pip install -r requirements.txt
SSH_LOG_PATH=/var/log/auth.log uvicorn app.main:app --reload
```

### Frontend only (local)
```bash
cd frontend
npm install
npm run dev   # http://localhost:5173
```
Vite proxies `/api` → `localhost:8000` and `/ws` → `ws://localhost:8000`. For Docker-based backend, the target must be changed to `backend:8000` in `vite.config.js`.

### Health check
```bash
curl http://localhost:8000/api/health
```

## Architecture

```
SSH log → tail_log() → parse_line() → enrich_ip() → EventStore → WebSocket broadcast
                                                                 ↘ REST API
```

**Backend (`backend/app/`)**
- `main.py` — FastAPI app. Two background tasks: `process_log_lines()` (pipeline) and `flush_loop()` (WS broadcast every `WS_BROADCAST_INTERVAL`). Per-client `asyncio.Queue` in `ws_queues` dict. On WS connect, sends `config` then `initial` (last 100 events) then streams `events` batches.
- `store.py` — `EventStore` (singleton `store`): bounded `deque(maxlen=MAX_EVENTS)` with time-windowed query methods. Deduplicates on `ip:username:event_type:minute`.
- `parser.py` — Regex-based SSH log parser. Returns `SSHEvent | None`.
- `geo.py` — Async geolocation via ip-api.com or ipinfo.io with in-memory TTL cache.
- `tail.py` — `async for line in tail_log(path)`: async file tailer.
- `models.py` — `SSHEvent` and `GeoInfo` dataclasses.
- `config.py` — `Settings` class reads all config from env vars; singleton `settings`.

**Frontend (`frontend/src/`)**
- `App.jsx` — Root component. Holds all state, renders layout.
- `hooks/useWebSocket.js` — Manages WS connection, dispatches `config`/`initial`/`events`/`ping` message types.
- `components/WorldMap.jsx` — Leaflet map with animated arcs (attack origin → VPS).
- `components/EventFeed.jsx` — Live scrolling event list.
- `components/StatsPanel.jsx` — Top countries, IPs, usernames.
- `components/Charts.jsx` — Recharts timeline (events/minute).
- `styles/app.css` — All styles (hacker terminal theme: green on black, CRT effects).

## Key Design Decisions

- **In-memory only**: No database. Events lost on restart. `deque(maxlen=MAX_EVENTS)` is the store.
- **WS message types**: `config` (VPS coords), `initial` (recent events), `events` (new batch), `ping` (keepalive every 30s).
- **Window parameter**: REST endpoints accept `window=5m|15m|1h|24h`; translated to seconds in `_parse_window()`.
- **Geo rate limiting**: ip-api.com free tier is 45 req/min. Repeated IPs are cached in memory for `GEO_CACHE_TTL` seconds (default 24h).
- **Docker volume**: In production, the SSH log file is bind-mounted read-only into the backend container.

## New components (Phase 2+)

- `components/MitreBadge.jsx` — badge reutilizable MITRE ATT&CK (id + nombre)
- `components/AttackerProfile.jsx` — drawer lateral 420px, abre al clickar una IP. Fetch `GET /api/attacker/{ip}`. Muestra threat score, TTPs, AbuseIPDB, usernames.
- `components/HeatmapChart.jsx` — grid 7×24 (día×hora), datos de `GET /api/stats/heatmap`.
- `components/ExportPanel.jsx` — botones STIX / CSV / REPORT que disparan descargas.

## Threat intelligence API (Phase 3)

`backend/app/threat_intel.py` — AbuseIPDB (fire-and-forget en pipeline, cache 24h, max 900/día).
`backend/app/analyzer.py` — `Analyzer` class con cache de 30s. Clasifica IPs en DICTIONARY_ATTACK, PASSWORD_SPRAYING, SINGLE_PROBE. Genera heatmap 7×24.
`backend/app/stix_export.py` — STIX 2.1 JSON construido manualmente (sin librería `stix2`).

New REST endpoints:
- `GET /api/attacker/{ip}` — perfil completo con TTPs y AbuseIPDB
- `GET /api/attackers?window=&limit=` — ranking por threat score
- `GET /api/stats/patterns?window=` — distribución de tipos de ataque
- `GET /api/stats/asns?window=` — top ISPs/ASNs
- `GET /api/stats/heatmap?window=` — grid 7×24
- `GET /api/export/stix?window=` — bundle STIX 2.1 (descarga JSON)
- `GET /api/export/csv?window=` — eventos CSV
- `GET /api/export/report?window=` — resumen ejecutivo JSON

## Planned Expansion (PLAN.md)

PLAN.md documents a multi-phase evolution into a Threat Intelligence Dashboard:
- **Phase 1**: `analyzer.py` — attack fingerprinting (DICTIONARY_ATTACK, CREDENTIAL_STUFFING, PASSWORD_SPRAYING), MITRE ATT&CK TTPs, threat scores.
- **Phase 2**: Frontend drawer for attacker profiles, heatmap 7×24, MITRE badges.
- **Phase 3**: AbuseIPDB + Shodan integration (`threat_intel.py`).
- **Phase 4**: STIX 2.1 export, CSV export, executive report.

New env vars for Phase 3: `ABUSEIPDB_API_KEY`, `SHODAN_API_KEY`.
