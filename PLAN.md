# Plan: Passive SSH Honeypot — Threat Intelligence Dashboard

## Estado actual (base)

- Mapa en tiempo real con animaciones (arcos, partículas, impactos)
- GeoIP lookup via ip-api.com con cache
- Feed de eventos (failed_password, invalid_user, connection_closed, etc.)
- Stats panel (total, top countries, top IPs, top usernames)
- Charts timeline con Recharts
- Tema visual hacker terminal (green on black, CRT, matrix rain, glitch)

---

## Fase 1: Motor de Análisis (Backend)

Extraer inteligencia del mismo log sin nuevas fuentes de datos.

### 1.1 Nuevo archivo: `backend/app/analyzer.py`

Clase `Analyzer` que opera sobre el `EventStore` existente.

**Fingerprinting de patrones de ataque:**
- **DICTIONARY_ATTACK**: 1 IP, muchos usernames distintos (>5). MITRE T1110.001
- **CREDENTIAL_STUFFING**: 1 username desde muchas IPs (>3). MITRE T1110.004
- **PASSWORD_SPRAYING**: pocos usernames (1-3) desde 1 IP. MITRE T1110.003
- **SINGLE_PROBE**: 1-2 intentos y desaparece

**Velocidad del ataque:**
- **BRUTE_FORCE**: >10 req/min
- **MODERATE**: 2-10 req/min
- **SLOW_SCAN**: <2 req/min

**Métodos:**
- `get_attacker_profile(ip) -> AttackerProfile`
- `get_all_profiles(window, limit) -> list[AttackerProfile]`
- `get_targeted_usernames(limit, window) -> list[dict]`
- `get_attack_pattern_summary(window) -> dict`
- `get_asn_summary(window) -> list[dict]`
- `get_heatmap(window) -> list[list[int]]` (7 días × 24 horas)

Cache interno con TTL de 30s para no escanear el deque en cada request.

### 1.2 Modificar: `backend/app/models.py`

Añadir:

```python
@dataclass
class AttackerProfile:
    ip: str
    total_attempts: int
    unique_usernames: int
    first_seen: str
    last_seen: str
    attack_pattern: str        # DICTIONARY_ATTACK, CREDENTIAL_STUFFING, etc.
    attack_speed: str          # BRUTE_FORCE, MODERATE, SLOW_SCAN
    requests_per_minute: float
    mitre_ttps: list[str]      # ["T1110.001", "T1021.004"]
    usernames_attempted: list[str]
    geo: Optional[GeoInfo]
    threat_score: int          # 0-100

MITRE_TTPS = {
    "T1110.001": {"name": "Password Guessing", "tactic": "Credential Access"},
    "T1110.003": {"name": "Password Spraying", "tactic": "Credential Access"},
    "T1110.004": {"name": "Credential Stuffing", "tactic": "Credential Access"},
    "T1078":     {"name": "Valid Accounts", "tactic": "Initial Access"},
    "T1021.004": {"name": "Remote Services: SSH", "tactic": "Lateral Movement"},
}
```

### 1.3 Modificar: `backend/app/store.py`

Añadir métodos:
- `events_for_ip(ip, window) -> list[SSHEvent]`
- `events_for_username(username, window) -> list[SSHEvent]`

### 1.4 Modificar: `backend/app/main.py`

Nuevos endpoints:
- `GET /api/attacker/{ip}` — perfil completo
- `GET /api/attackers?window=&limit=` — lista ordenada por threat_score
- `GET /api/stats/patterns?window=` — distribución de tipos de ataque
- `GET /api/stats/asns?window=` — top ISPs/ASNs
- `GET /api/stats/heatmap?window=` — grid 7×24

Enriquecer eventos WebSocket con `attack_pattern` y `mitre_ttps` inline.

---

## Fase 2: Inteligencia Visual (Frontend)

### 2.1 Nuevo: `frontend/src/components/HeatmapChart.jsx`

- Grid 7 columnas (Lun-Dom) × 24 filas (0h-23h)
- Celdas coloreadas con opacidad proporcional al volumen
- Color: `var(--green)` a opacidades 0.05 → 1.0
- Scanline animado en la hora actual
- Título: `ATTACK_FREQUENCY_MATRIX`
- Datos de `GET /api/stats/heatmap`

### 2.2 Nuevo: `frontend/src/components/AttackerProfile.jsx`

Drawer lateral derecho (420px) que se abre al hacer clic en una IP.

Contenido:
- IP + país + bandera
- ISP/ASN (del campo `org` de GeoInfo)
- Badge de patrón: `DICTIONARY_ATTACK` (rojo), `CREDENTIAL_STUFFING` (naranja), etc.
- Badge de velocidad: `BRUTE_FORCE` (rojo), `MODERATE` (amber), `SLOW_SCAN` (cyan)
- Badges MITRE ATT&CK: `T1110.001 Password Guessing`
- Barra threat score 0-100 con gradiente verde→rojo
- Requests per minute
- Timeline: first seen / last seen
- Lista de usernames intentados (scrollable, max 50)
- Datos de `GET /api/attacker/{ip}`

### 2.3 Nuevo: `frontend/src/components/MitreBadge.jsx`

Badge reutilizable con borde lateral coloreado y texto monospace.

### 2.4 Modificar: `frontend/src/components/EventFeed.jsx`

- IPs clickables (`cursor: pointer`, underline on hover)
- Callback `onIpClick(ip)` hacia App.jsx
- Badges MITRE inline si vienen en el evento WebSocket

### 2.5 Modificar: `frontend/src/components/StatsPanel.jsx`

- IPs clickables en TOP_THREAT_IPS
- Nueva card `ATTACK_PATTERNS` con distribución por tipo

### 2.6 Modificar: `frontend/src/App.jsx`

- Estado `selectedIp` + handler open/close drawer
- Pasar `onIpClick` a EventFeed y StatsPanel
- Renderizar `<AttackerProfile>` condicional
- Integrar HeatmapChart en la sección de charts

### 2.7 Modificar: `frontend/src/styles/app.css`

Nuevos estilos:
- `.attacker-drawer` — fixed, right: 0, width: 420px, z-index: 2000
- `.attacker-drawer-backdrop` — overlay semitransparente
- `.mitre-badge` — badge rectangular con borde lateral
- `.attack-pattern-badge` — badges de clasificación
- `.speed-badge` — badges de velocidad
- `.heatmap-grid` — layout 7×24
- `.heatmap-cell` — celda con hover tooltip
- `.ip-clickable` — estilos hover para IPs
- `.threat-score-bar` — barra horizontal con gradiente

---

## Fase 3: Threat Intelligence (APIs externas)

### 3.1 Nuevo: `backend/app/threat_intel.py`

**AbuseIPDB** (gratis, 1000 checks/día):
- `check_ip_reputation(ip) -> dict`
- Endpoint: `https://api.abuseipdb.com/api/v2/check`
- Devuelve: abuse_confidence_score, total_reports, usage_type, isp
- Cache: dict con TTL 24h (misma estrategia que geo.py)
- Rate limit: semáforo, max 1 req/s, max 900/día
- Solo consultar IPs que aparezcan más de una vez

**Shodan** (opcional, gratis limitado):
- `shodan_host_info(ip) -> dict | None`
- Endpoint: `https://api.shodan.io/shodan/host/{ip}`
- Devuelve: puertos abiertos, OS, vulns
- Si no hay `SHODAN_API_KEY`, skip

**Threat score combinado** (en analyzer.py):
```
score = abuse_confidence × 0.4
      + speed_score × 0.25       # BRUTE=80, MODERATE=40, SLOW=20
      + pattern_score × 0.25     # DICT=60, CRED_STUFF=70, SPRAY=50, PROBE=10
      + volume_score × 0.1       # min(attempts/10 * 100, 100)
```

### 3.2 Modificar: `backend/app/config.py`

```python
ABUSEIPDB_API_KEY: str   # env var, default ""
SHODAN_API_KEY: str      # env var, default ""
THREAT_INTEL_ENABLED: bool  # True si ABUSEIPDB_API_KEY != ""
ABUSE_CACHE_TTL: int     # default 86400
```

### 3.3 Modificar: `backend/app/main.py`

- En `process_log_lines()`: consultar AbuseIPDB después del geo enrich (no bloqueante)
- Endpoint `GET /api/attacker/{ip}` incluye datos de reputación si disponibles

### 3.4 Modificar: `frontend/src/components/AttackerProfile.jsx`

- Badge `KNOWN_SCANNER` rojo pulsante si abuse_confidence > 50
- Barra de AbuseIPDB confidence score
- Total de reportes

### 3.5 Crear `.env.example`

```env
SSH_LOG_PATH=/var/log/auth.log
VPS_LAT=40.4168
VPS_LON=-3.7038
VPS_LABEL=My VPS
GEO_PROVIDER=ip-api
ABUSEIPDB_API_KEY=
SHODAN_API_KEY=
```

---

## Fase 4: Output Profesional (Portfolio)

### 4.1 Nuevo: `backend/app/stix_export.py`

Genera STIX 2.1 Bundle:
- `identity`: el honeypot sensor
- `indicator`: cada IP atacante con pattern `[ipv4-addr:value = 'x.x.x.x']`
- `attack-pattern`: MITRE ATT&CK TTPs detectados
- `observed-data`: resumen de patrones observados
- `relationship`: conecta indicators con attack-patterns

Dependencia: `stix2` (añadir a requirements.txt). Alternativa: construir el JSON a mano siguiendo la spec STIX 2.1 para evitar la dependencia.

### 4.2 Nuevo: `frontend/src/components/ExportPanel.jsx`

Botones en el header con estilo cyan:
- `[EXPORT STIX]` — descarga bundle JSON
- `[EXPORT CSV]` — descarga eventos CSV
- `[GENERATE REPORT]` — resumen ejecutivo

### 4.3 Modificar: `backend/app/main.py`

Endpoints:
- `GET /api/export/stix?window=` — STIX bundle
- `GET /api/export/csv?window=` — CSV de eventos
- `GET /api/export/report?window=` — resumen ejecutivo JSON

### 4.4 Polish final

- Título: `PASSIVE_SSH_HONEYPOT // THREAT_SENSOR`
- Footer: `LOW_INTERACTION_HONEYPOT :: SENSOR_ID: [UUID] :: UPTIME: [calculado]`
- README profesional describiendo el proyecto como honeypot

---

## Resumen de archivos

### Nuevos (7)

| Archivo | Propósito |
|---|---|
| `backend/app/analyzer.py` | Clasificación de ataques, perfiles, heatmap |
| `backend/app/threat_intel.py` | AbuseIPDB + Shodan con cache |
| `backend/app/stix_export.py` | Exportación STIX 2.1 |
| `frontend/src/components/HeatmapChart.jsx` | Heatmap 7×24 |
| `frontend/src/components/AttackerProfile.jsx` | Drawer perfil atacante |
| `frontend/src/components/ExportPanel.jsx` | Botones exportación |
| `frontend/src/components/MitreBadge.jsx` | Badge MITRE reutilizable |

### Modificados (9)

| Archivo | Cambios |
|---|---|
| `backend/app/models.py` | AttackerProfile, MITRE_TTPS |
| `backend/app/store.py` | events_for_ip(), events_for_username() |
| `backend/app/config.py` | API keys, THREAT_INTEL_ENABLED |
| `backend/app/main.py` | ~8 endpoints, enriquecer WebSocket |
| `backend/requirements.txt` | stix2 |
| `frontend/src/App.jsx` | Drawer state, layout, título |
| `frontend/src/components/EventFeed.jsx` | IPs clickables, badges |
| `frontend/src/components/StatsPanel.jsx` | IPs clickables, patterns card |
| `frontend/src/styles/app.css` | Drawer, badges, heatmap, threat score |

---

## Orden de implementación

```
Fase 1 (backend analysis) ──→ Fase 2 (frontend visual)
                           ╲
                            ──→ Fase 3 (threat intel) ──→ Fase 4 (export + polish)
```

Fase 3 backend se puede hacer en paralelo con Fase 2 frontend.
Cada fase es desplegable independientemente.

---

## Descripción para portfolio

> **Passive SSH Honeypot with Real-Time Threat Intelligence Dashboard**
>
> Low-interaction honeypot collecting and visualizing attack telemetry:
> geolocation, ASN attribution, TTP classification aligned with MITRE ATT&CK,
> behavioral fingerprinting of automated threat actors, and STIX 2.1 export
> for threat intelligence sharing.
