# Despliegue y configuracion — siege map

Todo lo necesario para montar siege map en tu propio VPS: arranque, modo demo con datos
sinteticos, todas las variables de entorno, despliegue tras Cloudflare Tunnel y
troubleshooting.

Para **qué hace y cómo detecta**, vuelve al [README](../README.md).

---

## Levantarlo en 30 segundos

```bash
git clone <este-repo>
cd siege-map
cp .env.example .env
# Edita .env (ver "Adaptar a tu entorno" abajo)
docker compose up -d --build
```

Luego abre:
- Dashboard: `http://127.0.0.1:8082` (solo localhost; publícalo con un reverse proxy o Cloudflare Tunnel)
- API: `http://localhost:8000/api/health`

### Modo desarrollo (con logs sinteticos)
Si estas probando localmente y no tienes acceso a logs reales:

```bash
docker compose -f docker-compose.dev.yml up -d --build
# En otra terminal, genera trafico falso:
python scripts/fake_ssh_log.py --output ./logs/auth.log --rate 2.0
```

El compose dev monta `./logs/auth.log` en lugar de los logs del host.

### Demo guiada (5 minutos)

`scripts/demo_scenario.py` escribe un dia de ataque completo para que cada deteccion tenga algo que enseñar:

```bash
docker compose -f docker-compose.dev.yml up -d --build
python scripts/demo_scenario.py        # historico + parte en vivo
```

1. **Mapa y feed**: llegan los eventos en vivo.
2. **INTEL -> CAMPAIGNS**: la botnet (`zx_miner...`, un /24, 20 minutos) sale como `coordinated campaign`; la wordlist `root, admin, user, test` compartida por maquinas sin relacion sale como `shared tooling`. Click en la fila para ver la evidencia.
3. **Click en un miembro**: dossier con desglose del score y narrativa.
4. A los ~3 minutos el script lanza un pico de trafico y un login aceptado tras siete fallos: saltan `BURST` y `LOGIN ACCEPTED` (aviso en la cabecera + toast).
5. **[BLOCKLIST]** y `curl localhost:8000/api/export/report.md` para el informe.

Con `GEO_PROVIDER=ip-api` (45 consultas/min) las ~130 IPs tardan unos tres minutos en aparecer; con `mmdb` es inmediato.

---

## Adaptar a tu entorno

Todo lo que probablemente quieras tocar.

### 1. Variables de entorno (`.env`)

| Variable | Default | Que cambiar y por que |
|----------|---------|------------------------|
| `SSH_LOG_PATH` | `/var/log/auth.log` | **Obligatorio**. Debian/Ubuntu usa `auth.log`, RHEL/CentOS/Fedora usa `/var/log/secure`. |
| `NGINX_LOG_PATH` | `/var/log/nginx/access.log` | Opcional. Si no usas Nginx dejalo vacio o apunta a tu access log (Apache funciona si esta en formato combined). |
| `NGINX_LOG_PATHS` | _(vacio)_ | Varios access logs separados por coma (rutas **dentro** del contenedor). Si tiene valor, sustituye a `NGINX_LOG_PATH`. |
| `NGINX_LOG_DIR` | `/var/log/nginx` | Carpeta del **host** que se monta (solo lectura) como `/var/log/nginx` en el backend. Ver "Webs en contenedores" abajo. |
| `MASK_HTTP_IPS` | `true` | Trunca las IPs de visitantes HTTP a /24 (IPv4) o /48 (IPv6) antes de guardarlas. |
| `IGNORE_IPS` | _(vacio)_ | Tus IPs (casa, móvil), nunca aparecen en el mapa. |
| `TZ` | `UTC` | Zona horaria del **host**. Las lineas syslog clasicas no llevan offset: si el contenedor usa otro reloj, las ventanas de tiempo salen desplazadas. |
| `VPS_LAT` | `40.4168` | **Obligatorio**. Latitud de tu VPS — donde caera la "lluvia" de arcos. |
| `VPS_LON` | `-3.7038` | **Obligatorio**. Longitud de tu VPS. |
| `VPS_LABEL` | `My VPS` | Texto que veras en el popup del marker del VPS. |
| `GEO_PROVIDER` | `ip-api` | `ip-api` (gratis, 45 req/min) o `ipinfo` (mejor calidad, requiere token). |
| `IPINFO_TOKEN` | _(vacio)_ | Solo si `GEO_PROVIDER=ipinfo`. Token gratis en [ipinfo.io](https://ipinfo.io/). |
| `ABUSEIPDB_API_KEY` | _(vacio)_ | Opcional. Activa enriquecimiento de reputacion. Free tier: 1000 checks/dia. |
| `SHODAN_API_KEY` | _(vacio)_ | Opcional. Datos extra de puertos/OS/vulns. |
| `MAX_EVENTS` | `10000` | Eventos en memoria (cola circular). Sube si tienes mucho trafico y quieres ventanas largas. |
| `GEO_CACHE_TTL` | `86400` | TTL del cache de geo en segundos (24h por defecto). |
| `ABUSE_CACHE_TTL` | `86400` | TTL del cache de AbuseIPDB. |
| `WS_BROADCAST_INTERVAL` | `1.0` | Cadencia de envio por WebSocket en segundos. Sube a `2.0` si tu CPU sufre. |
| `ALERT_WEBHOOK_URL` | _(vacio)_ | Opcional. Webhook de Discord/Slack (se detectan) o cualquier URL que acepte JSON. Sin el, las alertas solo salen en el dashboard. |
| `ALERT_TELEGRAM_BOT_TOKEN` / `ALERT_TELEGRAM_CHAT_ID` | _(vacio)_ | Opcional. Alertas por Telegram. |
| `ALERT_NOTIFY_MIN_SEVERITY` | `HIGH` | Severidad minima que se envia fuera. |
| `ALERT_COOLDOWN` | `600` | Segundos de calma para resolver una alerta. El resto de umbrales (`ALERT_*`) estan comentados en `.env.example`. |
| `FRONTEND_PORT` | `8082` | Puerto del dashboard (en `127.0.0.1`). Cambialo si ya está en uso. |
| `BACKEND_PORT` | `8000` | Puerto del backend FastAPI. |

### 2. Rutas HTTP "legitimas" de tu app
**Importante** si tienes Nginx sirviendo una web propia. Por defecto cualquier ruta no listada se marca como `BOT_PROBE` (amarillo). Para que tus rutas reales aparezcan en azul como visitas legitimas:

Edita `frontend/src/config/knownRoutes.js` y añade tus rutas:

```js
export const KNOWN_ROUTES = [
  '/',
  '/about',
  '/api/...',
  // tus rutas aqui
]
```

### 2b. Webs en contenedores (p. ej. detrás de Cloudflare Tunnel)
En la imagen oficial `nginx` el `access.log` es un symlink a `/dev/stdout`: los logs solo existen en `docker logs` y el radar no tiene nada que leer. Para cada web:

1. **IP real del visitante** en el `nginx.conf` de la web (si no, todo llega desde el gateway de Docker `172.x` y el parser lo descarta):
   ```nginx
   set_real_ip_from 172.16.0.0/12;
   real_ip_header   CF-Connecting-IP;
   ```
   Solo es seguro si el puerto de la web está publicado en `127.0.0.1` (nadie de fuera puede inventarse la cabecera).
2. **Volumen** en el compose de la web, encima de `/var/log/nginx` (tapa los symlinks y nginx escribe un archivo real):
   ```yaml
   volumes:
     - /var/log/web/<sitio>:/var/log/nginx
   ```
3. **`.env` de siege-map**:
   ```bash
   NGINX_LOG_DIR=/var/log/web
   NGINX_LOG_PATHS=/var/log/nginx/<sitio>/access.log
   ```
4. **Rotación** en el host (`/etc/logrotate.d/web`). `copytruncate` porque nginx vive en el contenedor y no recibe la señal de reabrir; `tail -F` aguanta el truncado:
   ```
   /var/log/web/*/access.log {
       daily
       rotate 14
       compress
       delaycompress
       missingok
       notifempty
       copytruncate
   }
   ```

Si el backend no puede **leer** el log al arrancar (permisos), esa ingesta se para hasta reiniciar el backend: `docker logs ssh-rain-backend | grep -i permission`.

### 2c. Cloudflare Tunnel en contenedor (opcional)
[`docker-compose.tunnel.yml`](../docker-compose.tunnel.yml) añade un `cloudflared` propio del proyecto. Frente a un cloudflared instalado en el host: no corre como root, el frontend **no publica puerto** y **no tiene salida a Internet** (solo el backend y el túnel la tienen).

```bash
# 1. Zero Trust → Networks → Tunnels → Create a tunnel → Cloudflared.
#    Copiar SOLO el token (empieza por eyJ). No ejecutar el comando del panel.

# 2. Guardar el token sin que se vea ni quede en el historial
mkdir -p -m 700 secrets
read -rs -p "Token: " T; echo; printf '%s' "$T" > secrets/tunnel_token; unset T
chmod 444 secrets/tunnel_token

# 3. Activar el override (en .env) y levantar
echo 'COMPOSE_FILE=docker-compose.yml:docker-compose.tunnel.yml' >> .env
docker compose up -d --build
docker compose logs cloudflared | grep 'Registered tunnel connection'

# 4. Panel → rutas del túnel → http://frontend:3000
```

La red `internal` usa la subred `172.30.82.0/24`: si choca con otra red del host (`Pool overlaps`), cámbiala en el override. Tiene que seguir dentro de `172.16.0.0/12` para que `set_real_ip_from` de `frontend/nginx.conf` acepte la IP real.

### 3. Coordenadas del VPS
Si no sabes la lat/lon de tu servidor, usa `curl ifconfig.co/json` desde el VPS o consulta el panel de tu proveedor (Hetzner, DigitalOcean, OVH, etc).

### 4. Frontend en host distinto al backend
Si despliegas frontend y backend en hosts separados (no recomendado para esta app, pero posible):
- Edita `frontend/src/hooks/useWebSocket.js` para apuntar al WS correcto (`ws://tu-backend:8000/ws`).
- Edita `frontend/vite.config.js` (`proxy.target`) para el modo dev.
- En produccion el `nginx.conf` del frontend asume backend en el servicio docker llamado `backend`. Cambialo si tu setup es distinto.

### 5. Si tu VPS ya usa los puertos 3000/8000
Cambia `FRONTEND_PORT` y `BACKEND_PORT` en `.env` o edita los port mappings en `docker-compose.yml`. Por ejemplo:

```yaml
frontend:
  ports:
    - "8080:80"   # accede en :8080
```

### 6. Permisos del log de SSH
El backend lee el log montado como read-only. En la mayoria de distros `auth.log` pertenece a `root:adm` o `root:syslog`. Si el contenedor no puede leerlo:

```bash
sudo chmod o+r /var/log/auth.log
# o ajusta el user del contenedor en docker-compose.yml
```

### 7. Personalizar la apariencia
- **Tema Pip-Boy**: las variables CSS estan al inicio de `frontend/src/styles/app.css` (`--pip-green`, `--pip-amber`, `--pip-bg`, etc). Cambialas para tener tu propia paleta.
- **Colores de tipos de ataque**: definidos en `frontend/src/components/WorldMap.jsx` (`SSH_COLOR`, `HTTP_COLOR`, `VISITOR_COLOR`).
- **Mensajes de glitch**: edita `GLITCH_LINES` en `frontend/src/components/StatsPanel.jsx`.

---

## Operacion y troubleshooting

```bash
# Health check
curl http://localhost:8000/api/health

# Logs en vivo
docker compose logs -f backend
docker compose logs -f frontend

# Datos crudos
curl http://localhost:8000/api/events?limit=20
curl http://localhost:8000/api/stats/total

# Reset (sin perder logs del host)
docker compose restart backend

# Rebuild despues de tocar codigo
docker compose up -d --build
```

**Actualizar y volver atrás (imágenes etiquetadas con el commit):**
```bash
git pull
TAG=$(git rev-parse --short HEAD) docker compose up -d --build   # siege-map-*:<commit>

docker image ls 'siege-map-*'                                    # versiones disponibles
T=<commit-anterior>                                              # rollback, sin reconstruir:
docker image inspect siege-map-backend:$T siege-map-frontend:$T >/dev/null && TAG=$T docker compose up -d
# OJO: sin el "docker image inspect", un TAG que no existe NO da error: compose construye
# el código actual y le pone esa etiqueta (comprobado; pull_policy: never tampoco lo evita)

docker image rm siege-map-backend:<commit> siege-map-frontend:<commit>   # borrar versiones viejas
```

**No veo eventos:**
1. ¿El contenedor lee el log? `docker compose exec backend cat $SSH_LOG_PATH | head` (deberia funcionar).
2. ¿Hay actividad real? Genera con `python scripts/fake_ssh_log.py --output ./logs/auth.log --rate 2.0` en modo dev.
3. ¿Las coordenadas del VPS son correctas? Si estan a `0,0` el mapa centrara al medio del oceano.

**Geo dice "Unknown":**
- ip-api tiene rate limit. Espera o cambia a ipinfo con token.
- IPs privadas (`10.x`, `192.168.x`) no se geolocalizan a proposito.

**Frontend no conecta WS:**
- Mira la consola del navegador. Si hay `404` en `/ws`, revisa que el proxy de Vite o el `nginx.conf` apunten al backend correcto.
