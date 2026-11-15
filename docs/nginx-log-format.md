# Formato de log de nginx para siege-map

siege-map entiende dos formatos de access log:

| Formato | Qué aporta |
|---|---|
| `combined` (el de por defecto) | IP, ruta, código, **referer** y user-agent → dispositivo, sistema, navegador, de dónde llegan |
| `siege_json` (este documento) | Todo lo anterior + **idioma del navegador**, host y tiempo de respuesta. Además permite detectar "navegadores" que no envían `Accept-Language` (scripts disfrazados) |

No hace falta cambiar nada para que funcione: con `combined` solo se queda vacía la tarjeta LANGUAGE.

## Activarlo

En el bloque `http {}` del nginx **de la web que quieres medir** (no el del frontend de siege-map):

```nginx
log_format siege_json escape=json
  '{'
    '"time":"$time_iso8601",'
    '"ip":"$remote_addr",'
    '"method":"$request_method",'
    '"uri":"$request_uri",'
    '"status":$status,'
    '"ua":"$http_user_agent",'
    '"referer":"$http_referer",'
    '"lang":"$http_accept_language",'
    '"host":"$host",'
    '"rt":$request_time'
  '}';

access_log /var/log/nginx/access.log siege_json;
```

Y recargar: `nginx -t && nginx -s reload` (o `docker compose restart <web>`).

Notas:

- `escape=json` es obligatorio: sin él, un user-agent con comillas rompe la línea.
- `$remote_addr` solo es la IP real del visitante si tienes configurado `real_ip_header`
  (ver "Webs en contenedores" en el README). Detrás de Cloudflare Tunnel, sin eso, todo llega
  desde `172.x` y el parser lo descarta.
- Otras herramientas que lean ese log (GoAccess, fail2ban) esperan `combined`. Si las usas,
  escribe los dos: añade una segunda línea `access_log /var/log/nginx/access.json.log siege_json;`
  y apunta `NGINX_LOG_PATHS` a ese archivo.

## Qué se guarda y qué no

| Dato del log | Qué hace siege-map |
|---|---|
| IP del visitante | Se geolocaliza y se **trunca** a /24 (IPv4) o /48 (IPv6) antes de guardarse. La IP completa solo vive en memoria, hasta medianoche, para contar visitantes únicos |
| User-agent | Se reduce a familia: `mobile · Android · Chrome`. El texto completo y la versión no se guardan |
| Referer | Solo el sitio (`linkedin`, `search:google`, `blog.example.org`). Nunca la URL ni la búsqueda |
| `Accept-Language` | Solo el idioma principal (`es`) |
| Ruta | La ruta sin query string |

Lo que queda en disco son contadores diarios ("3 visitantes Android/Chrome el 15-nov"), no un
historial por persona.

## Limitación conocida: verificación por assets detrás de un CDN

La pestaña VISITORS separa `Browser (verified)` —pidió también css/js/imágenes, como hace un
navegador real— de `Browser` —solo pidió la página—. Si la web está detrás de Cloudflare, los
estáticos cacheados se sirven desde el borde y **no llegan al origen**, así que muchas personas
reales aparecerán como `Browser` sin verificar. No es un fallo de detección: es que el log del
origen no ve esas peticiones.
