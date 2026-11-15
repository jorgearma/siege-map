# Seguridad de siege-map

siege-map lee logs que **escribe el atacante** y los enseña en una web publica. Este documento es el modelo de amenazas de la propia herramienta: que entradas no son de fiar, que se protege y como.

Para avisar de una vulnerabilidad: ver `/.well-known/security.txt` en el despliegue, o abre un issue privado en el repositorio.

## Que no es de fiar

| Entrada | Quien la controla | Donde entra |
|---|---|---|
| Usuario SSH, banner del cliente, oferta KEX | el atacante | `parser.py` |
| Ruta, query, user-agent, referer, idioma | el atacante (y visitantes) | `nginx_parser.py` |
| Parametros de la API y del WebSocket | cualquiera en internet | `main.py` |
| Respuestas de ip-api, AbuseIPDB, GreyNoise | un tercero | `geo.py`, `threat_intel.py`, `intel.py` |

## Que se protege

1. A las personas que visitan las webs monitorizadas (sus IPs).
2. Al dueño del servidor (su IP, sus cuentas, sus logins).
3. Las claves y cuotas de APIs externas.
4. La disponibilidad del sensor (256 MB de memoria, un proceso).
5. A quien abre un export (CSV, informe) en su equipo.

## Amenazas y controles

### Inyeccion en la interfaz (XSS)
- El frontend es React y no usa `dangerouslySetInnerHTML` ni `innerHTML`: todo texto del atacante se pinta como texto.
- `parser._clean` sustituye los caracteres no imprimibles y acota la longitud antes de guardar (test: `test_control_characters_are_neutralised`).
- **CSP estricta** en `frontend/nginx.conf` (`script-src 'self'`, sin `unsafe-inline`). Probada con Chrome sin cabeza sobre el build de produccion: cero violaciones en globo, mapa, panel INTEL y dossier.

### Inyeccion en los exports
- **CSV**: se genera con el modulo `csv` (comillas y comas correctas) y toda celda que empieza por `=`, `+`, `-` o `@` se prefija con `'` para que Excel no la ejecute como formula. Un usuario SSH puede ser `=cmd|'/c calc'!A1` (test: `test_csv_neutralises_formulas_and_keeps_its_columns`).
- **Informe Markdown**: el texto del atacante va en bloques de codigo con `|`, `` ` `` y `<` escapados (test: `test_markdown_report_escapes_attacker_text`).
- **STIX**: los patrones se construyen solo a partir de direcciones validadas; las IPs truncadas se emiten como subred (`ISSUBSET '/24'`).
- **Blocklist**: solo se emite lo que `ipaddress` acepta como direccion.

### Abuso de la API publica
- `/api/attacker/{ip}` acepta unicamente una IP valida (o la forma truncada `a.b.c.xxx`); cualquier otra cosa devuelve 400. El valor acaba en consultas SQL parametrizadas y en la URL de una API externa.
- **GreyNoise solo se consulta para IPs que el sensor ha visto de verdad.** Sin esto, cualquiera podia agotar la cuota diaria pidiendo perfiles de IPs inventadas (test: `test_unknown_address_never_reaches_the_external_api`).
- Todos los parametros tienen rango o patron (`Query(..., ge=, le=, pattern=)`).
- nginx limita a 5 peticiones/s por IP en `/api` y 5 conexiones WebSocket por IP.
- El backend no publica puertos: solo le habla el nginx del frontend.

### Agotamiento de memoria
- El store de eventos es una cola acotada (`MAX_EVENTS`) con indice por IP que se vacia a la vez.
- Todas las caches cuya clave controla un atacante son `TTLCache` con tamaño maximo (`cache.py`): perfiles, AbuseIPDB, GreyNoise. Antes eran diccionarios que crecian mientras el proceso viviera.
- Cada cliente WebSocket tiene una cola de 50 mensajes; si no lee, se descartan.

### Privacidad
- Las IPs de HTTP se truncan a /24 (IPv4) o /48 (IPv6) **antes** de guardarse: la IP completa de un visitante no llega a disco, API, WebSocket ni exports.
- Un **login aceptado nunca es un evento**: no se guarda ni se muestra, porque normalmente es el dueño. Solo genera alerta si esa IP venia fallando logins, y el nombre de la cuenta va unicamente al webhook del operador, no al registro publico (test: `test_accepted_login_after_failures_is_critical`).
- `IGNORE_IPS` excluye las IPs propias de todo el pipeline.
- Las URLs de webhook y el token de Telegram nunca se escriben en los logs.

### Despliegue
- Contenedores sin root, sin capabilities, sistema de ficheros de solo lectura, limites de memoria y de procesos.
- Los logs del host se montan en solo lectura.
- Sin CORS: la API solo se usa desde el mismo origen.

## Limites conocidos

- **La API no tiene autenticacion.** Es publica por diseño (es un escaparate). No expongas datos que no quieras publicos y deja `MASK_HTTP_IPS=true`.
- **`exploit_2xx` puede dar falsos positivos** si una web monitorizada responde 200 a cualquier ruta (SPA con catch-all). La alerta lo avisa y se desactiva con `ALERT_EXPLOIT_2XX=false`.
- **La blocklist es una sugerencia.** Revisa antes de aplicarla automaticamente: una IP de salida compartida (CGNAT, VPN) puede bloquear a usuarios legitimos.
- **Clasificar no es atribuir.** Las campañas llevan un nivel de confianza precisamente porque compartir wordlist no demuestra un mismo operador.
- Las reglas Sigma se validan en sintaxis (`sigma check`), no contra un SIEM real.
- No hay auditoria externa: este documento describe lo revisado por el autor.
