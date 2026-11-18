# syntax=docker/dockerfile:1

# ── ETAPA 1: build ───────────────────────────────────────────
# pip solo vive aquí. Base oficial fijada por versión + DIGEST (OWASP #13):
# la etiqueta se mueve, el digest no. Para actualizarlo:
#   docker pull python:3.12-slim
#   docker inspect --format '{{index .RepoDigests 0}}' python:3.12-slim
FROM python:3.12-slim@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b AS build
ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /build

# venv en ruta fija → se copia entero a la etapa final
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Dependencias PRIMERO (capa cacheada si no cambian)
COPY requirements.txt .
# pip uninstall: el venv no lleva pip (el del sistema se quita en la etapa final)
RUN pip install -r requirements.txt \
 && pip uninstall -y pip

# ── ETAPA 2: imagen final ────────────────────────────────────
# MISMA base que la etapa 1 (el venv depende de la versión exacta de Python)
FROM python:3.12-slim@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b

LABEL org.opencontainers.image.title="siege-map-backend" \
      org.opencontainers.image.source="https://github.com/jorgearma/siege-map"

# pip del SISTEMA: la imagen base trae /usr/local/bin/pip aparte del del venv.
# Sin quitarlo, un atacante podría instalar paquetes en /data (pip install --target).
# Antes del ENV PATH (si no, "python" sería el del venv) y del USER (necesita root).
RUN /usr/local/bin/python -m pip uninstall -y pip

# Python sin archivos .pyc (FS read-only) y con logs al instante
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/venv/bin:$PATH"

# Usuario y grupo sin privilegios, UID fijo, sin home ni shell
RUN groupadd -r -g 10001 app \
 && useradd -r -u 10001 -g app -s /usr/sbin/nologin -M app

# Todo se copia como root → el usuario app solo puede LEER su código y sus librerías
COPY --from=build /opt/venv /opt/venv
WORKDIR /app
COPY app/ ./app/

# /data: único sitio donde el contenedor puede escribir (SQLite). Un volumen
# con nombre hereda este dueño la primera vez que se crea, así que el
# usuario app puede escribir sin ser root ni tocar permisos en el host.
RUN mkdir -p /data /geoip && chown app:app /data

# SUID/SGID (su, passwd, mount, chage...) vienen de Debian y la app no los usa.
# no-new-privileges del compose ya los anula; quitarlos aquí no deja todo en esa sola línea.
RUN find / -xdev -perm /6000 -type f -exec chmod a-s {} + 2>/dev/null || true
VOLUME /data
USER 10001

EXPOSE 8000

# uvicorn: FastAPI es ASGI (gunicorn sync no sirve).
# 1 worker: eventos, WebSockets y tail de logs viven en memoria del proceso.
# --forwarded-allow-ips=*: fiarse de X-Forwarded-* de nginx (otro contenedor, no 127.0.0.1).
#   Seguro SOLO porque el backend no tiene puerto publicado: solo nginx puede hablarle.
# --no-access-log + --log-level warning: nginx ya registra cada visita; uvicorn no
#   duplica IPs de visitantes (el access log no cubre las conexiones WebSocket, el
#   log-level sí). Afecta solo a los loggers de uvicorn: los de la app siguen en INFO.
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1", \
     "--proxy-headers", "--forwarded-allow-ips=*", "--no-access-log", "--log-level", "warning"]
