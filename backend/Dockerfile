# Base: Python oficial "slim" (pequeña), versión fijada
FROM python:3.12-slim

# Python sin archivos .pyc y con logs al instante
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Dependencias PRIMERO (capa cacheada si no cambian)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Solo el código (nada de .env, venv, .git).
# Se copia como root → el usuario app solo puede LEERLO, no modificarlo.
COPY app/ ./app/

# Usuario sin privilegios, UID fijo, sin home ni shell
RUN useradd --system --no-create-home --uid 10001 --shell /usr/sbin/nologin app
USER app

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
