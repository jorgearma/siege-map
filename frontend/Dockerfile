# syntax=docker/dockerfile:1

# ── ETAPA 1: build ───────────────────────────────────────────
# Node, npm y node_modules SOLO existen aquí; no llegan a la imagen final.
# Base fijada por versión + DIGEST (OWASP #13). Node 22 (LTS); el 20 ya no recibe parches.
# Para actualizar: docker pull node:22-alpine
#                  docker inspect --format '{{index .RepoDigests 0}}' node:22-alpine
FROM node:22-alpine@sha256:1314fb30ec37592d5845e5a160d522c0e680972aa534549940b8d73bde88481a AS build
WORKDIR /app

# Primero solo los manifiestos → la capa de dependencias se cachea
COPY package.json package-lock.json ./
# npm ci: instala EXACTAMENTE lo del lockfile (reproducible, falla si no cuadra)
# --ignore-scripts: los paquetes no ejecutan scripts al instalarse (vector de supply chain)
RUN npm ci --ignore-scripts

# Solo lo que el build necesita (nunca "COPY . .")
COPY index.html vite.config.js ./
COPY src ./src

# Map tiles key: Vite embeds VITE_* variables into the JS during the build.
# Public by design (it ends up in the browser) — restrict it to your domain in CARTO.
# Only in this stage: the final image does not keep the ARG/ENV.
ARG VITE_CARTO_KEY=""
ENV VITE_CARTO_KEY=$VITE_CARTO_KEY
RUN npm run build

# ── ETAPA 2: imagen final ────────────────────────────────────
# nginx WITHOUT root (official image, uid 101). Port 3000 > 1024 → no privileges needed.
# Para actualizar: docker pull nginxinc/nginx-unprivileged:1.30-alpine (+ docker inspect como arriba)
FROM nginxinc/nginx-unprivileged:1.30-alpine@sha256:f5116ed4606f3eb015dd4a8e28cb9b351476dc0ad4bc6e9f93b19cec130cdf03

# Pasos que necesitan root → solo aquí (uid numérico: hadolint DL3066)
USER 0

# apk upgrade → parches de seguridad publicados después de la imagen base
# apk del curl → nginx no lo usa (el healthcheck usa wget de busybox)
# rm nc        → sin netcat no hay reverse shell fácil con "nc -e"
# hadolint ignore=DL3018
RUN apk upgrade --no-cache \
 && apk del --no-cache curl \
 && rm -f /usr/bin/nc

# Custom nginx config for SPA + proxy. La imagen base deja /etc/nginx con dueño 101:
# se devuelve a root para que nginx no pueda reescribir su propia config
# (segunda capa por si algún día se quita read_only en el compose).
COPY nginx.conf /etc/nginx/conf.d/default.conf
RUN chown -R root:root /etc/nginx \
 && chmod -R go-w /etc/nginx

# Solo el resultado del build, de root → nginx lo lee pero no lo modifica
WORKDIR /usr/share/nginx/html
RUN rm -rf ./*
COPY --from=build --chown=root:root /app/dist ./

USER 101
EXPOSE 3000

# Healthcheck: en docker-compose.yml (wget a 127.0.0.1:3000/), igual que el del backend

CMD ["nginx", "-g", "daemon off;"]
