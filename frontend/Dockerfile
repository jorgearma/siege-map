FROM node:20-alpine AS build

WORKDIR /app

COPY package.json ./
RUN npm install

COPY . .
# Map tiles key: Vite embeds VITE_* variables into the JS during the build
ARG VITE_CARTO_KEY=""
ENV VITE_CARTO_KEY=$VITE_CARTO_KEY
RUN npm run build

# Production: serve with nginx WITHOUT root (official image, runs as uid 101).
# Port 3000 > 1024 → no privileges needed to bind it.
FROM nginxinc/nginx-unprivileged:1.27-alpine

# Custom nginx config for SPA + proxy
COPY --from=build /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 3000

CMD ["nginx", "-g", "daemon off;"]
