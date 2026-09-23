# --- Build stage -----------------------------------------------------------
FROM node:22-alpine AS build

WORKDIR /srv

# Install dependencies first (cached layer)
COPY package.json package-lock.json ./
RUN npm ci

# Build-time (non-secret) API base URL. Empty = same-origin relative paths,
# which is what the nginx config below proxies to the api service.
ARG VITE_API_URL=""
ENV VITE_API_URL=$VITE_API_URL

COPY . .
RUN npm run build

# --- Serve stage -----------------------------------------------------------
FROM nginx:1.27-alpine

COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /srv/dist /usr/share/nginx/html

EXPOSE 80

# Container-level healthcheck (compose also defines one).
HEALTHCHECK --interval=10s --timeout=3s --retries=5 \
  CMD wget -qO- http://127.0.0.1/healthz >/dev/null || exit 1
