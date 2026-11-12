# syntax=docker/dockerfile:1

# ---- Build: compile the dashboard to static files ----
FROM node:26-alpine AS build
WORKDIR /app
# Install exactly what package-lock.json pins; lifecycle scripts are not needed for the build.
COPY package.json package-lock.json ./
RUN npm ci --ignore-scripts
COPY . .
RUN npm run build

# ---- Serve: static files + reverse proxy to the API, as a non-root user ----
FROM nginxinc/nginx-unprivileged:1.29-alpine
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/dist /usr/share/nginx/html
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s --retries=3 CMD wget -q -O /dev/null http://127.0.0.1:8080/nginx-health || exit 1
