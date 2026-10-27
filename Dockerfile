# Multi-stage Dockerfile for CrowdNinja (Cloud-Native CrowdSec Security Operations)

# Stage 0: Official CrowdSec CLI & default config templates
FROM docker.io/crowdsecurity/crowdsec:v1.8.1 AS crowdsec-cli

# Stage 1: Build frontend
FROM node:20-alpine AS frontend-builder

WORKDIR /app/web

COPY web/package*.json ./
RUN npm ci --legacy-peer-deps

COPY web/ ./
RUN npm run build

# Stage 2: Build Go backend
FROM golang:1.23-alpine AS backend-builder

WORKDIR /app

RUN apk add --no-cache git gcc musl-dev sqlite-dev

COPY go.mod go.sum ./
RUN go mod download

COPY cmd/ cmd/
COPY internal/ internal/

RUN CGO_ENABLED=1 GOOS=linux go build -o crowdsec-manager ./cmd/server

# Stage 3: Final runtime image (Alpine + embedded cscli for Cloud-Native K8s/LAPI mode)
FROM alpine:latest

RUN apk --no-cache add ca-certificates tzdata curl

WORKDIR /app

# Copy embedded cscli and default /etc/crowdsec templates for Cloud-Native mode
COPY --from=crowdsec-cli /usr/local/bin/cscli /usr/local/bin/cscli
COPY --from=crowdsec-cli /etc/crowdsec /etc/crowdsec

# Copy CrowdNinja backend binary, entrypoint, and frontend assets
COPY --from=backend-builder /app/crowdsec-manager .
COPY --from=frontend-builder /app/web/dist ./web/dist
COPY docker-entrypoint.sh /app/docker-entrypoint.sh

RUN chmod +x /app/docker-entrypoint.sh /app/crowdsec-manager && \
    mkdir -p /app/backups /app/logs /app/config /app/data /app/geoip \
             /var/lib/crowdsec/data /etc/crowdsec/hub /etc/crowdsec/parsers/s02-enrich \
             /etc/crowdsec/scenarios /etc/crowdsec/postoverflows /etc/crowdsec/notifications

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:${PORT:-8080}/health || exit 1

ENTRYPOINT ["/app/docker-entrypoint.sh"]
CMD ["./crowdsec-manager"]
