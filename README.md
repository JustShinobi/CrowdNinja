# 🥷 CrowdNinja

**A self-hosted, cloud-native control plane for CrowdSec — built for Kubernetes, K3s, and Docker.**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Go](https://img.shields.io/badge/Backend-Go%201.23-00ADD8?logo=go)](https://go.dev/)
[![React](https://img.shields.io/badge/Frontend-React%20%2B%20ShadcnUI-61DAFB?logo=react)](https://ui.shadcn.com/)
[![Runtime](https://img.shields.io/badge/Runtime-Kubernetes%20%7C%20K3s%20%7C%20Docker-326ce5?logo=kubernetes)](https://github.com/JustShinobi/CrowdNinja)

---

## Why I Built This

If you run **CrowdSec** in your homelab or production cluster, you quickly hit a wall with the official SaaS console: the free tier is heavily restricted, retention is short, and basic operational actions quickly bump into paywalls.

When looking at self-hosted alternatives in the community, I found myself having to choose between trade-offs:
* Some dashboards had great LAPI search and Prometheus metrics, but couldn't manage **Hub collections, scenarios, bouncers, or allowlists**.
* Other tools had awesome **ShadcnUI** management screens, but were hardwired to `/var/run/docker.sock` (`docker exec crowdsec cscli ...`), making them impossible to run cleanly on **Kubernetes / K3s** where `containerd` is the runtime and CrowdSec is split between a `LAPI` Deployment and a `DaemonSet` of agents.
* Mini-SIEM tools had really smart ideas like **persistent ASN bans** (banning hostile Autonomous Systems automatically with CIDR exceptions), but required adopting a whole separate stack.

**CrowdNinja** is my attempt to bring the best of those worlds together into a single, fast Go + React application that works out of the box on **Kubernetes (K3s/K8s)**, **Proxmox LXC / Bare-Metal**, and **Docker Compose** — without requiring a Docker socket.

---

## What It Does

* **Zero Docker Socket Required (`RUNTIME_MODE=kubernetes|lapi`):**
  Runs `cscli` natively inside the container against your shared CrowdSec database (PostgreSQL / MySQL / SQLite) and LAPI endpoint, while keeping legacy `docker` mode available if you still use Docker Compose.
* **Full Hub, Scenario, Bouncer & Allowlist Management:**
  Browse, install, upgrade, and remove CrowdSec Hub collections, parsers, scenarios, postoverflows, and AppSec WAF rules directly from the UI. Manage bouncers, whitelists, and `profiles.yaml` without touching the terminal.
* **Boolean Structured Search (`?q=`):**
  Filter decisions and alerts using structured expressions like:
  * `ip:198.51.100.42 AND -origin:CAPI`
  * `country:CN OR country:RU`
  * `scenario:"http-probing" AND asn:AS4134`
* **Persistent ASN Response Engine:**
  Getting hammered by a rogue hosting ASN? Mark an ASN once (e.g., `AS14061`) to automatically ban newly observed IPs from that network for a configurable duration (`168h` by default), with **IP/CIDR exception lists** and **Dry-Run simulation mode**.
* **Pluggable Observability (Prometheus, VictoriaMetrics, Loki, VictoriaLogs):**
  Query runtime `cs_*` metrics directly from **Prometheus** or **VictoriaMetrics**, and stream or correlate container and Traefik/Ingress access logs from **VictoriaLogs (LogsQL)**, **Grafana Loki (LogQL)**, or local files.
* **Multi-LAPI & SSO Ready:**
  Switch between multiple CrowdSec LAPI instances from the top bar, and protect the UI with **OIDC (Authorization Code + PKCE)** or **Reverse-Proxy Trusted Headers** (Authelia, Authentik, Keycloak, PocketID).

---

## How It Fits Together

```text
                       ┌──────────────────────────────────────┐
                       │         CrowdNinja Web UI            │
                       │   (React 18 + TypeScript + ShadcnUI) │
                       └──────────────────┬───────────────────┘
                                          │ REST / SSE / WebSocket
                       ┌──────────────────▼───────────────────┐
                       │       CrowdNinja Go Backend          │
                       │  • Boolean Structured Search         │
                       │  • Persistent ASN Response Engine    │
                       │  • OIDC (PKCE) & Trusted Header SSO  │
                       │  • Multi-LAPI Instance Router        │
                       └────┬──────────────┬──────────────┬───┘
                            │              │              │
         ┌──────────────────┘              │              └──────────────────┐
         ▼                                 ▼                                 ▼
┌─────────────────────┐         ┌─────────────────────┐         ┌─────────────────────┐
│   RUNTIME_MODE      │         │  METRICS_PROVIDER   │         │    LOGS_PROVIDER    │
├─────────────────────┤         ├─────────────────────┤         ├─────────────────────┤
│ • kubernetes (K3s)  │         │ • PromQL API        │         │ • VictoriaLogs      │
│ • lapi (CloudNative)│         │   (Prometheus /     │         │   (LogsQL HTTP API) │
│ • docker (Socket)   │         │    VictoriaMetrics) │         │ • Grafana Loki      │
│                     │         │ • Direct (:6060)    │         │   (LogQL HTTP API)  │
│                     │         │                     │         │ • Local File        │
└─────────────────────┘         └─────────────────────┘         └─────────────────────┘
```

---

## Quick Start

### 1. Kubernetes / K3s (Cloud-Native Mode)

When running on Kubernetes or K3s alongside a CrowdSec LAPI backed by PostgreSQL, CrowdNinja automatically configures `/etc/crowdsec/config.yaml.local`, self-registers its machine credentials against the LAPI, and initializes the Hub index on startup:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: crowdninja
  namespace: crowdsec
spec:
  replicas: 1
  strategy:
    type: Recreate
  selector:
    matchLabels:
      app.kubernetes.io/name: crowdninja
  template:
    metadata:
      labels:
        app.kubernetes.io/name: crowdninja
    spec:
      containers:
        - name: crowdninja
          image: ghcr.io/justshinobi/crowdninja:latest
          ports:
            - containerPort: 8080
          env:
            - name: PORT
              value: "8080"
            - name: RUNTIME_MODE
              value: "kubernetes"
            - name: DB_HOST
              value: "postgres-rw.database.svc.cluster.local"
            - name: DB_PORT
              value: "5432"
            - name: DB_USER
              value: "crowdsec_user"
            - name: DB_PASSWORD
              valueFrom:
                secretKeyRef:
                  name: crowdsec-credentials
                  key: DB_PASSWORD
            - name: DB_NAME
              value: "crowdsec"
            - name: CROWDSEC_LAPI_URL
              value: "http://crowdsec-service:8080"
            - name: CROWDSEC_METRICS_URL
              value: "http://crowdsec-service:6060/metrics"
            - name: PROMETHEUS_URL
              value: "http://victoriametrics:9090"
            - name: LOGS_PROVIDER
              value: "victorialogs"
            - name: VICTORIALOGS_URL
              value: "http://victorialogs:3100"
```

### 2. Docker Compose

```yaml
services:
  crowdninja:
    image: ghcr.io/justshinobi/crowdninja:latest
    container_name: crowdninja
    restart: unless-stopped
    ports:
      - "8080:8080"
    environment:
      - PORT=8080
      - RUNTIME_MODE=auto
      - CROWDSEC_LAPI_URL=http://crowdsec:8080
      - CROWDSEC_METRICS_URL=http://crowdsec:6060/metrics
    volumes:
      - ./config:/app/config
      - ./data:/app/data
      - ./logs:/app/logs
```

---

## Configuration Reference

| Variable | Default | Description |
| :--- | :--- | :--- |
| `PORT` | `8080` | HTTP server listen port |
| `RUNTIME_MODE` | `auto` | `auto`, `kubernetes`, `lapi`, or `docker` |
| `CROWDSEC_LAPI_URL` | `http://localhost:8080` | CrowdSec Local API URL |
| `DB_HOST` / `DB_PORT` | *(empty)* / `5432` | Optional PostgreSQL host/port for automatic Cloud-Native `cscli` bootstrap |
| `DB_USER` / `DB_PASSWORD` / `DB_NAME` | `crowdsec_user` / `crowdsec` | PostgreSQL credentials for shared CrowdSec database |
| `COLLECTIONS` | *(empty)* | Space-separated Hub collections to auto-install on startup |
| `CROWDSEC_METRICS_URL` | `http://localhost:6060/metrics` | Direct Prometheus metrics endpoint on CrowdSec |
| `PROMETHEUS_URL` | *(empty)* | Prometheus or VictoriaMetrics base URL for `/api/crowdsec/promql` |
| `LOGS_PROVIDER` | `file` | `file`, `victorialogs`, or `loki` |
| `VICTORIALOGS_URL` | *(empty)* | Base URL for VictoriaLogs (`http://victorialogs:3100`) |
| `LOKI_URL` | *(empty)* | Base URL for Grafana Loki (`http://loki:3100`) |
| `LAPI_INSTANCES` | *(empty)* | Comma-separated Multi-LAPI instances (`id=http://host:8080[|/path/config.yaml],...`) |
| `AUTH_ENABLED` | `false` | Enforce authentication on API/UI routes (`true` / `false`) |
| `AUTH_MODE` | `auto` | `oidc` (OAuth2/OIDC + PKCE) or `trusted-header` (Authelia/Authentik ForwardAuth) |
| `OIDC_ISSUER_URL` | *(empty)* | OIDC Discovery Issuer URL (`https://auth.example.com`) |
| `OIDC_CLIENT_ID` / `OIDC_CLIENT_SECRET` | *(empty)* | OIDC Client credentials |
| `OIDC_ALLOWED_GROUPS` | *(empty)* | Optional comma-separated list of authorized OIDC/SSO groups (`admins,secops`) |
| `AUTH_TRUSTED_HEADER_ENABLED` | `false` | Read operator identity from reverse-proxy headers (`Remote-User`, `Remote-Groups`) |
| `GEOIP_DB_PATH` | `/app/geoip/GeoLite2-City.mmdb` | Optional MaxMind GeoLite2 City database path |

---

## License

Released under the [MIT License](LICENSE).
