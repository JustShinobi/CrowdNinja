<div align="center">
  <h1>🥷 CrowdNinja</h1>
  <p><strong>Cloud-Native Security Operations Center, LAPI Dashboard, Hub & Bouncer Manager for CrowdSec</strong></p>

  [![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
  [![Runtime: Kubernetes / K3s / Docker](https://img.shields.io/badge/Runtime-Kubernetes%20%7C%20K3s%20%7C%20Docker-326ce5)](https://github.com/JustShinobi/CrowdNinja)
  [![Observability: Prometheus / VictoriaMetrics / Loki / VictoriaLogs](https://img.shields.io/badge/Observability-Prometheus%20%7C%20VictoriaMetrics%20%7C%20Loki%20%7C%20VictoriaLogs-e6522c)](https://github.com/JustShinobi/CrowdNinja)
</div>

---

**CrowdNinja** is a lightweight, self-hosted, open-source web interface and Security Operations Center (SOC) for **CrowdSec**.

Built with **Go** and **React + TypeScript + ShadcnUI**, CrowdNinja unifies the best capabilities of the open-source CrowdSec ecosystem into a single ~45 MB binary/container that runs natively on **Kubernetes (K3s/K8s)**, **Proxmox LXC / Bare-Metal**, and **Docker Compose** — with **zero dependency on `/var/run/docker.sock`** when running in Cloud-Native mode.

---

## ✨ Key Features

| Domain | Capabilities |
| :--- | :--- |
| **Cloud-Native Runtime (`RUNTIME_MODE`)** | Pluggable runtime drivers: **`lapi`** (direct LAPI + local `cscli` + shared DB/filesystem), **`kubernetes`** (K8s/K3s native), and **`docker`** (legacy Docker socket compatibility). Auto-detects environment at startup. |
| **Decisions & Alerts Explorer** | Real-time active & expired ban management, manual IP/CIDR bans with custom durations/reasons, bulk import/delete, and **Durable Deletion Tombstones** so deleted alerts never reappear during background sync. |
| **Boolean Structured Search** | Query Decisions and Alerts using structured expressions (`ip:198.51.100.42 AND -origin:CAPI`, `country:CN OR country:RU`, `scenario:"http-probing" AND NOT scope:Range`). |
| **Persistent ASN Response Engine** | Mark an entire Autonomous System (`AS14061`, etc.) once to automatically ban newly observed IPs from that ASN for a configurable duration (default `168h`), complete with **ASN-specific IP/CIDR exceptions** and **Dry-Run Simulation mode**. |
| **Graphical Hub, Scenarios & Bouncers** | Browse, install, upgrade, and remove CrowdSec Hub **Collections, Parsers, Scenarios, Postoverflows, and AppSec WAF rules**; manage **Bouncers, Allowlists, Whitelists, and Profiles** from the UI. |
| **Pluggable Observability (`METRICS` & `LOGS`)** | Native integration with **Prometheus / VictoriaMetrics** (`/api/crowdsec/promql`) for LAPI latency, Bouncer polling, and parser metrics, plus **VictoriaLogs (LogsQL)** and **Grafana Loki (LogQL)** for Traefik/Ingress log correlation. |

---

## 🏗️ Pluggable Architecture

CrowdNinja is designed from the ground up to fit any self-hosted or production environment without vendor or runtime lock-in:

```text
                       ┌──────────────────────────────────────┐
                       │         CrowdNinja Web UI            │
                       │   (React 18 + TypeScript + ShadcnUI) │
                       └──────────────────┬───────────────────┘
                                          │ REST / SSE / WebSocket
                       ┌──────────────────▼───────────────────┐
                       │       CrowdNinja Go Backend          │
                       │  • Structured Search Engine          │
                       │  • Persistent ASN Response Engine    │
                       │  • Durable Deletion Tombstones       │
                       └────┬──────────────┬──────────────┬───┘
                            │              │              │
         ┌──────────────────┘              │              └──────────────────┐
         ▼                                 ▼                                 ▼
┌─────────────────────┐         ┌─────────────────────┐         ┌─────────────────────┐
│   RUNTIME_MODE      │         │  METRICS_PROVIDER   │         │    LOGS_PROVIDER    │
├─────────────────────┤         ├─────────────────────┤         ├─────────────────────┤
│ • lapi (CloudNative)│         │ • PromQL API        │         │ • VictoriaLogs      │
│ • kubernetes (K3s)  │         │   (Prometheus /     │         │   (LogsQL HTTP API) │
│ • docker (Socket)   │         │    VictoriaMetrics) │         │ • Grafana Loki      │
│                     │         │ • Direct (:6060)    │         │   (LogQL HTTP API)  │
│                     │         │                     │         │ • Local File        │
└─────────────────────┘         └─────────────────────┘         └─────────────────────┘
```

---

## 🚀 Quick Start

### Option 1: Kubernetes / K3s (Cloud-Native Mode — No Docker Socket)

In Kubernetes or K3s, CrowdNinja runs without `/var/run/docker.sock` by setting `RUNTIME_MODE=kubernetes` (or leaving `RUNTIME_MODE=auto`, which automatically detects `KUBERNETES_SERVICE_HOST`):

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

### Option 2: Docker Compose (Standalone or Full Stack)

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

## ⚙️ Environment Variables Reference

| Variable | Default | Description |
| :--- | :--- | :--- |
| `PORT` | `8080` | HTTP server listen port |
| `RUNTIME_MODE` | `auto` | `auto`, `lapi`, `kubernetes`, or `docker` |
| `CROWDSEC_LAPI_URL` | `http://localhost:8080` | CrowdSec Local API URL |
| `CROWDSEC_CONFIG_FILE` | `/etc/crowdsec/config.yaml` | Path to CrowdSec configuration for local `cscli` operations |
| `CROWDSEC_CSCLI_BIN` | `cscli` | Path or binary name for `cscli` |
| `CROWDSEC_METRICS_URL` | `http://localhost:6060/metrics` | Direct Prometheus metrics endpoint on CrowdSec |
| `PROMETHEUS_URL` | *(empty)* | Optional Prometheus or VictoriaMetrics base URL for `/api/crowdsec/promql` |
| `LOGS_PROVIDER` | `file` | `file`, `victorialogs`, or `loki` |
| `VICTORIALOGS_URL` | *(empty)* | Base URL for VictoriaLogs (`http://victorialogs:3100`) |
| `LOKI_URL` | *(empty)* | Base URL for Grafana Loki (`http://loki:3100`) |
| `LAPI_INSTANCES` | *(empty)* | Comma-separated Multi-LAPI instances (`id=http://host:8080[|/path/config.yaml],...`) |
| `AUTH_ENABLED` | `false` | Enable authentication middleware (`true` / `false`) |
| `AUTH_MODE` | `auto` | `oidc` (OAuth2/OIDC + PKCE) or `trusted-header` (Authelia/Authentik ForwardAuth) |
| `OIDC_ISSUER_URL` | *(empty)* | OIDC Discovery Issuer URL (`https://auth.example.com`) |
| `OIDC_CLIENT_ID` | *(empty)* | OIDC Client ID |
| `OIDC_CLIENT_SECRET` | *(empty)* | OIDC Client Secret |
| `OIDC_REDIRECT_URL` | *(auto)* | OIDC Callback URL (`https://crowdninja.example.com/api/auth/callback`) |
| `OIDC_ALLOWED_GROUPS` | *(empty)* | Optional comma-separated list of authorized OIDC/SSO groups (`admins,secops`) |
| `AUTH_TRUSTED_HEADER_ENABLED` | `false` | Accept identity from trusted reverse-proxy headers (`Remote-User`, `Remote-Groups`) |
| `GEOIP_DB_PATH` | `/app/geoip/GeoLite2-City.mmdb` | Optional MaxMind GeoLite2 City database path |

---

## 🔌 New REST API Endpoints in CrowdNinja

### Persistent ASN Response (`/api/asn`)
* `GET /api/asn/rules` — List all persistent ASN ban rules.
* `POST /api/asn/rules` — Create or update an ASN rule (`asn`, `as_name`, `action`, `duration`, `reason`, `dry_run`, `enabled`).
* `DELETE /api/asn/rules/:asn` — Remove a persistent ASN rule.
* `GET /api/asn/exceptions?asn=AS14061` — List IP/CIDR exceptions for an ASN.
* `POST /api/asn/exceptions` — Add an IP or CIDR subnet exception (`asn`, `ip_or_cidr`, `note`).
* `DELETE /api/asn/exceptions/:id` — Delete an exception by ID.
* `POST /api/asn/evaluate` — Evaluate an observed `{ "ip": "...", "asn": "..." }` against active ASN rules (respects CIDR exceptions and `dry_run` simulation mode).

### Structured Search & PromQL Metrics (`/api/crowdsec`)
* `GET /api/crowdsec/decisions/analysis?q=ip:198.51.100.0/24+AND+-origin:CAPI` — Filter decisions using boolean structured queries.
* `GET /api/crowdsec/alerts/analysis?q=country:CN+OR+asn:AS4134` — Filter alerts using boolean structured queries.
* `GET /api/crowdsec/promql?query=...` — Query runtime CrowdSec metrics (`cs_*`) from Prometheus or VictoriaMetrics.

### Multi-LAPI Instances & OIDC / SSO Authentication (`/api/hosts` & `/api/auth`)
* `GET /api/hosts/list` — List all configured LAPI instances / hosts and their real-time connectivity status.
* `POST /api/hosts/lapi` — Dynamically register or update a CrowdSec LAPI instance (`{ "id": "edge-dmz", "lapi_url": "http://10.20.10.10:8080", "config_file": "/etc/crowdsec/edge.yaml" }`).
* `DELETE /api/hosts/lapi/:id` — Remove a dynamically registered LAPI instance.
* `GET /api/auth/status` — Retrieve current authentication state and OIDC/SSO user profile (`sub`, `username`, `name`, `email`, `groups`, `provider`).
* `GET /api/auth/login` & `GET /api/auth/callback` — OIDC Authorization Code Flow with PKCE S256.
* `POST /api/auth/logout` — Clear session cookie.

---

## 📄 License

Released under the [MIT License](LICENSE).
