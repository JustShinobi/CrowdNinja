#!/bin/sh
set -e

mkdir -p /app/backups /app/logs /app/config /app/data /app/geoip \
         /var/lib/crowdsec/data /etc/crowdsec/hub /etc/crowdsec/parsers/s02-enrich \
         /etc/crowdsec/scenarios /etc/crowdsec/postoverflows /etc/crowdsec/notifications

# Seed default CrowdSec templates from /staging/etc/crowdsec when present in the base image
if [ -d /staging/etc/crowdsec ]; then
  cp -rn /staging/etc/crowdsec/* /etc/crowdsec/ 2>/dev/null || true
fi

touch /var/lib/crowdsec/data/online_api_credentials.yaml

# Bootstrap Cloud-Native CrowdSec configuration when database/LAPI environment variables are provided
DB_HOST_VAL="${CROWDSEC_DB_HOST:-${DB_HOST:-}}"
DB_PORT_VAL="${CROWDSEC_DB_PORT:-${DB_PORT:-5432}}"
DB_USER_VAL="${CROWDSEC_DB_USER:-${DB_USER:-crowdsec_user}}"
DB_PASS_VAL="${CROWDSEC_DB_PASSWORD:-${DB_PASSWORD:-}}"
DB_NAME_VAL="${CROWDSEC_DB_NAME:-${DB_NAME:-crowdsec}}"
LAPI_URL_VAL="${CROWDSEC_LAPI_URL:-http://localhost:8080}"
MACHINE_ID_VAL="${CROWDNINJA_MACHINE_ID:-crowdninja}"

if [ -n "$DB_HOST_VAL" ] && [ -n "$DB_PASS_VAL" ]; then
  echo "[CrowdNinja] Configuring Cloud-Native PostgreSQL connection ($DB_HOST_VAL:$DB_PORT_VAL/$DB_NAME_VAL)..."
  cat > /etc/crowdsec/config.yaml.local <<EOF
db_config:
  log_level: info
  type: postgresql
  user: ${DB_USER_VAL}
  password: "${DB_PASS_VAL}"
  db_name: ${DB_NAME_VAL}
  host: ${DB_HOST_VAL}
  port: ${DB_PORT_VAL}
  sslmode: disable
api:
  client:
    credentials_path: /etc/crowdsec/local_api_credentials.yaml
  server:
    online_client:
      credentials_path: /var/lib/crowdsec/data/online_api_credentials.yaml
EOF

  if command -v cscli >/dev/null 2>&1; then
    echo "[CrowdNinja] Self-registering machine '${MACHINE_ID_VAL}' against LAPI (${LAPI_URL_VAL})..."
    cscli machines add "${MACHINE_ID_VAL}" --auto -f /etc/crowdsec/local_api_credentials.yaml --url "${LAPI_URL_VAL}" --force >/dev/null 2>&1 || true
  fi
elif [ -n "${CROWDSEC_LAPI_USER:-}" ] && [ -n "${CROWDSEC_LAPI_PASSWORD:-}" ]; then
  cat > /etc/crowdsec/local_api_credentials.yaml <<EOF
url: ${LAPI_URL_VAL}
login: ${CROWDSEC_LAPI_USER}
password: ${CROWDSEC_LAPI_PASSWORD}
EOF
fi

if [ ! -f /etc/crowdsec/simulation.yaml ]; then
  printf "simulation: false\n" > /etc/crowdsec/simulation.yaml
fi

if [ ! -f /etc/crowdsec/parsers/s02-enrich/mywhitelists.yaml ]; then
  cat > /etc/crowdsec/parsers/s02-enrich/mywhitelists.yaml <<'EOF'
name: crowdsecurity/whitelists
description: "Whitelist events from trusted IPs"
whitelist:
  reason: "Trusted IP/CIDR managed by CrowdNinja"
  ip: []
  cidr: []
EOF
fi

if command -v cscli >/dev/null 2>&1 && [ ! -s /etc/crowdsec/hub/.index.json ]; then
  echo "[CrowdNinja] Initializing CrowdSec Hub index..."
  cscli hub update >/dev/null 2>&1 || true
  if [ -n "${COLLECTIONS:-}" ]; then
    # shellcheck disable=SC2086
    cscli collections install $COLLECTIONS >/dev/null 2>&1 || true
  fi
fi

exec "$@"
