#!/bin/sh
# Reads secrets back out of Vault and writes infra/.env for docker-compose
# to pick up via ${VAR} interpolation. Run AFTER vault is seeded
# (infra/vault/init.sh) and BEFORE starting postgres/grafana/keycloak/rabbitmq.
#
# No `vault` CLI dependency on the host — talks to Vault's HTTP API directly.
set -e

VAULT_ADDR="${VAULT_ADDR:-http://localhost:8200}"
VAULT_TOKEN="${VAULT_TOKEN:-agentlens-dev-token}"

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
ENV_FILE="$SCRIPT_DIR/../.env"

field() {
  path="$1"; key="$2"
  curl -sf -H "X-Vault-Token: $VAULT_TOKEN" "$VAULT_ADDR/v1/agentlens/data/$path" \
    | python3 -c "import json,sys; print(json.load(sys.stdin)['data']['data']['$key'])"
}

cat > "$ENV_FILE" <<EOF
POSTGRES_PASSWORD=$(field postgres password)
KC_DB_PASSWORD=$(field postgres password)
GF_ADMIN_PASSWORD=$(field grafana admin_password)
KEYCLOAK_ADMIN_PASSWORD=$(field keycloak admin_password)
RABBITMQ_DEFAULT_PASS=$(field rabbitmq password)
EOF

chmod 600 "$ENV_FILE"
echo "Wrote $ENV_FILE from Vault secrets (source of truth: agentlens/* in Vault)."
