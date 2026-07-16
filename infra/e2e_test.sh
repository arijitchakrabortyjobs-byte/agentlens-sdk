#!/bin/bash
# AgentLens — End-to-End Infrastructure Test
# Tests every system in docker-compose.yml is wired correctly.
# Run AFTER: docker compose -f infra/docker-compose.yml up -d
#       AND: bash infra/localstack/bootstrap.sh
#       AND: bash infra/vault/init.sh

set -e
export AWS_ACCESS_KEY_ID="${AWS_ACCESS_KEY_ID:-test}"
export AWS_SECRET_ACCESS_KEY="${AWS_SECRET_ACCESS_KEY:-test}"
export AWS_DEFAULT_REGION="${AWS_DEFAULT_REGION:-ap-south-1}"
PASS=0; FAIL=0
GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; NC='\033[0m'

check() {
  local name="$1"; local cmd="$2"
  if eval "$cmd" &>/dev/null; then
    echo -e "${GREEN}✓${NC} $name"
    PASS=$((PASS+1))
  else
    echo -e "${RED}✗${NC} $name"
    FAIL=$((FAIL+1))
  fi
}

section() { echo -e "\n${YELLOW}── $1 ──${NC}"; }

echo "AgentLens E2E Infrastructure Test"
echo "=================================="

# ── 1. LocalStack (AWS emulation) ──────────────────────────────────────────
section "LocalStack — AWS services"
check "LocalStack health" \
  "curl -sf http://localhost:4566/_localstack/health | grep -q '\"s3\": \"running\"'"
check "S3 Object Lock bucket exists" \
  "aws --endpoint-url=http://localhost:4566 --region ap-south-1 s3api head-bucket --bucket agentlens-worm-audit"
check "KMS alias exists" \
  "aws --endpoint-url=http://localhost:4566 --region ap-south-1 kms list-aliases --query 'Aliases[?AliasName==\`alias/agentlens-worm\`]' --output text | grep -q agentlens"
check "Secrets Manager — postgres secret" \
  "aws --endpoint-url=http://localhost:4566 --region ap-south-1 secretsmanager get-secret-value --secret-id agentlens/dev/postgres"
check "SQS DLQ exists" \
  "aws --endpoint-url=http://localhost:4566 --region ap-south-1 sqs get-queue-url --queue-name agentlens-worm-dlq"

# ── 2. Vault ────────────────────────────────────────────────────────────────
section "HashiCorp Vault"
check "Vault sealed=false" \
  "curl -sf http://localhost:8200/v1/sys/health | grep -q '\"sealed\":false'"
check "Vault AWS secret readable" \
  "curl -sf -H 'X-Vault-Token: agentlens-dev-token' http://localhost:8200/v1/agentlens/data/aws | grep -q 'region'"

# ── 3. PostgreSQL ────────────────────────────────────────────────────────────
section "PostgreSQL"
check "Postgres accepting connections" \
  "pg_isready -h localhost -p 5432 -U agentlens -d agentlens_compliance"
check "sessions table exists" \
  "psql -h localhost -p 5432 -U agentlens -d agentlens_compliance -c '\dt sessions' 2>&1 | grep -q sessions"
check "responsibility_map table exists" \
  "psql -h localhost -p 5432 -U agentlens -d agentlens_compliance -c '\dt responsibility_map' 2>&1 | grep -q responsibility_map"

# ── 4. OTEL Collector ───────────────────────────────────────────────────────
section "OpenTelemetry Collector"
check "OTEL gRPC port open (4317)" \
  "nc -z localhost 4317"
check "OTEL HTTP port open (4318)" \
  "nc -z localhost 4318"
check "OTEL self-metrics reachable" \
  "curl -sf http://localhost:8888/metrics | grep -q otelcol"

# ── 5. Jaeger ────────────────────────────────────────────────────────────────
section "Jaeger"
check "Jaeger UI reachable" \
  "curl -sf http://localhost:16686/api/services | grep -q data"

# ── 6. Prometheus ────────────────────────────────────────────────────────────
section "Prometheus"
check "Prometheus API reachable" \
  "curl -sf http://localhost:9090/-/ready | grep -q Ready"
check "OTEL target being scraped" \
  "curl -sf 'http://localhost:9090/api/v1/targets' | grep -q otel"

# ── 7. Grafana ───────────────────────────────────────────────────────────────
section "Grafana"
check "Grafana health endpoint" \
  "curl -sf http://localhost:3000/api/health | grep -q ok"
check "Prometheus datasource configured" \
  "curl -su admin:agentlens_dev http://localhost:3000/api/datasources | grep -q prometheus"

# ── 8. Keycloak ──────────────────────────────────────────────────────────────
section "Keycloak"
check "Keycloak health" \
  "curl -sf http://localhost:8080/health/ready | grep -q UP"
check "agentlens realm exists" \
  "curl -sf http://localhost:8080/realms/agentlens | grep -q agentlens"
check "Token exchange works" \
  "curl -sf -X POST http://localhost:8080/realms/agentlens/protocol/openid-connect/token \
    -d 'grant_type=password&client_id=agentlens-api&client_secret=agentlens-api-secret&username=bank-admin&password=admin123' \
    | grep -q access_token"

# ── 9. RabbitMQ ───────────────────────────────────────────────────────────────
section "RabbitMQ"
check "RabbitMQ management API" \
  "curl -su agentlens:agentlens_dev http://localhost:15672/api/overview | grep -q rabbitmq_version"
check "audit.worm.main queue exists" \
  "curl -su agentlens:agentlens_dev http://localhost:15672/api/queues/agentlens/audit.worm.main | grep -q name"
check "audit.worm.dlq exists" \
  "curl -su agentlens:agentlens_dev http://localhost:15672/api/queues/agentlens/audit.worm.dlq | grep -q name"

# ── 10. OpenSearch ────────────────────────────────────────────────────────────
section "OpenSearch"
check "OpenSearch cluster health green/yellow" \
  "curl -sf http://localhost:9200/_cluster/health | grep -q '\"status\":\"green\"\|\"status\":\"yellow\"'"
check "OpenSearch Dashboards reachable" \
  "curl -sf http://localhost:5601/api/status | grep -q overall"

# ── 11. AgentLens SDK integration tests ──────────────────────────────────────
section "AgentLens SDK — integration with real infra"
if command -v python3 &>/dev/null && [ -f venv/bin/python ]; then
  check "S3 Object Lock write via SDK" \
    "AWS_ENDPOINT_URL=http://localhost:4566 AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test \
     venv/bin/python -c \"
from agentlens.storage import S3ObjectLockAdapter
from agentlens.audit_log import AuditLog, AuditEvent, EventType
adapter = S3ObjectLockAdapter(bucket='agentlens-worm-audit', region='ap-south-1')
log = AuditLog('TestBank', storage_adapter=adapter)
log.append(AuditEvent(agent_id='e2e-test', event_type=EventType.AGENT_START))
print('S3 write OK')
\""
  check "OTEL span emitted to collector" \
    "venv/bin/python -c \"
from agentlens.otel import OTELExporter
from agentlens.audit_log import AuditLog, AuditEvent, EventType
exp = OTELExporter(endpoint='http://localhost:4317', service_name='e2e-test')
log = AuditLog('TestBank', otel_exporter=exp)
log.append(AuditEvent(agent_id='e2e-test', event_type=EventType.DECISION))
print('OTEL emit OK')
\""
  check "Postgres ComplianceDatabase write" \
    "venv/bin/python -c \"
import os
os.environ['AGENTLENS_DB_URL'] = 'postgresql://agentlens:agentlens_dev_pw@localhost:5432/agentlens_compliance'
from agentlens.compliance_db import ComplianceDatabase
db = ComplianceDatabase()
db.record_session({'session_id':'e2e-001','entity':'TestBank','decisions_recorded':5,'human_overrides':1,'chain_intact':True})
rate = db.override_rate('TestBank')
assert rate > 0
print('Postgres ComplianceDB OK')
\""
else
  echo -e "${YELLOW}⚠${NC}  SDK tests skipped — run from repo root with venv activated"
fi

# ── Summary ────────────────────────────────────────────────────────────────
echo ""
echo "=================================="
echo -e "Results: ${GREEN}$PASS passed${NC}  ${RED}$FAIL failed${NC}"
echo ""
if [ $FAIL -eq 0 ]; then
  echo -e "${GREEN}All systems are wired and healthy.${NC}"
  echo "Open:"
  echo "  Grafana:    http://localhost:3000  (admin / agentlens_dev)"
  echo "  Jaeger:     http://localhost:16686"
  echo "  OpenSearch: http://localhost:5601"
  echo "  RabbitMQ:   http://localhost:15672 (agentlens / agentlens_dev)"
  echo "  Vault:      http://localhost:8200  (token: agentlens-dev-token)"
  echo "  Keycloak:   http://localhost:8080  (admin / admin)"
else
  echo -e "${RED}$FAIL system(s) not ready. Check docker compose logs.${NC}"
  exit 1
fi
