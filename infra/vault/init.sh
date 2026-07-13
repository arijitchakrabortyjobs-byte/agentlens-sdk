#!/bin/sh
# Run after vault starts to seed all AgentLens secrets.
# In prod: these are populated by the bank's security team, not this script.

export VAULT_ADDR=http://localhost:8200
export VAULT_TOKEN=agentlens-dev-token

# Enable KV secrets engine
vault secrets enable -path=agentlens kv-v2

# Seed LLM API keys (bank uses Indian endpoints in prod)
vault kv put agentlens/llm \
  anthropic_api_key="sk-ant-REPLACE-IN-PROD" \
  sarvam_api_key="sarvam-REPLACE-IN-PROD" \
  bedrock_role_arn="arn:aws:iam::123456789012:role/agentlens-bedrock"

# Seed AWS credentials (in prod: replaced by IRSA — no static keys needed)
vault kv put agentlens/aws \
  access_key_id="LOCALSTACK_DEV_KEY" \
  secret_access_key="LOCALSTACK_DEV_SECRET" \
  region="ap-south-1" \
  s3_bucket="agentlens-worm-audit"

# Seed Postgres credentials
vault kv put agentlens/postgres \
  host="postgres" \
  port="5432" \
  db="agentlens_compliance" \
  user="agentlens" \
  password="agentlens_dev_pw"

# Seed OTEL endpoint
vault kv put agentlens/otel \
  endpoint="http://otel-collector:4317" \
  service_name="agentlens-dev"

echo "Vault seeded. Read secrets with:"
echo "  vault kv get agentlens/aws"
echo "  vault kv get agentlens/postgres"
