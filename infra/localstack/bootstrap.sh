#!/bin/bash
# Run once after LocalStack starts to create all AWS resources.
# Emulates: S3 Object Lock (ap-south-1), KMS CMK, Secrets Manager, SQS DLQ
# Usage: docker exec agentlens-localstack bash /etc/localstack/init/bootstrap.sh
#   OR:  AWS_ENDPOINT_URL=http://localhost:4566 bash infra/localstack/bootstrap.sh

set -e
ENDPOINT="${AWS_ENDPOINT_URL:-http://localhost:4566}"
REGION="ap-south-1"
AWSCLI="aws --endpoint-url=$ENDPOINT --region=$REGION"

echo "==> Creating KMS Customer Managed Key (simulates AWS KMS CMK)"
KMS_KEY_ID=$($AWSCLI kms create-key \
  --description "AgentLens WORM audit log encryption key" \
  --query 'KeyMetadata.KeyId' --output text)
echo "    KMS Key ID: $KMS_KEY_ID"

$AWSCLI kms create-alias \
  --alias-name alias/agentlens-worm \
  --target-key-id "$KMS_KEY_ID" || true

echo "==> Creating S3 bucket with Object Lock (COMPLIANCE mode)"
$AWSCLI s3api create-bucket \
  --bucket agentlens-worm-audit \
  --object-lock-enabled-for-bucket \
  --create-bucket-configuration LocationConstraint=$REGION

$AWSCLI s3api put-object-lock-configuration \
  --bucket agentlens-worm-audit \
  --object-lock-configuration '{
    "ObjectLockEnabled": "Enabled",
    "Rule": {
      "DefaultRetention": {
        "Mode": "COMPLIANCE",
        "Years": 7
      }
    }
  }'

# Enable SSE-KMS on the bucket
$AWSCLI s3api put-bucket-encryption \
  --bucket agentlens-worm-audit \
  --server-side-encryption-configuration "{
    \"Rules\": [{
      \"ApplyServerSideEncryptionByDefault\": {
        \"SSEAlgorithm\": \"aws:kms\",
        \"KMSMasterKeyID\": \"$KMS_KEY_ID\"
      }
    }]
  }"

echo "==> Creating Secrets Manager secrets"
$AWSCLI secretsmanager create-secret \
  --name agentlens/dev/postgres \
  --secret-string '{"host":"localhost","port":"5432","db":"agentlens_compliance","user":"agentlens","password":"agentlens_dev_pw"}' || true

$AWSCLI secretsmanager create-secret \
  --name agentlens/dev/llm-keys \
  --secret-string '{"anthropic_api_key":"sk-ant-REPLACE","sarvam_api_key":"sarvam-REPLACE"}' || true

echo "==> Creating SQS dead-letter queue for failed WORM writes"
DLQ_URL=$($AWSCLI sqs create-queue \
  --queue-name agentlens-worm-dlq \
  --attributes MessageRetentionPeriod=1209600 \
  --query 'QueueUrl' --output text)
echo "    DLQ URL: $DLQ_URL"

DLQ_ARN=$($AWSCLI sqs get-queue-attributes \
  --queue-url "$DLQ_URL" \
  --attribute-names QueueArn \
  --query 'Attributes.QueueArn' --output text)

# Main queue with DLQ redrive policy
$AWSCLI sqs create-queue \
  --queue-name agentlens-worm-main \
  --attributes "{
    \"RedrivePolicy\": \"{\\\"deadLetterTargetArn\\\":\\\"$DLQ_ARN\\\",\\\"maxReceiveCount\\\":\\\"3\\\"}\"
  }" || true

echo ""
echo "LocalStack bootstrap complete."
echo "S3 bucket:       agentlens-worm-audit"
echo "KMS key alias:   alias/agentlens-worm"
echo "SQS DLQ:         agentlens-worm-dlq"
echo "Secrets Manager: agentlens/dev/postgres, agentlens/dev/llm-keys"
echo ""
echo "Test S3 write:   aws --endpoint-url=$ENDPOINT s3 ls s3://agentlens-worm-audit/"
