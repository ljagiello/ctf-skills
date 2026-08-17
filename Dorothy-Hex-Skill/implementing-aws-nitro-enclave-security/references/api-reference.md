# API Reference: AWS Nitro Enclave Security Agent

## Overview

Assesses the security posture of AWS Nitro Enclave deployments by auditing KMS key policies for attestation conditions, verifying IAM role permissions, validating attestation document structure, and searching CloudTrail for enclave-related security events. For authorized cloud security assessments only.

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| boto3 | >=1.26 | AWS API access for EC2, KMS, IAM, CloudTrail, SSM |
| cbor2 | >=5.4 | CBOR decoding of Nitro Enclave attestation documents |
| cryptography | >=38.0 | X.509 certificate parsing and signature verification |

## CLI Usage

```bash
# Full assessment
python agent.py --region us-east-1 --kms-key-ids alias/enclave-key mrk-abc123 \
  --iam-roles EnclaveParentRole --cloudtrail-days 14 --output report.json

# Validate a specific attestation document
python agent.py --attestation-doc <base64-encoded-doc> --output attestation_report.json

# Quick scan of enclave-enabled instances only
python agent.py --region us-west-2 --output instances_report.json
```

## Arguments

| Argument | Required | Description |
|----------|----------|-------------|
| `--region` | No | AWS region to assess (default: us-east-1) |
| `--kms-key-ids` | No | One or more KMS key IDs or aliases to audit for attestation conditions |
| `--iam-roles` | No | IAM role names to audit for enclave-appropriate permissions |
| `--attestation-doc` | No | Base64-encoded attestation document to validate structure |
| `--cloudtrail-days` | No | Number of days of CloudTrail history to search (default: 7) |
| `--output` | No | Output file path (default: `nitro_enclave_security_report.json`) |

## Key Functions

### `get_nitro_instances(ec2_client, region)`
Discovers all EC2 instances with Nitro Enclave support enabled by filtering on `enclave-options.enabled=true`. Returns instance IDs, types, IAM roles, and launch times.

### `audit_kms_key_policy(kms_client, key_id)`
Parses KMS key policies to verify the presence of `kms:RecipientAttestation:ImageSha384` and `kms:RecipientAttestation:PCR*` condition keys. Flags keys that allow Decrypt/GenerateDataKey without attestation conditions.

### `audit_iam_role_for_enclave(iam_client, role_name)`
Checks an IAM role for KMS permissions, wildcard resources, and overprivileged policies (AdministratorAccess). Audits both attached managed policies and inline policies.

### `validate_attestation_document_structure(attestation_b64)`
Decodes a base64-encoded COSE_Sign1 attestation document, extracts PCR measurements, module ID, timestamps, certificate chain, and public key. Validates structural completeness.

### `audit_cloudtrail_enclave_events(cloudtrail_client, days_back)`
Searches CloudTrail for enclave-related events including instance launches with enclave options and KMS operations with Recipient (attestation) parameters.

### `check_enclave_allocator_config(instance_id, ssm_client)`
Uses SSM Run Command to read the enclave allocator configuration from `/etc/nitro_enclaves/allocator.yaml` and checks for adequate memory and CPU allocation.

## Output Schema

```json
{
  "report_type": "Nitro Enclave Security Assessment",
  "generated_at": "ISO-8601 timestamp",
  "summary": {
    "enclave_instances": 0,
    "kms_keys_audited": 0,
    "iam_roles_audited": 0,
    "cloudtrail_events": 0,
    "total_issues": 0,
    "critical_issues": 0
  },
  "critical_findings": ["string"],
  "instances": [{"instance_id": "", "instance_type": "", "enclave_enabled": true}],
  "kms_policy_audits": [{"key_id": "", "has_attestation_condition": false, "pcr_conditions": [], "issues": []}],
  "iam_role_audits": [{"role_name": "", "has_kms_permissions": false, "overprivileged": false, "issues": []}],
  "cloudtrail_events": [{"event": "", "time": "", "user": "", "detail": ""}],
  "attestation_validation": {"valid_structure": false, "pcrs": {}, "issues": []}
}
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | No critical issues found |
| 1 | Critical issues detected (missing attestation conditions or overprivileged roles) |
