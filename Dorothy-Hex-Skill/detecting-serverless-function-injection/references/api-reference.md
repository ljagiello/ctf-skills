# API Reference: Serverless Function Injection Detection Agent

## Overview

Detects code injection vulnerabilities in AWS Lambda functions by scanning function code for dangerous sinks (eval, exec, os.system, child_process.exec), auditing Lambda layers for external account dependencies, identifying IAM privilege escalation paths through overprivileged execution roles, and monitoring CloudTrail for suspicious function modifications. For authorized security assessments only.

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| boto3 | >=1.26 | AWS API access for Lambda, IAM, CloudTrail |

## CLI Usage

```bash
# Full assessment with code scanning
python agent.py --region us-east-1 --scan-code --cloudtrail-days 14 --output report.json

# Scan specific functions only
python agent.py --functions payment-processor auth-handler --scan-code --output report.json

# Quick assessment without code download (IAM, layers, CloudTrail only)
python agent.py --region us-west-2 --output quick_report.json
```

## Arguments

| Argument | Required | Description |
|----------|----------|-------------|
| `--region` | No | AWS region to assess (default: us-east-1) |
| `--functions` | No | Specific function names to scan (default: all functions in region) |
| `--scan-code` | No | Download and scan function deployment packages for injection sinks |
| `--cloudtrail-days` | No | Number of days of CloudTrail history to search (default: 7) |
| `--output` | No | Output file path (default: `serverless_injection_report.json`) |

## Key Functions

### `enumerate_functions(lambda_client)`
Lists all Lambda functions with runtime, handler, execution role, layers, environment variable names, and function URL configuration. Flags functions with secrets in environment variables.

### `get_event_source_mappings(lambda_client)`
Enumerates all event source mappings (SQS, DynamoDB Streams, Kinesis, Kafka, MQ) to identify injection entry points where untrusted data enters function handlers.

### `download_and_scan_function(lambda_client, function_name, runtime_family, work_dir)`
Downloads the function deployment package, extracts it, and scans source files for injection sinks using regex patterns. Checks whether event data accessors (`event[`, `event.get(`) appear in the context around each sink to assess data flow confidence.

### `audit_layers(lambda_client, functions)`
Identifies Lambda layers from external AWS accounts and high-impact layers shared across 5+ functions. External layers can intercept function execution or override runtime dependencies.

### `detect_privilege_escalation_paths(iam_client, functions)`
Audits execution roles for dangerous permissions (iam:PassRole, lambda:UpdateFunctionCode, sts:AssumeRole) and administrative policies. Any function with UpdateFunctionCode + PassRole is a privilege escalation vector.

### `check_cloudtrail_for_modifications(cloudtrail_client, days_back)`
Searches CloudTrail for UpdateFunctionCode, UpdateFunctionConfiguration, PublishLayerVersion, and CreateFunction events. Flags modifications outside CloudFormation/console, role changes, layer additions, and off-hours activity.

### `check_function_url_security(lambda_client, functions)`
Identifies Lambda function URLs with `AuthType=NONE` that are publicly accessible without authentication.

## Injection Pattern Coverage

### Python Sinks
| Pattern | CWE | Severity |
|---------|-----|----------|
| `eval()` | CWE-95 | Critical |
| `exec()` | CWE-95 | Critical |
| `os.system()` | CWE-78 | Critical |
| `os.popen()` | CWE-78 | Critical |
| `subprocess.*(shell=True)` | CWE-78 | Critical |
| `pickle.loads()` | CWE-502 | High |
| `yaml.load()` without SafeLoader | CWE-502 | High |
| `jinja2.Template()` with event data | CWE-1336 | High |
| SQL via f-string with event data | CWE-89 | Critical |

### Node.js Sinks
| Pattern | CWE | Severity |
|---------|-----|----------|
| `eval()` | CWE-95 | Critical |
| `new Function()` | CWE-95 | Critical |
| `child_process.exec()` | CWE-78 | Critical |
| `child_process.execSync()` | CWE-78 | Critical |
| `vm.runInNewContext()` | CWE-95 | Critical |
| `vm.runInThisContext()` | CWE-95 | Critical |
| Template literal command injection | CWE-78 | Critical |

## Output Schema

```json
{
  "report_type": "Serverless Function Injection Assessment",
  "generated_at": "ISO-8601 timestamp",
  "summary": {
    "functions_analyzed": 0,
    "event_source_mappings": 0,
    "total_findings": 0,
    "critical_findings": 0,
    "high_findings": 0,
    "injection_sinks_found": 0,
    "layer_issues": 0,
    "escalation_paths": 0,
    "suspicious_modifications": 0
  },
  "findings": [
    {
      "category": "code_injection|layer_security|privilege_escalation|suspicious_modification|function_url",
      "function_name": "",
      "severity": "critical|high|medium",
      "description": ""
    }
  ],
  "functions": [],
  "event_source_mappings": [],
  "cloudtrail_events": []
}
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | No critical findings |
| 1 | Critical injection sinks or privilege escalation paths detected |
