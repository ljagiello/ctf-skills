# Sensitive Data Tracking Reference

Track and document all credentials, tokens, API keys, and sensitive data discovered during HackerOne testing.

## Data Categories

| Category | Types | Default Severity |
|----------|-------|-----------------|
| Credentials | Usernames, passwords, hashes, service accounts | CRITICAL |
| API Keys & Tokens | Bearer tokens, API keys, OAuth tokens, JWTs | HIGH |
| Private Data | Private keys (RSA/EC/SSH), certificates | CRITICAL |
| Configuration Data | Database connection strings, config files, env vars | CRITICAL |
| User PII | Email, phone, address, SSN, DOB | CRITICAL |
| Other Sensitive | Internal IPs, architecture info, service discovery | MEDIUM |

## Metadata Schema

Each engagement produces a `sensitive_data_metadata.json`:

```json
{
  "program": "Program Name",
  "program_handle": "handle",
  "asset_identifier": "https://example.com",
  "asset_type": "URL",
  "testing_date_start": "2025-01-16T10:00:00Z",
  "testing_date_end": "2025-01-16T14:30:00Z",
  "tester": "Pentester Agent",
  "sensitive_data_categories": {
    "credentials": [],
    "api_keys_and_tokens": [],
    "private_data": [],
    "configuration_data": [],
    "user_pii": [],
    "other_sensitive": []
  },
  "summary": {
    "total_items_discovered": 0,
    "by_category": {},
    "by_severity": {},
    "highest_risk_finding": null
  }
}
```

Each item in a category array contains: `type`, `location`, `finding_id`, `discovered_date`, `data` (redacted), `evidence` (file refs), `impact_assessment` (severity, scope), `remediation`, `status`.

## Detection Patterns

### Credentials
```python
CREDENTIAL_PATTERNS = [
    r"username[:\s]+(['\"]?)(\w+)\1",
    r"password[:\s]+(['\"]?)(.+?)\1",
    r"admin[:\s]+(['\"]?)(\w+)\1"
]
```

### API Keys
```python
API_KEY_PATTERNS = [
    r"(sk_live|sk_test)_[A-Za-z0-9]{20,}",
    r"(pk_live|pk_test)_[A-Za-z0-9]{20,}",
    r"Bearer\s+[A-Za-z0-9._\-]+",
    r"api[_-]?key[:\s]+(['\"]?)([A-Za-z0-9_\-]+)\1"
]
```

### Private Keys
```python
PRIVATE_KEY_PATTERNS = [
    r"-----BEGIN\s+(?:RSA\s+)?PRIVATE KEY-----",
    r"-----BEGIN\s+EC\s+PRIVATE KEY-----",
    r"-----BEGIN\s+OPENSSH PRIVATE KEY-----"
]
```

### Database Credentials
```python
DB_CREDENTIAL_PATTERNS = [
    r"(mongodb|postgres|mysql|mssql)://([^:]+):([^@]+)@",
    r"jdbc:.*://(.*):(.*)@"
]
```

### PII
```python
PII_PATTERNS = {
    "email": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
    "phone": r"\+?1?\s*\(?(\d{3})\)?[\s.-]?(\d{3})[\s.-]?(\d{4})",
    "ssn": r"\d{3}-\d{2}-\d{4}",
    "credit_card": r"\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}"
}
```

## Redaction Rules

| Data Type | Redaction Format |
|-----------|-----------------|
| Passwords | `[REDACTED]` |
| API keys | `****...last_4_chars` |
| Tokens | `[REDACTED]` |
| Private keys | `[REDACTED]` |
| Credit cards | `****-****-****-last_4` |
| SSN | `***-**-last_4` |
| Phone/Email | `[REDACTED]` |
| Database hosts | `[REDACTED]` |

**Safe to show**: Key ID/fingerprint, last 4 chars, key type/algorithm, scope/permissions, account type.

## Tracker API

```python
from tools.sensitive_data_tracker import SensitiveDataTracker

tracker = SensitiveDataTracker(program_name, asset_identifier, output_dir)

tracker.add_credentials(username, password_hash, account_type, location, finding_id, ...)
tracker.add_api_key(key_id, key_preview, scope, location, finding_id, ...)
tracker.add_private_key(key_type, key_length, purpose, location, finding_id, ...)
tracker.add_database_credentials(database_type, host, port, database_name, location, finding_id, ...)
tracker.add_user_pii(pii_types, records_affected, location, finding_id, ...)
tracker.add_configuration_data(...)
tracker.add_other_sensitive_data(...)

tracker.finalize()
tracker.export_summary()  # -> sensitive_data_report.md + sensitive_data_metadata.json
```

## Compliance Notes

- **GDPR**: Document all personal data accessed. Notify supervisory authority within 72 hours if high risk. Notify affected individuals.
- **CCPA**: Document California resident data accessed. Provide right to access/delete. File breach notification if applicable.
- **General**: Minimize PII in reports. Secure all data during testing. Follow responsible disclosure practices.
