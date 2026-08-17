# Sensitive Data Metadata Integration Guide

How to track sensitive data discovery in HackerOne workflows using `SensitiveDataTracker`.

## Quick Start

```python
from tools.sensitive_data_tracker import SensitiveDataTracker

tracker = SensitiveDataTracker(
    program_name="ACME Corp Bug Bounty",
    asset_identifier="https://api.example.com",
    output_dir="{OUTPUT_DIR}",
)
```

## Logging Discoveries

```python
# Credentials
tracker.add_credentials(
    username="admin", password_hash="$2y$10$abc...", account_type="admin",
    location="SQLi in /search", finding_id="finding-001",
    hash_algorithm="bcrypt",
    evidence={"poc_script": "findings/finding-001/poc.py",
              "screenshot": "evidence/screenshots/finding-001-admin.png"},
)

# API keys
tracker.add_api_key(
    key_id="sk_live_abc123xyz", key_preview="sk_live_****...xyz",
    scope=["read:users", "write:data", "admin"],
    location="Hardcoded in React app.js",
    finding_id="finding-003", token_type="Stripe API Key",
)

# Private keys
tracker.add_private_key(
    key_type="RSA", key_length=2048,
    purpose="AWS EC2 prod key pair",
    location=".git/config in repo",
    finding_id="finding-005",
    systems_accessible=["prod-api", "prod-db", "prod-cache"],
)

# Database credentials
tracker.add_database_credentials(
    database_type="PostgreSQL", host="db.internal.company.com", port=5432,
    database_name="production_users",
    location="Config file via path traversal",
    finding_id="finding-002", records_affected=2547,
    evidence={"poc_script": "findings/finding-002/poc.py",
              "data_sample": "evidence/http-captures/finding-002-db-dump.txt"},
)

# PII access
tracker.add_user_pii(
    pii_types=["email", "phone", "home_address", "dob"],
    records_affected=2547,
    location="DB via SQLi", finding_id="finding-001",
    affected_jurisdictions=["EU", "California"],
    evidence={"sample_record": "evidence/screenshots/finding-001-pii-sample.png",
              "count_proof": "evidence/http-captures/finding-001-record-count.txt"},
)
```

## Finalize and Export

```python
tracker.finalize()
report_path = tracker.export_summary()  # markdown
# JSON saved to {OUTPUT_DIR}/artifacts/sensitive_data_metadata.json
```

## Integration Points

### Hunter agent

Initialize at testing start, process each returned finding through a dispatch helper that maps `credentials_found`, `api_keys_found`, `private_keys_found`, etc. into the corresponding `tracker.add_*` calls. Call `tracker.finalize()` and `tracker.export_summary()` at the end.

```python
def process_finding(finding_data, tracker):
    for cred in finding_data.get("credentials_found", []):
        tracker.add_credentials(
            username=cred["username"], password_hash=cred["password_hash"],
            account_type=cred["type"], location=cred["location"],
            finding_id=finding_data["finding_id"],
        )
    for key in finding_data.get("api_keys_found", []):
        tracker.add_api_key(
            key_id=key["key_id"], key_preview=key["preview"],
            scope=key["scope"], location=key["location"],
            finding_id=finding_data["finding_id"], token_type=key["type"],
        )
    # ... handle other categories
```

### Pentester agent — extracting indicators from PoC output

Inspect `poc_output.txt` and tag indicators by regex match before passing to the tracker.

```python
def collect_indicators(finding):
    indicators = {k: [] for k in
        ("credentials_found","api_keys_found","private_keys_found",
         "database_credentials","user_pii_accessed","config_data_exposed")}
    poc_output = open(finding["poc_output.txt"]).read()
    if re.search(r"username[:\s]+\w+", poc_output):
        indicators["credentials_found"].append({"detected_in": "poc_output", "type": "username"})
    if re.search(r"(sk_live|pk_test|Bearer|Authorization)", poc_output):
        indicators["api_keys_found"].append({"detected_in": "poc_output", "type": "api_key"})
    if re.search(r"-----BEGIN.*PRIVATE KEY-----", poc_output):
        indicators["private_keys_found"].append({"detected_in": "poc_output", "type": "private_key"})
    return indicators
```

## Detection Patterns

```python
CREDENTIAL_PATTERNS = [
    r"username[:\s]+(['\"]?)(\w+)\1",
    r"password[:\s]+(['\"]?)(.+?)\1",
    r"user[:\s]+(['\"]?)(\w+)\1",
    r"pass[:\s]+(['\"]?)(.+?)\1",
    r"admin[:\s]+(['\"]?)(\w+)\1",
]
API_KEY_PATTERNS = [
    r"(sk_live|sk_test)_[A-Za-z0-9]{20,}",
    r"(pk_live|pk_test)_[A-Za-z0-9]{20,}",
    r"Bearer\s+[A-Za-z0-9._\-]+",
    r"Authorization[:\s]+Bearer\s+\S+",
    r"api[_-]?key[:\s]+(['\"]?)([A-Za-z0-9_\-]+)\1",
]
PRIVATE_KEY_PATTERNS = [
    r"-----BEGIN\s+(?:RSA\s+)?PRIVATE KEY-----",
    r"-----BEGIN\s+EC\s+PRIVATE KEY-----",
    r"-----BEGIN\s+OPENSSH PRIVATE KEY-----",
    r"-----BEGIN\s+PGP PRIVATE KEY BLOCK-----",
]
DB_CREDENTIAL_PATTERNS = [
    r"(mongodb|postgres|mysql|mssql)://([^:]+):([^@]+)@",
    r"db[_-]?(user|pass)[:\s]+(['\"]?)(.+?)\2",
    r"database[_-]?(url|connection)[:\s]+(['\"]?)(.+?)\3",
    r"jdbc:.*://(.*):(.*)@",
]
PII_PATTERNS = {
    "email": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
    "phone": r"\+?1?\s*\(?(\d{3})\)?[\s.-]?(\d{3})[\s.-]?(\d{4})",
    "ssn": r"\d{3}-\d{2}-\d{4}",
    "credit_card": r"\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}",
}
```

## Output

- `{OUTPUT_DIR}/artifacts/sensitive_data_metadata.json` — per-finding records with `program`, `asset_identifier`, dates, `sensitive_data_categories` (credentials / api_keys_and_tokens / private_data / configuration_data / user_pii / other_sensitive), and `summary` block.
- `{OUTPUT_DIR}/reports/sensitive_data_report.md` — summary grouped by severity, immediate actions, remediation timeline (0-1h / 1-24h / 1-7d / 30d+).

## Privacy and Redaction

```python
REDACTION_RULES = {
    "passwords": "[REDACTED]",
    "api_keys": "****...last_4_chars",
    "tokens": "[REDACTED]",
    "private_keys": "[REDACTED]",
    "credit_cards": "****-****-****-last_4",
    "ssn": "***-**-last_4",
    "phone": "[REDACTED]",
    "email": "[REDACTED]",
    "ip_address": "redacted",
    "database_host": "[REDACTED]",
}
```

**GDPR**: document personal-data accessed; notify supervisory authority within 72h on high risk; notify individuals if breached. **CCPA**: document Californian residents' data; respect access/delete rights; file breach notice if PII involved. **General**: minimize PII in reports, secure data in transit/storage, follow responsible-disclosure timeline.

## Validation Checklist

- [ ] `sensitive_data_metadata.json` generated; each item has `discovered_date`
- [ ] Evidence references resolve to PoC / screenshots
- [ ] Severity assigned correctly; impact assessed; remediation guidance present
- [ ] Markdown report properly redacted; GDPR/CCPA implications noted on PII
- [ ] Highest-risk finding identified; `sensitive_data_report.md` generated

## Troubleshooting

- Not tracked → tracker not initialized at start, or discovery not logged.
- Incomplete JSON → `tracker.finalize()` not called before export.
- Report missing → call `tracker.export_summary()` after `finalize()`; ensure output dir exists.
- Unsure what to track → see `formats/sensitive-data-metadata.md` for the 6 categories.

## References

- `formats/sensitive-data-metadata.md`
- `.claude/skills/hackerone/tools/sensitive_data_tracker.py`
- GDPR: https://gdpr-info.eu/
- CCPA: https://oag.ca.gov/privacy/ccpa
- HackerOne: https://www.hackerone.com/
