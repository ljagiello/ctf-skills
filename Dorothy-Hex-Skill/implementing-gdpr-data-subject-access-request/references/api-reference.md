# API Reference: GDPR DSAR Workflow Automation

## PIIPatternMatcher

Scans text for PII using compiled regex patterns with confidence scoring and contextual boosting.

### Constructor
```python
PIIPatternMatcher(custom_patterns=None)
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `custom_patterns` | `dict` or `None` | Additional regex patterns to include in scanning |

### Methods

#### `scan_text(text, min_confidence=0.5)`
Scan a string for PII matches.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `text` | `str` | required | Text to scan for PII |
| `min_confidence` | `float` | `0.5` | Minimum confidence threshold (0.0-1.0) |

**Returns:** `list[dict]` -- Each match contains `type`, `value`, `description`, `confidence`, `gdpr_category`, `position`.

#### `scan_file(file_path, min_confidence=0.5)`
Scan a file on disk for PII matches.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `file_path` | `str` | required | Absolute path to the file |
| `min_confidence` | `float` | `0.5` | Minimum confidence threshold |

**Returns:** `dict` with `file`, `size_bytes`, `matches`, `match_count`, `pii_types_found`.

### Built-in PII Patterns

| Pattern Name | Description | Confidence | GDPR Category |
|-------------|-------------|------------|---------------|
| `email` | Email address | 0.95 | contact_information |
| `phone_international` | International phone number | 0.70 | contact_information |
| `uk_phone` | UK phone number | 0.80 | contact_information |
| `ssn_us` | US Social Security Number | 0.85 | government_id |
| `nino_uk` | UK National Insurance Number | 0.90 | government_id |
| `credit_card` | Credit/debit card number | 0.85 | financial_data |
| `iban` | International Bank Account Number | 0.80 | financial_data |
| `ipv4` | IPv4 address | 0.60 | online_identifier |
| `date_of_birth` | Date of birth (DD/MM/YYYY) | 0.65 | demographic_data |
| `uk_postcode` | UK postcode | 0.75 | location_data |
| `passport_uk` | UK passport number (9 digits) | 0.40 | government_id |
| `eu_vat` | EU VAT number | 0.50 | financial_data |

---

## PIIDiscoveryEngine

Discovers PII across structured (database) and unstructured (files) data sources.

### Constructor
```python
PIIDiscoveryEngine(custom_patterns=None)
```

### Methods

#### `scan_database(connection_string, search_identifiers, tables=None)`
Generate parameterized SQL queries for PII discovery in databases.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `connection_string` | `str` | required | Database connection string (redacted in output) |
| `search_identifiers` | `dict` | required | Key-value pairs to search for (e.g., `{"email": "user@example.com"}`) |
| `tables` | `list[str]` or `None` | auto | Tables to scan; defaults to common tables |

**Returns:** `dict` with `source_type`, `connection`, `tables_scanned`, `queries_generated`, `queries`.

#### `scan_files(directories, search_identifiers, file_extensions=None, max_file_size_mb=50)`
Scan files in directories for PII matching identifiers.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `directories` | `list[str]` | required | Directory paths to scan |
| `search_identifiers` | `dict` | required | Identifiers to search for |
| `file_extensions` | `list[str]` or `None` | common types | File extensions to include |
| `max_file_size_mb` | `int` | `50` | Skip files larger than this |

**Returns:** `dict` with `files_scanned`, `files_with_matches`, `matches`, `raw_text_matches`.

#### `scan_with_ner(text_corpus, entity_types=None, confidence_threshold=0.7)`
Scan text using Named Entity Recognition (spaCy NER with regex fallback).

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `text_corpus` | `list[str]` | required | List of file paths to scan |
| `entity_types` | `list[str]` or `None` | common types | NER entity types to detect |
| `confidence_threshold` | `float` | `0.7` | Minimum confidence for results |

**Supported Entity Types:** `PERSON`, `EMAIL`, `PHONE_NUMBER`, `LOCATION`, `DATE_OF_BIRTH`, `ORG`, `GPE`

**Returns:** `dict` with `files_processed`, `total_entities`, `results`, `model_used`.

#### `consolidate_results(*result_sets)`
Merge results from database, file, and NER scans into a unified record set.

**Returns:** `dict` with `total_records`, `source_count`, `sources`, `records`.

#### `full_scan(search_identifiers, sources=None, db_connection="", directories=None)`
Run a complete PII discovery scan across all source types.

**Returns:** Consolidated `dict` from all scans.

---

## DataMapper

Maps discovered PII to GDPR Article 15 disclosure categories.

### Constructor
```python
DataMapper(data_inventory_path=None)
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `data_inventory_path` | `str` or `None` | Path to JSON data inventory for overrides |

### Methods

#### `map_to_article15(pii_records, data_subject_id)`
Map PII records to Article 15 required categories including processing purposes, legal basis, retention periods, and recipients.

**Returns:** `dict` with `categories`, `supplementary_info`, `article_15_reference`.

### Article 15 Categories Mapped

| Category | Article Reference | Contents |
|----------|-------------------|----------|
| Processing Purposes | Art. 15(1)(a) | Why data is processed |
| Data Categories | Art. 15(1)(b) | Types of personal data |
| Recipients | Art. 15(1)(c) | Who receives the data |
| Retention Period | Art. 15(1)(d) | How long data is kept |
| Data Subject Rights | Art. 15(1)(e-f) | Rights to rectify, erase, restrict, object |
| Data Source | Art. 15(1)(g) | Where data was collected from |
| Automated Decisions | Art. 15(1)(h) | Profiling and automated decision-making |
| International Transfers | Art. 15(2) | Safeguards for cross-border transfers |

---

## ExemptionReviewer

Reviews DSAR data against applicable GDPR/UK GDPR exemptions.

### Methods

#### `review_exemptions(mapped_data, exemption_checks=None)`
Flag applicable exemptions for DPO review.

**Returns:** `dict` with `exemption_count`, `exemptions`, `review_status`.

#### `apply_redactions(mapped_data, approved_exemptions)`
Apply approved exemption redactions to the mapped data.

**Returns:** Redacted `dict` with `redaction_log`.

### Supported Exemption Types

| Type | Legal Basis | Action |
|------|-------------|--------|
| `third_party_data` | Art. 15(4) / DPA 2018 Sch. 2 Para 16 | redact |
| `legal_professional_privilege` | DPA 2018 Sch. 2 Para 19 | withhold |
| `trade_secrets` | Recital 63 GDPR | redact |
| `crime_prevention` | DPA 2018 Sch. 2 Para 2 | withhold |
| `management_forecasting` | DPA 2018 Sch. 2 Para 22 | withhold |
| `negotiations` | DPA 2018 Sch. 2 Para 24 | withhold |
| `regulatory_function` | DPA 2018 Sch. 2 Para 20 | withhold |

---

## DSARResponseGenerator

Generates compliant DSAR response packages per GDPR Article 15.

### Constructor
```python
DSARResponseGenerator(template_dir=None, organization_name="Organization",
                      dpo_email="dpo@organization.com", controller_name="Data Protection Officer")
```

### Methods

#### `generate_response(dsar_id, data_subject, mapped_data, format="json", request_date=None)`
Generate a complete response package with cover letter, data export, supplementary info, and audit metadata.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `dsar_id` | `str` | required | DSAR reference ID |
| `data_subject` | `str` | required | Name of the data subject |
| `mapped_data` | `dict` | required | Output from DataMapper/ExemptionReviewer |
| `format` | `str` | `"json"` | Export format: `json` or `csv` |
| `request_date` | `str` or `None` | today | Date the request was received |

**Returns:** `dict` with `documents` list containing filename, type, and content for each document.

#### `save_response_package(response, output_dir)`
Save all response documents to disk.

**Returns:** `list[str]` of saved file paths.

---

## DSARWorkflowEngine

Manages the complete DSAR lifecycle: intake, tracking, deadlines, and compliance.

### Constructor
```python
DSARWorkflowEngine(config_path=None)
```

### Methods

#### `register_dsar(requester_name, requester_email, request_channel, request_text, identity_docs=None)`
Register a new DSAR and start the 30-day compliance clock.

**Returns:** `dict` with `dsar_id`, `deadline`, `status`, `identity_verified`.

#### `update_status(dsar_id, new_status, notes="")`
Update DSAR processing status.

**Valid Statuses:** `received`, `identity_verification`, `verification_failed`, `in_progress`, `pii_discovery`, `exemption_review`, `dpo_review`, `response_generation`, `response_sent`, `closed`, `refused`.

#### `apply_extension(dsar_id, reason)`
Apply a 2-month extension for complex requests per Art. 12(3).

#### `pause_clock(dsar_id, reason)`
Pause the response clock (e.g., awaiting identity verification).

#### `days_remaining(dsar_id)`
Calculate remaining days until DSAR deadline. **Returns:** `int`.

#### `get_overdue_dsars()`
Get all DSARs past their deadline. **Returns:** `list[dict]`.

#### `generate_dashboard()`
Generate a DSAR processing dashboard summary. **Returns:** `dict` with status breakdown and overdue info.

---

## DSARAuditLogger

Maintains JSONL audit trails for DSAR processing lifecycle.

### Constructor
```python
DSARAuditLogger(log_path="dsar_audit_logs")
```

### Methods

#### `log_event(dsar_id, event_type, details=None)`
Log a DSAR processing event to the JSONL audit file.

#### `get_audit_trail(dsar_id)`
Retrieve the complete audit trail. **Returns:** `list[dict]`.

#### `generate_compliance_report(dsar_id)`
Generate a compliance report with pass/fail checks for all processing steps.

**Returns:** `dict` with `compliance_checks`, `timeline`, `overall_compliance` (`COMPLIANT` or `REVIEW_REQUIRED`).

---

## CLI Usage

```bash
# Full automated pipeline
python agent.py --action full_pipeline \
    --requester-name "Jane Smith" \
    --requester-email "jane.smith@example.com" \
    --scan-dirs /var/log/app /data/exports \
    --db-connection "postgresql://user:pass@localhost/appdb" \
    --output-dir dsar_output \
    --format json

# Scan text for PII
python agent.py --action scan_pii \
    --scan-text "Contact jane@example.com or call +44 20 7946 0958"

# Scan files only
python agent.py --action scan_files \
    --scan-dirs /data/exports /var/log \
    --requester-email "jane@example.com"

# Generate dashboard
python agent.py --action dashboard
```

### CLI Arguments

| Argument | Default | Description |
|----------|---------|-------------|
| `--action` | `full_pipeline` | Action to perform |
| `--requester-name` | `Test Subject` | Data subject name |
| `--requester-email` | `test@example.com` | Data subject email |
| `--request-channel` | `email` | Request channel |
| `--scan-dirs` | `[]` | Directories to scan |
| `--db-connection` | `""` | Database connection string |
| `--output-dir` | `dsar_output` | Output directory |
| `--config` | `dsar_config.json` | Configuration file path |
| `--format` | `json` | Output format (`json` or `csv`) |
| `--min-confidence` | `0.5` | Minimum PII confidence threshold |
| `--scan-text` | `""` | Direct text to scan for PII |
