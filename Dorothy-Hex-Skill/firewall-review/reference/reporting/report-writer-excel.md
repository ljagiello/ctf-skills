<!-- ../reporting/report-writer-excel.md -->
---
name: report-writer-excel
description: Renders the 6-sheet audit-grade remediation tracker XLSX deliverable from approved findings. Deterministic openpyxl pipeline; re-skinnable via brand.yaml.
---

# Report Writer — Excel (remediation tracker)

**Reference implementation:** `fwrr.report.excel.render_excel` in [firewall-review](https://github.com/ipunithgowda/firewall-review)
**Version pin:** `report-writer-excel:0.2.0` {{VERIFY}} — no `VERSIONS.md` in repo; pin string not authoritative.
**CLI:** `scripts/render-xlsx.py <engagement-dir>`

## Role in the pipeline
Reads `findings.final.jsonl` (enriched with Confidence + Validation Status by `fwrr.validation.post_process.enrich`) and `Pre-requisites/scoping-questionnaire.yaml`, then emits one `.xlsx` to the engagement's `Deliverables/` directory.

## Sheet layout (in creation order — `render_excel()`, lines 100-113)

### 1. Document Control
Audit-firm cover sheet built by `_build_document_control()`. Brand banner, document title block, positioning statement, 10-row Document Version Control table (title, version, date, engagement ID, period, prep, review, approved-by, classification, total findings), Firewalls in Scope block (driven by `scope.devices` / `devices_parsed_names`, with check/cross icons per device), Revision History, Purpose, Notice block (3 brand-config notices, fallback to `disclaimer_long`), Contact Details (skips empty brand fields).

### 2. Dashboard
Built by `_build_dashboard()`. Five KPI cards (Firewalls Audited coverage, Total Findings, Critical, High, Manual Review), Validated Findings 3-bucket summary (Confirmed / Needs Review / Discarded), Severity Distribution table + horizontal BarChart, Confidence Distribution (H/M/L), Detector Distribution table + PieChart. Charts only render when source data is non-empty (guards openpyxl from empty-range crashes).

### 3. Methodology & Legend
Built by `_build_methodology()`. Three sub-blocks: 6-phase audit pipeline (Intake, Detect, Validate, Pentest, Review, Report); 17-row observation-type rating legend (canonical taxonomy: Allow from Any Source = Critical, Allow to Any Destination = Critical, Access to Admin Services = High, Allow to Any Port = High, Access to ClearText Services = High, Access to Sensitive Services = Medium, Access to Unnecessary Services = Medium, Rules Allow from a Subnet = Medium, Rules Allow to a Subnet = Medium, Rules Allow Any Protocol = Low, Rules Allow Any IP = Low, Rules Allow ICMP = Low, Rules Allow to Port Range = Low, Rules Allow Without Logging = Low, Allow from Network Address Range = Low, Allow to a Network Address Range = Low, Rules List does not end with drop-all-and-log = Informational); Frameworks Cited (NIST CSF 2.0, PCI DSS v4.0.1, ISO/IEC 27001:2022, CIS Controls v8.1, HIPAA Security Rule, GDPR); Tool & Skill Provenance (parser/detector versions + skill-set SHA-256).

### 4. Findings & Action Plan
Built by `_build_findings()`. Banner spans `A1:AB1` — **28 columns** (not 20), header row 4. Verbatim headers: `ID`, `Firewall`, `Severity`, `Confidence`, `Validation_Status`, `Detector`, `Title`, `Rule_ID`, `Source_File`, `Line`, `Quoted_Rule`, `Description`, `Impact`, `Likelihood`, `Recommendation`, `Frameworks`, `Primary_Framework`, `Primary_Control`, `Owner`, `Status`, `Assigned`, `Target_Completion`, `Verification`, `Closure_Date`, `Residual_Risk`, `Notes`, `Input_SHA256`, `Parser_Ver`. Rows sorted by severity rank then ID. Severity / Confidence / Validation Status cells are coloured pills. Frozen panes at `H5`; auto-filter on the full table; Status column (T) gets a list-validator restricted to `Open, In Progress, Closed, Accepted Risk, False Positive`. Target_Completion auto-fills via `SLA_DAYS` (Critical 15d, High 30d, Medium 90d, Low 180d, Info 365d, RequiresManualReview 30d).

### 5. Discarded (False Positives)
Built by `_build_discarded()`. Four-column table — `Rule ID`, `Line`, `Quoted rule text`, `Why discarded` — listing rules auto-filtered by the infrastructure-rule sanity filter (loopback, stateful return-traffic, control-plane). When `discarded_fps` is empty, prints a single italic "No infrastructure rules were discarded" line.

### 6. Limitations
Built by `_build_limitations()`. Three-column table (`Category`, `What we couldn't determine`, `How to close the gap`). Always emits CIS Benchmarks, Egress visibility, NVD CVE matching rows; conditionally prepends Traffic-logs and Semantic-confirmation rows when `RequiresManualReview` / `senior-pentester-semantic` findings are present.

## Brand plumbing
`fwrr.report.brand.load()` merges `brand.yaml` (at repo root) over the OSS `_DEFAULTS` dict and returns it as the module-level `BRAND` constant in `excel.py`. Fields consumed: `name` (banners on Document Control + Dashboard), `tagline`, `url`, `audit_email`, `company`, `address`, `department` (Contact Details), `disclaimer_long` + `notice_ip` / `notice_nowarranty` / `notice_changes` (Notice block), `primary_navy` / `primary_blue` / `accent_red` / `accent_green` (palette, normalized to ARGB by `_hex_to_argb()`). Empty fields are skipped, so OSS builds don't render blank rows.

## Failure modes
- Missing `findings.final.jsonl` → CLI exits 1 with `[err] ... missing`.
- Empty findings list → workbook still emits; charts are suppressed (empty-range guards at lines 227 + 272).
- Hostname extraction reads each parsed config to find `set hostname "..."`; OS errors are swallowed and the device is treated as "config not supplied".

## Output filename convention
`scripts/render-xlsx.py` builds `<customer-slug>-firewall-review_<YYYY-MM-DD>.xlsx` from the questionnaire's `engagement.client` plus the date embedded in the engagement folder name. If either piece is missing, falls back to `remediation-tracker.xlsx`. Writes into `<engagement>/Deliverables/` (or legacy lowercase `deliverables/` when only that exists).
