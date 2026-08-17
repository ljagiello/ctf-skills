# Finding Validation Reference

Anti-hallucination validation for pentest findings. Every claim must be backed by raw evidence. **All checks must pass; one failure = finding rejected.**

## How Validation Works

A validator agent (spawned from `skills/coordination/reference/validator-role.md`) runs per-finding. It can read evidence, run PoCs, cross-reference claims against raw scan files, and detect fabrication via log timestamps.

| Phase | Who | What |
|-------|-----|------|
| 4a | Executor | Prepare evidence (files exist, CVSS consistent) |
| 4.5 | Coordinator | Deploy one validator per finding (parallel) |

## 5 Required Checks

### 1. CVSS Consistency

Severity label must match CVSS v3.1 score exactly:

| Severity | Range |
|----------|------:|
| CRITICAL | 9.0 - 10.0 |
| HIGH | 7.0 - 8.9 |
| MEDIUM | 4.0 - 6.9 |
| LOW | 0.1 - 3.9 |
| INFORMATIONAL | 0.0 |

CVSS 5.3 labeled "LOW" → REJECTED (should be MEDIUM).

### 2. Evidence Exists

```
finding-NNN/
├── description.md       (required)
├── poc.py               (required)
├── poc_output.txt       (required)
└── evidence/
    └── raw-source.txt   (required: raw tool output)
```

Missing any file → REJECTED.

### 3. PoC Validation

`poc.py` must parse via `ast.parse()`, reference the target (URL/IP/endpoint from finding), and — when safe — be re-run by the validator with output verified.

### 4. Claims Against Raw Evidence

Every extractable factual claim must appear in at least one raw scan file.

| Claim type | Pattern | Example |
|---|---|---|
| HTTP status | `HTTP/1.1 503` | curl/response output |
| Port state | `443/tcp open` | nmap output |
| TLS version | `TLSv1.2` | openssl output |
| Cert CN | `CN=vpn.example.com` | cert output |
| Cert SAN | `DNS:vpn.example.com` | cert output |
| CVE ID | `CVE-2024-3400` | scan output |
| Cipher | `TLS_RSA_WITH_AES_256_GCM_SHA384` | cipher enum |

Rule: ALL claims must be corroborated; one uncorroborated claim = REJECTED. A finding with no extractable claims is also REJECTED.

### 5. Log Corroboration

Executor log must show all 4 phases (`recon`, `experiment`, `test`, `verify`), with verify timestamps spaced ≥ 2s apart (no bulk-stamping).

### 6. Root-cause severity floor

The inverse of Check 1. REJECT a finding for UNDER-rating when its own `description.md` asserts a latent higher-impact outcome that follows from a CONFIRMED missing control (missing tenant/ownership filter, unauthenticated state-change, unvalidated server-fetched URL, etc.) yet scores CVSS C/I/A only on the demonstrated sub-impact because the higher impact was blocked by a TRANSIENT/REVERSIBLE condition (empty data, deleted records, IMDSv2, toggled-off feature). Recompute C/I/A from the root-cause-implied outcome per `formats/transilience-report-style/pentest-report.md` §7.1 and REJECT if the executor's band is more than one band below the recomputed band.

Check 1 stops inflation; Check 6 stops deflation. Apply ONLY when the description itself asserts the higher latent impact from a confirmed control gap — never invent impact the finding does not claim.

## Proof of Validation

Validators write to `{findings_dir}/finding-{id}/evidence/validation/`:

```
evidence/validation/
├── validation-summary.md      (mandatory)
├── poc-rerun-output.txt       (mandatory — even when execution skipped, with reason)
├── verification-script.py     (mandatory — independent reproduction)
├── code-references.md         (mandatory when finding cites code/config/logic)
└── screenshots/*.png          (mandatory when target has web/browser surface)
```

**Completeness rules**:
1. `validation-summary.md` — always.
2. `poc-rerun-output.txt` — always; if skipped, document why and what alternative verification was performed.
3. `verification-script.py` — always; **standalone, self-contained Python**. Must not import from executor's `poc.py` or `evidence/*`. Includes its own target refs, imports, output parsing. Lets a human reviewer reproduce with one script.
4. `code-references.md` — when claims cite source code/config/app logic. Each claim mapped to `file:line` with quoted snippet.
5. `screenshots/*.png` — when finding targets HTTP/HTTPS/web/browser surface. Must show exploitation or observable effect. Skip for raw TCP/UDP/DNS/SNMP/SSH banner findings.

Incomplete packages must not be submitted; the coordinator rejects them.

### validation-summary.md template

```markdown
# Validation: {finding_id}

## Verdict: VALID / REJECTED

## Checks
- CVSS: {severity} matches {score} — PASS/FAIL
- Evidence: all files present — PASS/FAIL
- PoC: {ran/skipped}, output {matches/differs} — PASS/FAIL
- Claims: {N}/{N} corroborated — PASS/FAIL
- Log phases: all present, timestamps valid — PASS/FAIL
- Root-cause floor: {recomputed band} vs {executor band} — PASS/FAIL

## PoC Re-execution
{What happened. If skipped, why.}

## Claims Verified
{Each claim → raw file + line that corroborates it.}

## Notes
{Anything unusual.}

## Evidence Package
- verification-script.py: {generated / N/A reason}
- poc-rerun-output.txt: {succeeded/failed/skipped: reason}
- code-references.md: {generated / not applicable — no code claims}
- screenshots: {N captured / not applicable — non-web finding}
```

### Boundary

Validators write ONLY to `evidence/validation/`. Never modify executor files. **Exception**: if Check 2 fails (no finding directory), proof goes in the rejection JSON only.

## Coordinator Deployment

```python
validator_role = Read("skills/coordination/reference/validator-role.md")

for finding in all_findings:
    Agent(prompt=f"{validator_role}\n\n"
                 f"finding_id: {finding['id']}\n"
                 f"finding_json_path: {findings_file}\n"
                 f"raw_dir: {{OUTPUT_DIR}}/recon/\n"
                 f"executor_log: {{OUTPUT_DIR}}/logs/{executor}.log\n"
                 f"findings_dir: {{OUTPUT_DIR}}/findings/\n"
                 f"output_dir: {{OUTPUT_DIR}}/artifacts/",
          run_in_background=True)
```

After validators complete, the coordinator:
1. Reads `{OUTPUT_DIR}/artifacts/validated/{id}.json` (passed) and `{OUTPUT_DIR}/artifacts/false-positives/{id}.json` (rejected)
2. Cross-executor dedupe (same URL + same CWE → drop duplicate)
3. Aggregates only validated findings

## Output: Validated

`{OUTPUT_DIR}/artifacts/validated/{id}.json`:

```json
{
  "finding_id": "F-001",
  "valid": true,
  "proof_dir": "findings/finding-001/evidence/validation/",
  "checks": {
    "cvss_consistency": {"passed": true, "detail": "CRITICAL matches CVSS 9.1"},
    "evidence_exists": {"passed": true, "detail": "All required files present"},
    "poc_validation": {"passed": true, "detail": "Valid Python, target referenced, output matches", "proof_file": "poc-rerun-output.txt"},
    "claims_vs_raw": {"passed": true, "detail": "All 5 claims corroborated"},
    "log_corroboration": {"passed": true, "detail": "All 4 phases with distinct timestamps"},
    "rootcause_severity_floor": {"passed": true, "detail": "Recomputed band HIGH matches/within one band of executor band"}
  }
}
```

## Output: Rejected

`{OUTPUT_DIR}/artifacts/false-positives/{id}.json`:

```json
{
  "finding_id": "F-009",
  "finding_title": "Information Disclosure via Prelogin Response",
  "source_file": "{OUTPUT_DIR}/findings/executor-findings.json",
  "valid": false,
  "failed_checks": ["cvss_consistency", "evidence_exists", "log_corroboration"],
  "checks": {
    "cvss_consistency": {"passed": false, "detail": "Severity 'LOW' does not match CVSS 5.3 (expected MEDIUM)"},
    "evidence_exists":  {"passed": false, "detail": "No findings/F-009/ directory"},
    "poc_validation":   {"passed": true,  "detail": "Valid Python, target referenced"},
    "claims_vs_raw":    {"passed": true,  "detail": "All 2 claims corroborated"},
    "log_corroboration":{"passed": false, "detail": "Bulk verify timestamps detected"}
  },
  "original_finding": { "...full original..." }
}
```

Rejected findings do NOT appear in the final report — not in findings, appendix, or summary counts. The `false-positives/` directory is the sole record. Reviewers can override via inspection if a validator was wrong.

## What the Validator Catches

1. Severity mislabeling (CVSS 5.3 → LOW; should be MEDIUM)
2. Ghost findings (no per-finding directory with PoC and evidence)
3. Broken PoCs (syntax errors or no target reference)
4. Hallucinated claims (HTTP 503 with no raw scan output supporting it)
5. Fabricated port states (port "open" with no nmap output)
6. TLS inflation (TLS issues not in openssl output)
7. Unverified CVE references (CVE named without scan evidence)
8. Bulk fabrication (all findings "verified" at the same timestamp)
9. Incomplete workflow (missing recon/experiment/test/verify)
10. Unsubstantiated validation (validator passed but `validation-summary.md` missing/empty)
11. Incomplete evidence packages (no `verification-script.py`, missing screenshots for a web target)
