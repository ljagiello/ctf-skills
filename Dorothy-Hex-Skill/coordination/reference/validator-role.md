# Validator

Two validator classes. Both are blind reviews — independent of the coordinator's reasoning.

| Class | Spawned | Receives | Job |
|-------|---------|----------|-----|
| **Finding validator** | One per finding at P5 | `finding_id`, `FINDING_DIR`, `TARGET_URL`, `OUTPUT_DIR` | All-or-nothing 5-check on one finding |
| **Engagement validator** | Once at P5 after finding-validators | `OUTPUT_DIR` only | Thoroughness check on the whole engagement |

Mount only `reference/VALIDATION.md`. Do **not** mount the full attack skill — biases judgment.

---

## Finding Validator

### Input

`finding_id`, `FINDING_DIR`, `TARGET_URL`, `OUTPUT_DIR`.

### Checks (all must PASS)

1. **CVSS** — severity matches band (C:9-10, H:7-8.9, M:4-6.9, L:0.1-3.9, I:0). If finding cites a CVE (`CVE-YYYY-NNNNN`), run `python3 tools/nvd-lookup.py <CVE-ID>`, include NVD score in summary, flag if executor's score diverges from NVD by >1.0.
2. **Evidence exists** — `description.md`, `poc.py`, `poc_output.txt`, `evidence/raw-source.txt`.
3. **PoC valid** — valid Python, references the target, output matches `poc_output.txt` after re-run.
4. **Claims vs evidence** — every factual claim in description.md corroborated by a raw scan/log file.
5. **Log phases** — recon / experiment / test / verify present, timestamps ≥ 2 s apart (catches templated bulk-stamp findings).

### Output

- VALID → `{OUTPUT_DIR}/validated/{finding_id}.json`
- REJECTED → `{OUTPUT_DIR}/false-positives/{finding_id}.json` (include original finding + failure reasons)

### Proof artifacts in `{FINDING_DIR}/evidence/validation/`

1. `validation-summary.md` — verdict + each check PASS/FAIL + what you verified. NVD risk-score table if CVE IDs present.
2. `poc-rerun-output.txt` — re-run poc.py, capture full stdout/stderr. If unsafe to run, document the specific reason here.
3. `verification-script.py` — standalone Python that independently reproduces the finding (own imports, own target reference).
4. `code-references.md` — when claims reference source code / config; quote `file:line` per claim.
5. `screenshots/*.png` — for web/browser-accessible findings only.

### Rules

- All-or-nothing. One failure = REJECTED.
- Read all evidence first. Missing = rejected.
- Never modify executor files. Write only to `evidence/validation/`.
- Items 1, 2, 3 always required. 4 required when source-code claims exist. 5 required for web targets.

---

## Engagement Validator

Spawned once per engagement at P5, after every finding-validator completes. Catches engagement-level gaps the per-finding validator can't see.

### Input

`OUTPUT_DIR` only. Read the directory tree; produce a thoroughness verdict.

### Checks (all must PASS for `engagement_status=THOROUGH`)

1. **Port coverage** — every open port in `recon/` has at least one `experiments.md` row.
2. **Share enumeration** — for AD/Windows targets: every share listed in `recon/smb_shares.txt` (or equivalent) has a corresponding spider/probe row in `tools/`. Both anonymous and guest probes attempted where applicable.
3. **Source-code coverage** — every file in `recon/source/` (or equivalent application source dump) referenced by at least one experiments row OR linked from attack-chain.md tested entries.
4. **Wildcard hypothesis** — at least 1 `[wildcard]`-tagged hypothesis appears in attack-chain.md and was tested (has an experiments row).
5. **Mandatory skeptic spawns** — `skeptic-brief-5.md`, `skeptic-brief-15.md`, `skeptic-brief-25.md` exist for the experiment counts the engagement reached.
6. **Time-to-first-finding** — `<= 0.3 * duration_seconds`. Late TTFF is a heuristic for skipped recon.
7. **No `AskUserQuestion` calls** — search any saved transcript / log for the call. Coordinator must have zero.
8. **Attack-class coverage (web/API/transport engagements)** — read `OUTPUT_DIR/coverage.json`. Compute `coverage_ratio = covered / applicable` where `applicable = total − not_applicable`. Every `covered` row must cite ≥1 real `evidence_ref` (a present E-NNN row in `experiments.md` or an existing `finding-NNN/` dir) else it is treated as pending. Every `not_applicable` row must carry a justification. FAIL (`engagement_status:GAPS_FOUND`) if `coverage_ratio < 0.80`. Skip as PASS-NA only for pure host/AD/binary targets with no HTTP/API/TLS surface.

### Output

`{OUTPUT_DIR}/artifacts/engagement-validation.json`:

```json
{
  "engagement_status": "THOROUGH" | "GAPS_FOUND",
  "checks": {
    "port_coverage": "PASS" | "FAIL — <ports skipped>",
    "share_enumeration": "PASS" | "FAIL — <shares skipped>",
    "source_coverage": "PASS" | "FAIL — <files skipped>",
    "wildcard_hypothesis": "PASS" | "FAIL",
    "skeptic_spawns": "PASS" | "FAIL — <missing>",
    "ttff_ratio": 0.27,
    "ask_user_count": 0,
    "attack_class_coverage": "PASS — 17/20 (0.85)" | "FAIL — 7/20 (0.35); pending: XC-CORS, ..."
  },
  "coverage_ratio": 0.85,
  "remediation": ["concrete next experiments to fill the gaps"]
}
```

Plus `{OUTPUT_DIR}/artifacts/engagement-validation-summary.md` (human-readable).

### Rules

- Blind to attack-chain reasoning and finding internals — judge from the directory state alone.
- A `GAPS_FOUND` verdict on an Easy-rated target blocks report generation; the coordinator must address the gaps and re-run validation.
- `attack_class_coverage:FAIL` forces `GAPS_FOUND` regardless of checks 1-7; the coordinator must cover-or-NA the named pending classes and re-validate before COMPLETE.
- Never write to `findings/` or `validated/` — engagement validator only writes to `artifacts/`.
