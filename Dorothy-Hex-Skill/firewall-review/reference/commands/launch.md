---
name: launch
description: Parse all configs in the current engagement, dispatch senior-pentester subagents in parallel, run the validation chain, emit findings ready for /review.
---

# /launch — Run the detection + validation pipeline

No arguments. Claude infers the engagement directory from the most recently scaffolded `engagements/*/` folder, OR asks the operator which engagement.

## What to do

### Step 1 — Locate the engagement and classify inputs
- `ls engagements/` and pick the most recent folder OR ask the operator if there are multiple open engagements. Accept both naming conventions: new `engagements/<slug>_<date>/` AND legacy `engagements/<date>-<slug>/`.
- Confirm there are files under `Pre-requisites/`. If the folder is empty (no top-level files AND no legacy vendor sub-folders containing configs), STOP and remind the operator: "No configs found. Drop files into Pre-requisites/ first — any vendor, any filename."
- **Walk `Pre-requisites/` flat.** The new layout has no per-vendor sub-folders; every config file sits at the top of `Pre-requisites/`. For each file (skipping `README.md`, `scoping-questionnaire.yaml`, and `.DS_Store`), call `fwrr.parsers._sniff.detect_vendor(path)` and report the classification to the operator before parsing:

  ```
  Input classification:
    <customer-slug>-va1-fgtfwa.conf    → fortigate (conf 0.95)
    acme-panfw-east.xml                → pan-os-xml (conf 1.00)
    nsg-prod-east.json                 → azure-nsg (conf 0.95)
    edge-unknown.txt                   → unknown (conf 0.00)  [skipped]
  ```

  If any file classifies as `unknown` or drops below confidence 0.75, warn the operator
  and give a fix hint: "rename the file to include a vendor hint (e.g. `*-fortigate.conf`,
  `*-asa.cfg`, `*-panos.xml`) OR drop it into the legacy per-vendor layout
  (`Pre-requisites/<vendor>/`)." Skip the file and continue — don't block the run.
- **Backward compatibility.** If the engagement still uses the legacy layout with
  `Pre-requisites/<vendor>/` sub-folders (e.g. `engagements/YYYY-MM-DD-<customer-slug>/`),
  the launcher walks those sub-folders automatically and trusts the folder name without
  running the sniff — old engagements keep working unchanged. Report which layout you
  detected in the summary line.

### Step 2 — Validate the scoping questionnaire

- Read `Pre-requisites/scoping-questionnaire.yaml`.
- **Before asking the operator for any missing fields, pre-populate from the dropped configs** (see CLAUDE.md § "extract what you can from the inputs"). In practice:
  - Walk every config file under `Pre-requisites/` (flat layout) OR `Pre-requisites/<vendor>/` (legacy layout). Derive `in_scope_devices` from hostnames (flat list of device-name strings — NOT structured dicts, the renderers crash on dicts).
  - Grep for regulatory-scope hints in address-object names (`PCI-*`, `HIPAA-*`, `CDE-*`, `SOX-*`, `PHI-*`) and pre-populate `regulatory_overlay` accordingly.
  - Derive candidate `in_scope_zones` from region codes in hostnames + zone declarations (`config system zone` on FortiGate / Palo Alto equivalents).
  - Surface the inferred block to the operator in one compact message: "Pulled these from the files: devices = [...], regions = [...], regulatory_overlay = [...]. Confirm or adjust?"
- Ask the operator ONLY for fields that truly couldn't be inferred: `engagement.client` (legal-entity exact spelling + punctuation), `engagement.lead_assessor` (name + cert), any scope override that contradicts what the files suggest.
- If the operator's reply is a terse "go" / "ok" / "proceed" without changes, treat the inferred block as committed and continue — do NOT re-ask for confirmation of each field.

**YAML format reminder:** `in_scope_devices` must be a flat list of name strings (`- "<customer-slug>-us-east-fgtfwa"`), not a list of structured dicts. If rich device metadata is needed, put it under a separate key (e.g. `in_scope_device_details:`) — the PDF/Excel renderers crash on `TypeError: unhashable type: 'dict'` otherwise.

### Step 3 — Parse configs (deterministic)
- Run: `bash -c "cd <engagement-dir> && python3.11 ../../scripts/detect.py ."`
- The script walks `Pre-requisites/` (flat layout, plus any legacy per-vendor sub-folders), runs `_sniff.detect_vendor()` on every file, picks the right parser per vendor, normalizes every rule into `NormalizedRule` schema, runs all 17 detectors at temperature 0, and writes `findings.draft.jsonl`.
- Report the finding count and detectors-fired list in chat.

**Partial-export guard:** after the parse completes, grep each config under `Pre-requisites/` (any depth) for the vendor's policy-block anchor (FortiGate: `^config firewall policy`; PAN-OS: `<rulebase>`; Cisco ASA: `access-list`). If any config has ZERO matches, it is an incomplete export — flag it to the operator immediately with the likely reason and remediation. Common patterns:
  - **FortiGate `config global` only** (multi-VDOM device exported from inside `config global` — policies live under `config vdom / edit <vdom>`, never captured). Fix: re-export with `config global` + `show full-configuration`, then `config vdom` + `edit root` + `show full-configuration`.
  - **Truncated export** (SSH session dropped mid-stream — look for tail-line `"Connection lost. Press Enter to start a new session."`). Fix: re-export with unlimited scrollback and no idle timeout.
  Offer the operator three paths: (1) pause + re-export, (2) proceed with the complete configs and disclose deferred devices in the final report's Limitations section, (3) proceed now + follow-up engagement for deferred. Move deferred configs to `engagement-dir/_deferred/<name>` with a README noting the reason — keep them out of `Pre-requisites/` so the next detect-run doesn't re-hash them into the chain-of-custody.

### Step 4 — Dispatch senior-pentester subagents in parallel
- `N = min(4, number_of_logical_firewalls_detected)`
- Spawn N `senior-pentester` subagents via Task tool. Each gets one firewall's normalized rules + its scope metadata. See `../agents/senior-pentester.md` for the full brief.
- Each returns semantic concerns (edge cases the deterministic detectors can't catch). Merge their outputs into `findings.draft.jsonl` as additional entries with `detector: "senior-pentester-semantic"`.

### Step 5 — Run the validation chain (citation-verifier → CTO → CISO → QA)
Sequence matters. Do NOT parallelize this.

  a. **citation-verifier** (`../agents/citation-verifier.md`) — deterministic. For each draft finding, invoke:
     `bash -c "python3.11 scripts/verify-citation.py <engagement-dir>"`
     Output partitions findings into `findings.verified.jsonl` (passed) and `quarantine.jsonl` (failed). Report quarantine count in chat.

  b. **cto-reviewer** (`../agents/cto-reviewer.md`) — dispatch one subagent per verified finding (or batched in groups of 20 for efficiency). It returns yes/no/uncertain per finding. Route:
       - `yes` → continues to CISO
       - `no`  → moves to `quarantine.jsonl` with CTO's reason
       - `uncertain` → moves to `held.jsonl`

  c. **ciso-reviewer** (`../agents/ciso-reviewer.md`) — batched. Returns approve or severity-adjust. Apply severity updates in place.

  d. **qa-reviewer** (`../agents/qa-reviewer.md`) — final editorial pass. Returns approve or flag. Flagged findings get a `qa_reviewer: "flagged"` annotation but still surface to the operator.

**Hybrid validation path — default for large finding sets (>500):** LLM-CTO on 1500+ citation-verified deterministic findings is wasted token spend — the quoted_rule_text has already been grep-verified against source, and the detector's claim is structural. Use the hybrid split by default when the deterministic set is large:

  - **Automated CTO-yes** for findings where `detector != "senior-pentester-semantic"` AND `citation_verifier == "passed"`. Record `cto_mode: "automated-citation-verified"` and a one-line rationale on each finding. Audit trail is explicit about which findings got AST-reverification vs deterministic corroboration.
  - **LLM-CTO** on senior-pentester-semantic findings ONLY — these are the ones that need business-logic judgment. Dispatch 1 subagent covering the full semantic slice (typically <50 findings, fits in one call).
  - **Automated CISO-approve** when `scoping-questionnaire.regulatory_overlay` applies uniformly across all `in_scope_zones` (no per-asset criticality tagging supplied). The CISO brief explicitly says "if engagement context is incomplete → approve" — so this is faithful, not a shortcut. Record `ciso_mode: "automated-uniform-approve"`.
  - **Automated QA** for framework-version pinning + quote-length sanity (both are deterministic); LLM QA only on the subset that fails the automated checks. Record `qa_mode: "automated-checks"`.

Record each finding's `cto_mode` / `ciso_mode` / `qa_mode` explicitly so the PDF appendix + manifest.json can disclose which findings got human-equivalent LLM review vs automated verification. This is MORE transparent than a uniform LLM stamp, not less.

**Operator-cadence hint during the validation chain:** once the operator has committed to the full-spec or hybrid path (at the start of `/launch` or at the Step 4/5 boundary), DO NOT pause again at every sub-stage to present new option menus. Execute through to the end of Step 5 and report in the Step 6 summary. Reserve further checkpoints for external-state surprises (parser errors, subagent crashes, quarantine-rate anomalies) or destructive actions.

- Final bucket goes to `findings.final.jsonl`.

### Step 6 — Summarize in chat

Print this structure:

```
🚀 Launch complete.

  Inputs parsed:      <vendor>: N files → M rules normalized
                      ...

  Detectors fired:    <counts by detector, sorted desc>

  Validation chain:
    citation-verifier: X passed, Y quarantined
    CTO reviewer:      X approved, Y held, Z rejected
    CISO reviewer:     X severity adjustments applied
    QA reviewer:       X approved, Y flagged

  Final finding set:  N findings ready for review

Next: type /review to triage in chat.
```

## Hard rules
- Detector output is deterministic — never edit or re-order it.
- Never surface a finding whose citation-verifier failed; quarantine is final.
- Held findings (CTO uncertain) are NOT in `findings.final.jsonl` — they await human reviewer in `held/`.
