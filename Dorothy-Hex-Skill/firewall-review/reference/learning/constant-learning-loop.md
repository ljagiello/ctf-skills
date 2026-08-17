---
name: Constant learning loop (every engagement feeds the skill catalogue)
description: Every engagement emits learning candidates that improve the skill catalogue — new vendor formats, new detector patterns, new framework controls, new false-positive classes. Curator review promotes to shared assets.
type: process-pattern
---

# Constant learning loop

Every engagement produces **learning candidates** — patterns worth promoting into the shared skill catalogue so the next 1001 auditor runs inherit the improvement. Runs in `/report` phase 3 (after PDF + Excel render).

## What generates a candidate

The existing `scripts/propose-skills.py` surfaces candidates when **≥3 auditors request the same severity adjustment on a given detector**. Extend this to also trigger on:

### Pattern-level triggers (from `feedback.jsonl`)
- `≥3 auditors request_changes same (detector, severity_change)` → severity-rule tune candidate
- `≥3 auditors mark same finding_id class as "other" with reason containing same key term` → new detector candidate
- `≥2 auditors add a framework citation not in the primary list` → citation-catalogue extension

### Pipeline-level triggers (from `held.jsonl` + `quarantine.jsonl`)
- `quarantine reason = "citation_text_mismatch" ≥5% of findings` → parser_raw-text quality regression
- `quarantine reason = "framework_version_unpinned"` → framework-citation regression; patch detector
- `held reason = "detector_mismatch" ≥3 distinct rule_ids` → detector overlap; semantic de-dup opportunity
- `held reason = "secondary_caught_primary_missed" same detector ≥3 engagements` → detector has coverage gap; PROMOTE

### Vendor / format-level triggers (from parser metrics)
- Parser `can_parse` returned False for a file with extension in `{.cfg, .conf}` where content contains `iptables`-like, `nftables`-like, `juniper junos`, `checkpoint`-like, `sonicwall`-like → NEW VENDOR candidate
- Parser normalized a rule but emitted `RequiresManualReview` because a reference was unresolved (dynamic address group, missing SG ref) — `≥5 across engagements` → parser enhancement candidate

### Regulatory / framework-level triggers
- Framework version used is older than the NIST/PCI publication date by `>6 months` — cite-version update candidate
- New framework control appears in ≥2 findings' external research (pentester notes) not in our catalog → catalog extension candidate

## Candidate schema (`.claude/pending/<id>.yaml`)

```yaml
id: LC-2026-04-19-0001
proposal_type: detector_rule_tune | new_detector | new_vendor_parser | citation_correction | persona_prompt_update | framework_catalog_extension
target_skill: detectors/public-source-allow/SKILL.md    # path under the skill catalogue
change_summary: |
  1-sentence what-changes
evidence:
  engagements_seen: 4
  total_findings_affected: 17
  engagement_ids_obscured: [sha256:...]       # NO client-identifying fields
  before_state: "severity=High universally"
  after_state:  "severity=Medium when scope contains zone=dmz AND asset_criticality<high"
test_cases:                                   # golden tests curator MUST add before promoting
  - input: fixture-001.yaml
    expected: finding-severity=Medium
validation_status: proposed                   # proposed | approved | rejected | held
curator_notes: ""
```

## Curator flow (existing slash commands)

- `/pending list` — all open candidates
- `/pending review <id>` — inspect one
- `/pending promote <id>` — creates `learning/<id>` branch; curator applies the proposed skill change, adds golden tests, opens PR
- `/pending reject <id>` with reason
- `/pending hold <id>` — needs more data from future engagements

## Privacy guardrails

Candidates MUST NOT leak client identifiers. Before writing `.claude/pending/<id>.yaml`:
- Replace client name → `sha256:<hash>` engagement ID
- Replace device hostnames → `host_<n>` slot-ids
- Replace IP addresses → RFC1918-safe placeholders (`10.x.y.z`, `172.16.x.y`)
- Replace rule comments → `<redacted-comment>`
- Keep: detector names, severity transitions, framework control IDs, vendor + OS version, pattern shapes

Run `scripts/redact-pending.py` as a final pass before the candidate file hits `.claude/pending/`.

## Observability

Every engagement's learning-loop output is logged to `engagements/<slug>/logs/learning-candidates.json` (local) AND summarized in the report's §9 Limitations (candidate count, without client-identifying detail).

## Upstream sync

Once a candidate is promoted and merged, all running auditors `git pull` the updated `reference/` catalogue catalogue. The skill-set SHA256 in every future `manifest.json` changes, giving the client evidence of catalogue evolution and enabling regulators to audit the audit.
