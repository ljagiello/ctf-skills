---
name: post-process-enrich
description: Post-detection enrichment that assigns Confidence (High/Medium/Low) and Validation Status (Confirmed/Needs Review) to every Finding based on detector class and severity context. Also computes the discarded-FP list from infrastructure rules (loopback, stateful return-traffic) for transparent client disclosure. Operates on serialized finding dicts; preserves auditor hand-edits by default.
---

# Post-Process Enrich

**Reference implementation:** `fwrr.validation.post_process.enrich` in [firewall-review](https://github.com/ipunithgowda/firewall-review) (and `compute_discarded_fps`)
**Version pin:** (see ../VERSIONS.md)

## Role in the pipeline
Runs between detection and rendering. Does not modify detector logic — operates on the serialized JSONL finding payload. Called before `apply_precedence_awareness` (precedence pass relies on the confidence/validation values that enrich sets). `compute_discarded_fps` is consumed by the Excel renderer to populate the dedicated "False Positives (Discarded)" sheet.

## What it does
Three functions:

**1. `assign_confidence(finding) -> "High" | "Medium" | "Low"`.** Branching:
- `severity == "RequiresManualReview"` -> `"Low"` (we lack the evidence to be confident).
- detector in `_EXPLICIT_DETECTORS` -> `"High"` if severity in `("Critical", "High")` else `"Medium"`. Special case for `public-source-allow`: if the evidence text contains `"0.0.0.0/0"` or `"::/0"`, return `"High"` regardless of severity.
- detector in `_HEURISTIC_DETECTORS` -> `"Medium"` if severity in `("Critical", "High")` else `"Low"`.
- detector == `"any-any-broadness"` (special middle-ground): `"High"` if `evidence.count("any") >= 2` or `"0.0.0.0/0"` in evidence, else `"Medium"`.
- fallback -> `"Medium"`.

`_HEURISTIC_DETECTORS` (default Medium): `senior-pentester-semantic`, `allow-icmp`, `allow-any-protocol`, `unused-rule`, `port-range-too-broad`, `rules-no-comments`.
`_EXPLICIT_DETECTORS` (default High when sev is Critical/High): `public-source-allow`, `admin-services-exposure`, `cleartext-service`, `risky-service`, `rules-end-with-drop-all-and-log`, `default-deny-presence`, `shadow-rule`, `duplicate-rule`, `contradicting-rule`.

**2. `assign_validation_status(finding) -> "Confirmed" | "Needs Review" | "False Positive"`.**
- `severity == "RequiresManualReview"` -> `"Needs Review"`.
- `confidence == "Low"` -> `"Needs Review"`.
- otherwise -> `"Confirmed"`.

(`"False Positive"` is in the return-type contract but not produced by this function — it's the manual override path.)

**3. `enrich(findings, *, preserve_overrides=True)`.** Walks each finding. For each of `confidence` and `validation_status`: if `preserve_overrides` is True (default) AND the field is already present and truthy, skip; otherwise recompute. Returns the same list (mutated in place).

**4. `compute_discarded_fps(rules) -> list[dict]`.** Walks `rules` and returns dicts for the ones the infrastructure-rule sanity filter discarded. Today only iptables-shaped scopes are recognized:
- scope contains `in:lo` or `out:lo` -> reason: "Loopback interface — local-only traffic..."
- scope contains `state:established` / `state:related` / `conntrack:established` -> reason: "Stateful return-traffic rule — permits responses to flows already approved..."

Each result dict has keys: `rule_id`, `reason`, `quoted_rule_text` (from `r["raw"]`), `source_lineno`.

## Inputs
- `enrich(findings, *, preserve_overrides=True)`: `findings: list[dict]` (mutated), keyword-only `preserve_overrides: bool`.
- `compute_discarded_fps(rules)`: `rules: list[dict]` — serialized NormalizedRule payload.

Reads from each finding: `severity`, `detector`, `evidence.quoted_rule_text`, `confidence`, `validation_status`. Writes to: `confidence`, `validation_status`.

## Outputs
- `enrich` -> same list, mutated. Each finding gets `confidence` (string) and `validation_status` (string).
- `compute_discarded_fps` -> list of `{rule_id, reason, quoted_rule_text, source_lineno}` dicts.

## Gotchas / failure modes
- **`preserve_overrides=True` is sticky.** Any finding that already carries a truthy `confidence` value (e.g. from a detector that explicitly set it, or a prior render an auditor hand-edited) is NOT recomputed. Pass `preserve_overrides=False` to force recomputation — useful after detector-version upgrades when historical scores are stale.
- **Detector list drift.** `_EXPLICIT_DETECTORS` and `_HEURISTIC_DETECTORS` are hard-coded — a new detector that isn't registered in either set falls into the `"Medium"` fallback regardless of how confident its evidence is.
- **`any-any-broadness` count semantics.** `evidence.count("any")` counts substring occurrences, not token occurrences — `"company"` would count once. In practice the quoted rule text rarely contains `"any"` outside the field values, but it's a substring check, not tokenized.
- **`compute_discarded_fps` is iptables-only today.** Other vendors don't write `in:lo` / `state:established` into their scope strings, so their loopback / control-plane filtering is not surfaced on the disclosed-FP sheet.
- **`assign_validation_status` defaults `confidence` to `"High"`.** If a finding lacks the field entirely when this function is called directly (e.g. before enrich), it will return `"Confirmed"` — caller order matters.

## When to modify
- **New detector:** decide if it's explicit-signal or heuristic and add to the matching set. If neither fits cleanly, mirror the `any-any-broadness` middle-ground branch.
- **New severity bucket:** update both branch tables in `assign_confidence` and the early-return in `assign_validation_status`.
- **New infra-rule shape:** add a scope-substring branch to `compute_discarded_fps`. Keep the reason text client-readable — it lands in the report verbatim.
