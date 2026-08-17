---
name: schema
description: Canonical Pydantic data contracts for the entire firewall-review pipeline. Defines NormalizedRule (parser output), Finding (detector output), Evidence, FrameworkRef, ChainOfCustody, Verification, Feedback, and PendingCandidate, plus the closed-set enums (Vendor, Direction, Action, Severity, VerificationState, Confidence, ValidationStatus, FeedbackDecision, CandidateStatus). Every parser emits these models, every detector consumes them, every renderer reads them — schema is the stability contract and any field-level change is a breaking change.
---

# Core Schema

**Reference implementation:** `fwrr.schema` in [firewall-review](https://github.com/ipunithgowda/firewall-review)
**Version pin:** (see ../VERSIONS.md)

## Role in the pipeline
The shared type contract that decouples parsers from detectors from renderers. Every parser in [`lib/fwrr/parsers/`](https://github.com/ipunithgowda/firewall-review/blob/main/lib/fwrr/parsers/) returns `list[NormalizedRule]`. Every detector in [`lib/fwrr/detectors/`](https://github.com/ipunithgowda/firewall-review/blob/main/lib/fwrr/detectors/) consumes `NormalizedRule` and emits `Finding`. The validation and rendering layers operate on the serialized JSONL form of these models. Pydantic v2 with `extra="forbid"` everywhere — unknown fields raise on instantiation.

## What it does
Declares the closed enums and frozen models that every other layer depends on. `extra="forbid"` on every `model_config` means any drift between a parser and a downstream consumer fails loudly at parse time, not silently downstream. Most models are `frozen=True` (immutable post-construction) except `Verification`, `Finding`, and `PendingCandidate` which are mutated by reviewer / enricher passes.

## The data contracts

### `NormalizedRule` (frozen, extra=forbid)
- `rule_id: str`
- `name: str`
- `vendor: Vendor`
- `scope: str` — vendor- and chain-scoping string. Convention: `vendor:<vendor>;chain:<chain-id>` (and additional `;k:v` tokens like `in:lo`, `state:established` for iptables). Parsed by `fwrr.detectors._context.chain_of` and mirrored in `fwrr.validation.precedence._chain_of`.
- `direction: Direction`
- `action: Action`
- `priority: Optional[int] = None` — `None` for AWS SGs (which have no rule order).
- `protocol: str`
- `source: list[str]`
- `source_object_refs: list[str] = []`
- `source_ports: list[str]`
- `destination: list[str]`
- `destination_object_refs: list[str] = []`
- `destination_ports: list[str]`
- `application: list[str] = []`
- `logging: bool = False`
- `description: str = ""`
- `raw: str` — verbatim quoted rule text from the source file (load-bearing for citation-verifier).
- `source_file: str`
- `source_lineno: Optional[int] = None`

### `Finding` (mutable, extra=forbid)
- `id: str`
- `severity: Severity`
- `title: str`
- `detector: str`
- `affected_rule_ids: list[str]`
- `evidence: Evidence`
- `description: str`
- `impact: str`
- `likelihood: str`
- `cvss_v4: Optional[float] = None`
- `framework_refs: list[FrameworkRef] = []`
- `recommendation: str`
- `verification: Verification = Verification()` (default factory)
- `chain_of_custody: ChainOfCustody`
- `confidence: Optional[Confidence] = None` — v0.3 addition. None means `enrich()` will compute it; non-None means an auditor or detector explicitly set it.
- `validation_status: Optional[ValidationStatus] = None` — same v0.3 contract.

### `Evidence` (frozen, extra=forbid)
- `source_file: str`
- `source_lineno: Optional[int]`
- `quoted_rule_text: str` — verbatim from source; the citation-verifier greps for this exact string.
- `input_sha256: str`

### `FrameworkRef` (frozen, extra=forbid)
- `framework: str` (e.g. `"CIS_Controls_v8.1"`, `"NIST_CSF_2.0"`)
- `control_id: str`
- `version: Optional[str] = None`

### `ChainOfCustody` (frozen, extra=forbid)
- `tool_version: str`
- `parser_version: str`
- `detector_version: str`
- `skill_set_hash: str`
- `created_at: datetime`

### `Verification` (mutable, extra=forbid)
Four reviewer-state fields, each `VerificationState` defaulting to `pending`:
- `citation_verifier`, `cto_reviewer`, `ciso_reviewer`, `qa_reviewer`.

### `Feedback` (frozen, extra=forbid)
- `finding_id: str`, `decision: FeedbackDecision`, `reason: str`, `proposed_severity_change: Optional[str] = None`, `auditor: str`, `timestamp: datetime`.

### `PendingCandidate` (mutable, extra=forbid)
- `id: str`, `proposal_type: str` (one of `detector_rule_tune | new_detector | citation_correction | persona_prompt_update`), `target_skill: str`, `change_summary: str`, `evidence: dict`, `test_cases: list[dict]`, `validation_status: CandidateStatus = proposed`, `curator_notes: str = ""`.

## Enums

- `Vendor`: `cisco_asa`, `cisco_ios`, `fortigate`, `panos`, `azure_nsg`, `aws_sg`, `iptables`.
- `Direction`: `inbound`, `outbound`, `both`.
- `Action`: `allow`, `deny`, `reject`, `drop`.
- `Severity`: `Critical`, `High`, `Medium`, `Low`, `Info`, `RequiresManualReview`.
- `VerificationState`: `pending`, `passed`, `failed`, `approved`, `held`, `rejected`, `severity_adjusted`, `flagged`.
- `Confidence`: `High`, `Medium`, `Low`.
- `ValidationStatus`: `Confirmed`, `Needs Review`, `False Positive`.
- `FeedbackDecision`: `approve`, `request_changes`, `other`.
- `CandidateStatus`: `proposed`, `approved`, `rejected`, `held`.

## Field discipline

- **`scope` string format.** Semicolon-separated `key:value` tokens. `vendor:<vendor>;chain:<chain-id>` is the minimum. Additional iptables tokens: `in:<iface>`, `out:<iface>`, `state:<conntrack-state>` — these drive the discarded-FP filter in `compute_discarded_fps`.
- **`raw` is verbatim.** No normalization, no reformatting — citation-verifier greps the source file for this exact string. Trailing whitespace and case must be preserved.
- **`source_file` + `source_lineno` everywhere.** Both `NormalizedRule` and `Evidence` carry them. `source_lineno` is `Optional[int]`; parsers that can't recover line numbers send `None` and downstream sort fallbacks treat that as `0`.
- **`severity` is a closed enum.** Adding `RequiresManualReview` instead of skipping means parsers / detectors NEVER drop ambiguous data — they surface it for human triage.

## Why schema is the stability contract
Every parser emits these models. Every detector consumes them. Every renderer reads them. Every validation pass mutates them. Changing a field is a breaking change across the entire library — parsers, detectors, validators, PDF/Excel/HTML renderers, persisted JSONL fixtures, and any operator-facing tooling that opens those JSONL payloads. Schema changes warrant a version bump in `tool_version` (carried in `ChainOfCustody`) and a migration note for stored engagement artefacts.

## Gotchas / failure modes
- **`extra="forbid"` everywhere.** Dropping an extra key into any model raises `ValidationError`. Useful for catching parser drift; painful when you add a field to a model and forget to update an upstream serializer.
- **Frozen models can't be patched in place.** `NormalizedRule`, `Evidence`, `FrameworkRef`, `ChainOfCustody`, `Feedback` are `frozen=True`. Validation passes that need to mutate work on `dict` form (e.g. `apply_precedence_awareness` operates on serialized JSONL).
- **`Confidence` and `ValidationStatus` defaults are `None`, not the enum.** Detectors that don't explicitly set them rely on `enrich()` to compute the value. A `None` here is meaningful — it means "not yet enriched".
- **`Direction.both` exists.** Detectors that branch on direction must handle three cases, not two.
- **`Vendor` enum uses underscores** (`cisco_asa`), but the sniff module returns hyphenated keys (`cisco-asa`). The parser-routing layer in `launch.py` is responsible for translating between the two.

## When to modify
- **New vendor:** add to `Vendor` enum, add a parser in [`lib/fwrr/parsers/`](https://github.com/ipunithgowda/firewall-review/blob/main/lib/fwrr/parsers/), register a sniff signature in `_sniff.py`, route in `launch.py`.
- **New severity:** add to `Severity`, update `_DOWNGRADE` ladder in `precedence.py`, update branch tables in `post_process.py`, audit every renderer's color palette mapping.
- **New finding field:** add to `Finding`, update every detector that emits findings, update `enrich()` if it should be auto-computed, update `excel.py` / `pdf.py` / `report.html.j2` to surface it. Bump `tool_version`.
- **New framework:** no schema change — `FrameworkRef.framework` is a free-form string. Pin the version in the citation.
