---
name: schema
description: Canonical data contracts for the pci-secure-software pipeline — the catalog entry (CatalogTestRequirement), the assessment context (AppContext), and the per-requirement output (RequirementVerdict) with Evidence, ControlRef, Remediation, ChainOfCustody, plus the closed-set enums (VerdictStatus, TestMethod, AnalysisType, Polarity, Module, EvidenceType). The catalog producer emits CatalogTestRequirement, the workflow assessor/verdict agents emit RequirementVerdict, the deterministic tools (validate_catalog.py, applicability.py, citation_verify.py, aggregate.py, coverage_gate.py) read/write these shapes. Any field-level change is a breaking change.
---

# Core Schema

The stable type contract that decouples the catalog (source of truth) from the workflow (assessment) from the tools (deterministic gates) from the report. JSON throughout. A change to any field name here ripples to `.claude/workflows/pci-compliance.js`, every `tools/pci-sss/*.py`, and `formats/transilience-report-style/compliance-report.md`.

## 1. `CatalogTestRequirement` (one per lettered Test Requirement; the deterministic enumeration source)

| field | type | rule |
|---|---|---|
| `id` | str | atomic lettered ID, regex `^([0-9]{1,2}|[A-D][0-9])-[0-9]+(\.[0-9]+){0,2}\.[a-z]$` (e.g. `1-3.c`, `4-1.7.6.c`, `C2-1.d`, `A1-1.a`); unique |
| `module` | enum | `core` \| `A` \| `B` \| `C` \| `D` |
| `objective` | str | `"1"`..`"11"`, `"A1"`, `"B1"`-`"B3"`, `"C1"`-`"C4"`, `"D1"` |
| `objective_title` | str | **verbatim** PDF/TOC title |
| `requirement_id` | str | parent Security Requirement, e.g. `1-3`, `4-1.7.6`, `C2-1` — the rollup grouping key |
| `requirement_text` | str | **verbatim** parent requirement text |
| `test_requirement_text` | str | **verbatim** lettered text — the citation-verifier's anchor and the assessor's brief |
| `test_method` | enum `TestMethod` | first keyword of the test text |
| `analysis_type` | enum `AnalysisType` | how the requirement is evaluated |
| `polarity` | enum `Polarity` | `negative` iff text matches *attempt(ing)? to (violate|bypass|circumvent)* |
| `applicability` | object | boolean-AST over the closed `AppContext` keys (§2); evaluated only by `applicability.py` |
| `cross_refs` | str[] | parsed "Leverage information from X" / "accounted for in Z" → `requirement_id`s or `id`s |
| `guidance` | str | verbatim guidance/implementation/testing note text (may be `""`) |
| `printed_page` | int | the printed footer page |
| `pdf_page` | int | 1-based PDF page (for `Read pages=`); `pdf_page == printed_page + meta.page_offset` |

The catalog file also carries a `meta` block: `framework`, `version`, `source_document`, `source_sha256`, `page_offset`, `objectives{core,A,B,C,D}`, `test_requirement_count`, `catalog_schema_version`, `disclaimer`.

## 2. `AppContext` — the closed applicability vocabulary (booleans, captured at Intake)

Exactly seven keys; `applicability.py` rejects any other `ctx` key:
`account_data`, `sensitive_mode`, `random_for_sensitive_assets`, `pts_poi_device`, `public_network_interface`, `is_sdk`, `sred_approved`.

**Applicability AST grammar** (closed): leaf `{"ctx":"<key>","eq":<bool>}`; combinators `{"all":[...]}`, `{"any":[...]}`, `{"not":<node>}`; literal `{"always":true}` for core-baseline rows. A row is applicable iff its predicate evaluates true under `AppContext`. Examples: core `{"always":true}`; Module A `{"all":[{"ctx":"account_data","eq":true}]}`; SO4 `{"all":[{"ctx":"sensitive_mode","eq":true}]}`; SO7 `{"all":[{"ctx":"random_for_sensitive_assets","eq":true}]}`; Module B SRED branch B2-2 `{"all":[{"ctx":"pts_poi_device","eq":true},{"ctx":"sred_approved","eq":true}]}` and non-SRED B2-1 `{"all":[{"ctx":"pts_poi_device","eq":true},{"ctx":"sred_approved","eq":false}]}`.

## 3. `RequirementVerdict` (one per applicable Test Requirement; the assessment output)

| field | type | rule |
|---|---|---|
| `test_requirement_id` | str | the catalog `id` |
| `status` | enum `VerdictStatus` | see invariants below |
| `evidence` | `Evidence[]` | MET/NOT_MET ⇒ length ≥ 1 |
| `applicability_evidence` | `Evidence[]` | NOT_APPLICABLE ⇒ length ≥ 1 (the search that returned nothing) |
| `analysis_performed` | `AnalysisType[]` | which of static/dynamic/documentation actually ran |
| `why` | str | the rationale shown in the report |
| `remediation` | `Remediation` \| null | required for NOT_MET / PARTIALLY_MET |
| `control_ref` | `ControlRef` | resolved by citation_verify.py against the pinned catalog |
| `verification` | `Verification` | citation_verifier / refutation_validator states |
| `downgraded_from` | str \| null | set when a MET/NOT_MET was downgraded to REQUIRES_MANUAL_REVIEW |
| `votes` | int | number of adversarial refuters run |
| `refuted_count` | int | refuters that returned `refuted:true` |
| `citation_verified` | bool | set true by citation_verify.py on a passing grep |
| `proof_dir` | str | `findings/<id>/evidence/` |
| `chain_of_custody` | `ChainOfCustody` | pins the catalog that produced the verdict |

### `VerdictStatus` enum
`MET` | `NOT_MET` | `PARTIALLY_MET` | `NOT_APPLICABLE` | `REQUIRES_MANUAL_REVIEW`

### Status invariants (the anti-hallucination core — enforced in citation_verify.py + the verdict agent)
- `MET` ⇒ `len(evidence) ≥ 1`. `NOT_MET` ⇒ `len(evidence) ≥ 1` (a negative finding must cite the gap location — the doc that omits it or the code path that lacks the control).
- `NOT_APPLICABLE` ⇒ `len(applicability_evidence) ≥ 1` and the row's predicate evaluated false.
- A row whose `analysis_type` is `dynamic` (or `static-and-or-dynamic` driven by Perform/Test) when dynamic analysis did not run (`"dynamic" not in analysis_performed`) ⇒ `REQUIRES_MANUAL_REVIEW`, never `MET`.
- `REQUIRES_MANUAL_REVIEW` is the only status allowed with zero evidence; it requires a one-line `why`.
- A proposed `MET`/`NOT_MET` with any refuter `citation_doubt`, or `refuted_count ≥ floor(votes/2)+1`, is downgraded to `REQUIRES_MANUAL_REVIEW` (`downgraded_from` set).

## 4. `Evidence` (immutable; the citation-verifier's grep target)
| field | type | rule |
|---|---|---|
| `source_file` | str | path to the app's source/doc file |
| `source_lineno` | int \| null | 1-based; null only when the whole file is the evidence |
| `quoted_text` | str | **verbatim** from `source_file` at `source_lineno ±5`; citation_verify.py greps this (ws-normalized) |
| `sha256` | str | sha256 of `source_file` contents at assessment time |
| `evidence_type` | enum `EvidenceType` | `source_code` \| `documentation` \| `build_artifact` \| `dynamic_observation` |

## 5. `ControlRef` (immutable)
`framework:"PCI_SSS_v2.0"`, `test_requirement_id`, `requirement_id`, `objective`, `version:"2.0"`. citation_verify.py resolves `test_requirement_id` against the pinned catalog; a missing id or wrong framework/version quarantines the verdict.

## 6. `Remediation`
`summary` (str), `detail` (str), `references` (str[] of objective/requirement IDs), `effort` (enum `Low`|`Medium`|`High`).

## 7. `Verification` (mutable)
`citation_verifier` and `refutation_validator`, each `VerificationState` ∈ `pending`|`passed`|`failed`, default `pending`.

## 8. `ChainOfCustody` (immutable)
`tool_version`, `catalog_version`, `catalog_sha256`, `skill_set_hash`, `created_at` (ISO-8601, from `date -u`).

## 9. Other enums
- `TestMethod`: `Examine` | `Interview` | `Observe` | `Perform` | `Test` | `Verify`.
- `AnalysisType`: `documentation-only` | `static` | `dynamic` | `static-and-or-dynamic` | `research`.
- `Polarity`: `positive` | `negative`.
- `Module`: `core` | `A` | `B` | `C` | `D`.
- `EvidenceType`: `source_code` | `documentation` | `build_artifact` | `dynamic_observation`.

## 10. Rollup (deterministic, in `aggregate.py`)
Group applicable verdicts by `requirement_id`, then ladder up to objective and module:
- all children `MET` (or `NOT_APPLICABLE` with ≥1 `MET`) ⇒ `MET`
- all children `NOT_MET` ⇒ `NOT_MET`
- any `REQUIRES_MANUAL_REVIEW` present and no `NOT_MET` ⇒ `REQUIRES_MANUAL_REVIEW`
- mix of `MET` and `NOT_MET` ⇒ `PARTIALLY_MET`
- all children `NOT_APPLICABLE` ⇒ `NOT_APPLICABLE`

## Field discipline
- `quoted_text` is **verbatim** — no reformatting; citation_verify.py greps the source for it (whitespace-normalized within `source_lineno ±5`). Re-wording a quote to make it match is a quarantine, not a fix.
- `REQUIRES_MANUAL_REVIEW` is a first-class outcome, never a silent drop — it is how the pipeline stays honest about what it could not prove (dynamic-not-run, ambiguous evidence, quarantined citation).
- Catalog text fields are verbatim from the PDF; `validate_catalog.py` + the spot-check enforce fidelity.

## See also
- [applicability.md](applicability.md) — the AppContext questionnaire and predicate evaluation.
- [../anti-hallucination/control-stack.md](../anti-hallucination/control-stack.md) — where each invariant is enforced.
- [../catalog/INDEX.md](../catalog/INDEX.md) — the catalog file and counts.
