---
name: applicability
description: How to determine which conditional Security Objectives and Modules of PCI SSS v2.0 apply to a given application — the closed 7-key AppContext questionnaire, the evidence each answer requires (excluding a module demands negative evidence), and how applicability.py deterministically filters the catalog to the applicable Test Requirement set. Read this during the workflow's Applicability phase before computing the work-list.
---

# Applicability — scoping the assessment

Core (Security Objectives 1–11) applies to **all** software in scope. Whether the conditional objectives and the Modules apply is decided by the **AppContext** — seven booleans. `tools/pci-sss/applicability.py` evaluates each catalog row's `applicability` predicate against this context; nothing is decided by an LLM at filter time.

## The closed AppContext (seven keys)

| key | true when… | drives |
|---|---|---|
| `account_data` | the software stores, processes, or transmits PAN and/or SAD (cardholder data per PCI DSS) | **Module A** |
| `sensitive_mode` | the software has sensitive functionality that meets the definition of a *sensitive mode of operation* (privileged/administrative state gated by authentication) | **Security Objective 4** |
| `random_for_sensitive_assets` | the software generates or consumes random values in association with sensitive assets (keys, tokens, nonces, IVs, session IDs) | **Security Objective 7** |
| `pts_poi_device` | the software is intended for deployment/execution on a PTS POI payment-terminal device | **Module B** |
| `public_network_interface` | the software exposes an interface reachable over a public network (web/API endpoint) | **Module C** |
| `is_sdk` | the software is delivered as a software development kit for integration into other applications | **Module D** |
| `sred_approved` | (only meaningful with `pts_poi_device`) the device's hardware/firmware is approved to SRED | **Module B branch** B2-1 (SRED) vs B2-2 (non-SRED) |

Missing keys default to **false** (conservative: an unproven condition does not pull in its conditional requirements — but core always applies).

## Answering each key — evidence required

Each AppContext answer is itself evidence-bound. Record the answer **and** what established it in `applicability/<scope_unit>.md`.

- **Setting a key TRUE** is supported by positive evidence: a code path, a config, a data-flow, or a documentation statement (e.g. a PAN-handling function, a public route table, an `sdk/` build target).
- **Setting a key FALSE (excluding a Module / conditional objective)** requires **negative evidence** — the search you ran that returned nothing, with the exact pattern. Examples:
  - exclude Module A: PAN regex (e.g. `\b[3-6][0-9]{12,18}\b`), SAD/track-data/CVV/PIN-block patterns, and crypto-of-card-data all return no matches across `source_paths`, and `declared_assets` lists no PAN/SAD.
  - exclude SO 7: no RNG/`random`/`secrets`/`crypto.randomBytes`/key-generation call sites tied to sensitive assets.
  - exclude Module C: no HTTP server / route registration / public listener in the codebase or deployment docs.
  An operator hint of "not applicable" is **not** sufficient on its own. When the evidence is ambiguous, default the key to **true** (assess conservatively) — over-scoping costs effort; under-scoping hides a gap.

## Predicate grammar (what the catalog encodes)

Each catalog row carries an `applicability` AST over these keys (see [schema.md §2](schema.md)): leaf `{"ctx":"<key>","eq":<bool>}`; combinators `{"all":[…]}`, `{"any":[…]}`, `{"not":<node>}`; literal `{"always":true}` for core rows. A row is applicable iff its predicate is true under the AppContext. The Module B SRED branch is encoded as two mutually-exclusive rows — B2-1 with `sred_approved:false` and B2-2 with `sred_approved:true`.

## Computing the work-list

```
python3 tools/pci-sss/applicability.py \
  --context '{"account_data":true,"public_network_interface":true,"random_for_sensitive_assets":true}' \
  --out-dir <engagement_dir> [--running-instance]
```
Writes `<engagement_dir>/applicability/{applicable.jsonl, not-applicable.jsonl, work-list.json}`. `--running-instance` marks dynamic Test Requirements as executable; without it they carry `dynamic_blocked:true` and the workflow records them `REQUIRES_MANUAL_REVIEW`.

## Anti-Patterns
- Excluding a Module from an operator hint alone, with no negative-evidence search recorded.
- Defaulting an ambiguous condition to *not applicable* — ambiguity resolves toward applicable.
- Marking `account_data:false` without grepping the codebase for PAN/SAD patterns first.

## See also
- [schema.md](schema.md) — the AppContext and predicate contracts.
- [../catalog/INDEX.md](../catalog/INDEX.md) — the catalog the predicates live in.
- [../anti-hallucination/coverage-gate.md](../anti-hallucination/coverage-gate.md) — why every applicable row must get a verdict.
