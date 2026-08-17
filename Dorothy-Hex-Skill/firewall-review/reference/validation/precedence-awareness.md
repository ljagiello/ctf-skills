---
name: precedence-awareness
description: Post-detection pass that downgrades findings whose primary affected rule is dead code due to an earlier explicit-deny rule in the same chain. Detectors evaluate rules in isolation and don't know the chain order; this pass reconstructs execution order, finds allow rules whose source/destination/ports are fully covered by an earlier deny in the same (vendor, chain), and one-step-downgrades any finding whose first affected_rule_id matches.
---

# Precedence-Awareness Pass

**Reference implementation:** `fwrr.validation.precedence.apply_precedence_awareness` in [firewall-review](https://github.com/ipunithgowda/firewall-review)
**Version pin:** (see ../VERSIONS.md)

## Role in the pipeline
Runs after `enrich()` (post_process) and before rendering. Mutates the in-memory list of finding dicts in place AND returns the list, so it can chain with other validation passes. Introduced as a CTO-review follow-up on 2026-04-19 to stop shipping high-severity findings on rules that the firewall would never reach.

## What it does
Two algorithmic stages:

**1. Identify shadowed allows (`_shadowed_allow_ids`).** Group `rules` by `(vendor, chain)` where `chain` is extracted from the `scope` string (`chain:<chain-id>` token, lowercased; falls back to the full scope when no chain token is present). Within each group, sort by `(priority or 0, source_lineno or 0)` — same fallback semantics as `shadow_rule.py`. For each allow rule, walk every earlier rule in execution order; if an earlier rule has `action in {"deny", "drop", "reject"}` and its `source` / `destination` / `destination_ports` form a superset of the allow's, mark the allow as shadowed and stop scanning earlier rules for that allow.

**2. Downgrade matching findings (`apply_precedence_awareness`).** For each finding, look at `affected_rule_ids[0]` (the primary rule). If that id is in the shadowed set, apply the `_DOWNGRADE` ladder:

```
Critical -> High
High     -> Medium
Medium   -> Low
Low      -> Info
```

Info and RequiresManualReview are intentionally absent from the ladder — those findings are left alone.

Containment helpers used by the cover check:
- `_set_contains(outer, inner)` — `any` / `0.0.0.0/0` / `::/0` in `outer` covers anything; otherwise every `inner` element must be a subnet (or equal) of some `outer` IP network of the same IP version. `inner` containing `any` / `0.0.0.0/0` / `::/0` returns False (a wildcard can't be covered by specific networks).
- `_ports_contain(outer, inner)` — `any` in outer covers anything; otherwise plain set-subset check.

## Inputs
- `findings: list[dict]` — serialized Finding payload (post-`enrich()`). Reads `affected_rule_ids`, `severity`, `description`. Mutates `severity`, `description`, `confidence`, `validation_status`.
- `rules: list[dict]` — serialized NormalizedRule payload. Reads `vendor`, `scope`, `action`, `priority`, `source_lineno`, `source`, `destination`, `destination_ports`, `rule_id`.

## Outputs
Returns the same `findings` list (mutated). Side effects per shadowed finding:
- `severity` -> next-lower step on the ladder (skipped if already Info / RequiresManualReview / unrecognized).
- `description` -> appended with `_PRECEDENCE_NOTE`: `" [Precedence note: this rule appears unreachable because an earlier deny in the same chain already matches. Severity auto-downgraded.]"` (idempotent — checks the stripped form is not already present).
- `confidence` -> `"Low"`.
- `validation_status` -> `"Needs Review"`.

If `_shadowed_allow_ids` returns an empty set, the function returns immediately with no mutation.

## Gotchas / failure modes
- **Only the first `affected_rule_ids` entry is checked.** A finding affecting multiple rules where only the secondary is shadowed will not be downgraded.
- **Missing rule_id silently dropped.** `_shadowed_allow_ids` only adds shadowed allows when `rid = later.get("rule_id")` is truthy.
- **No IPv4/IPv6 cross-coverage.** `_set_contains` filters outer networks by `o.version == inet.version`, so an IPv6 deny cannot shadow an IPv4 allow (and vice versa).
- **Priority tie-break is line number.** Two rules with the same `priority` are ordered by `source_lineno` — a parser that omits `source_lineno` produces a fallback `0` and unstable shadowing decisions if multiple rules collide.
- **Standalone serialized payload.** This pass operates on dicts, NOT Pydantic models — `_chain_of` is a deliberate mirror of `fwrr.detectors._context.chain_of` for that reason.
- **Idempotent description append.** Re-running the pass won't double-append the precedence note (checks `_PRECEDENCE_NOTE.strip()` substring before appending), but severity will downgrade again — re-running could push Critical -> High -> Medium across two passes.

## When to modify
- **New severity levels:** extend the `_DOWNGRADE` ladder. Decide explicitly whether to downgrade Info or RequiresManualReview — current spec leaves them alone.
- **New deny synonyms:** add to `_DENY_ACTIONS` (currently `{"deny", "drop", "reject"}`).
- **Tighter shadowing:** add protocol matching to `_covers` (today protocol is ignored — a deny on TCP can shadow an allow on UDP).
