<!-- ../detectors/rules-no-comments.md -->
---
name: rules-no-comments
description: Flag rules with empty description/comment fields. Single aggregate finding with a 10-rule evidence sample — per-rule findings would flood the report.
---

# Rules No Comments

**Reference implementation:** `fwrr.detectors.rules_no_comments.RulesNoComments` in [firewall-review](https://github.com/ipunithgowda/firewall-review)
**Version pin:** `rules-no-comments:0.1.0`
**Default severity:** Low

## What it checks
Counts rules whose `description` field is empty or whitespace-only. Emits exactly one aggregate finding with the full count, the total rule count, and the first 10 offending rules as evidence. Does NOT run the infrastructure-rule filter — every rule is in scope for hygiene review.

## Why this matters
Rules without comments cannot be traced to a change ticket, a business owner, or an expiry date. This produces long-term audit debt: reviewers cannot confirm business justification, compliance attestation becomes a guessing game, and stale rules accumulate because nobody remembers which service they supported. PCI DSS v4.0.1 §1.2.7 explicitly requires a firewall ruleset review every 6 months with documented business justification — uncommented rules cannot satisfy that control. The recommendation is to enforce a comment-required policy in change management (ticket reference, business owner, creation date, review date) and add a pre-commit hook in the firewall-config pipeline to block comment-less additions.

## Frameworks cited
- PCI DSS v4.0.1 — `1.2.7` (review firewall ruleset at least every 6 months with documented business justification)
- ISO/IEC 27001:2022 — `A.8.22` (segregation of networks — documentation requirement)
- CIS Controls v8.1 — `4.7` (manage default accounts and documentation)

## v0.2 / v0.3 plans
- v0.2: comment-quality heuristic — flag rules whose description exists but is a junk string (e.g. `test`, `tmp`, `asdf`, single-character, or ticket-ID-shaped without business text).
- v0.3: stale-rule detection via comment parse — extract "review date" from comment and surface rules past their review window.
- v0.3: per-rule findings behind a `--verbose-hygiene` flag for teams that want drill-down evidence rather than an aggregate.
