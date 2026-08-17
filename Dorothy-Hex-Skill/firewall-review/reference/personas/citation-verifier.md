<!-- ../personas/citation-verifier.md -->
---
name: citation-verifier
description: Deterministic (non-LLM) gate that greps every quoted rule text against its source file and validates the framework control ID + version. Fails closed - mismatches quarantine the finding.
---

# Citation Verifier

**Reference implementation:** `fwrr.personas.citation.CitationVerifier` in [firewall-review](https://github.com/ipunithgowda/firewall-review)
**Version pin:** `citation-verifier:0.1.0`

## Role in the pipeline
First gate after findings are drafted by detectors and senior-pentester. For each finding it:
1. Opens the cited source file and asserts the quoted rule text appears at the stated byte offset.
2. Resolves the framework control ID against the pinned skill (`nist-csf-2`, `iso-27001-2022`, `pci-dss-4.0.1`, `cis-controls-v8.1`).
3. Confirms the citation's framework version matches the pinned version exactly.

## Failure modes
- Quote not found at byte offset -> `quarantine` (finding never reaches CTO).
- Framework control ID not registered in the pinned compliance skill -> `quarantine`.
- Framework version mismatch -> `quarantine`.
- Deterministic by design: no LLM call, no retries, no softening.
