<!-- ../reporting/report-writer-pdf.md -->
---
name: report-writer-pdf
description: Renders the audit-grade PDF deliverable from approved findings + engagement metadata. Deterministic Jinja2 + WeasyPrint pipeline; all LLM narrative framing is frozen upstream.
---

# Report Writer (PDF)

**Reference implementation:** `fwrr.reporting.pdf.PDFReportWriter` in [firewall-review](https://github.com/ipunithgowda/firewall-review)
**Version pin:** `report-writer-pdf:0.1.0`

## Role in the pipeline
Runs during `fwrr report <engagement-dir>`. Consumes `findings.final.jsonl` + engagement metadata, renders the 10-section audit PDF via Jinja2 templates, and writes `deliverables/report.pdf`. The PDF embeds the chain-of-custody manifest (tool / parser / detector / skill-set hash + input SHA256) on every page footer.

## Failure modes
- Approved finding missing a framework citation -> render aborts; auditor must re-run review.
- Template render error -> partial PDF NOT written; custody.jsonl records `pdf_render_aborted`.
- WeasyPrint font fallback used -> warning logged; PDF still emitted (deterministic output is priority over typography).
