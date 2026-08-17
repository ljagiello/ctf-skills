#!/usr/bin/env python3
"""
NIST RMF helper: FIPS 199 categorization -> SP 800-53B baseline selection,
control-implementation status summary, and POA&M generation from findings.

Input JSON shape:
{
  "system": {"name": "Customer Portal", "ao": "Jane Roe"},
  "information_types": [
    {"name": "PII", "confidentiality": "Moderate", "integrity": "Moderate", "availability": "Low"},
    {"name": "Authentication data", "confidentiality": "High", "integrity": "High", "availability": "Moderate"}
  ],
  "implementation": {                 # OPTIONAL: per-family implemented/total counts
    "AC": {"implemented": 20, "total": 25},
    "AU": {"implemented": 10, "total": 16}
  },
  "findings": [                       # OPTIONAL: assessor findings -> POA&M
    {
      "id": "F-001", "control": "AC-7", "weakness": "No account lockout on portal",
      "severity": "High", "status": "Other Than Satisfied",
      "remediation": "Configure lockout after 5 failed attempts",
      "owner": "App team", "milestone": "2026-07-15"
    }
  ]
}

Categorization rule (FIPS 199): overall impact = high-water mark across all
information types and all three objectives (C, I, A).

Usage:
  python process.py --input system.json [--output package.md]
  python process.py --input system.json --fail-open-high   # exit 1 if any High finding open
"""

import argparse
import json
import sys

IMPACT = ["Low", "Moderate", "High"]
IMPACT_RANK = {v: i for i, v in enumerate(IMPACT)}
SEVERITY_RANK = {"Low": 0, "Moderate": 1, "Medium": 1, "High": 2, "Critical": 3}

# Indicative SP 800-53B baseline control counts by impact level.
# (Approximate; the authoritative counts live in SP 800-53B. Used here to
#  communicate relative baseline size, not as a substitute for the catalog.)
BASELINE_SIZE = {"Low": "~150 controls", "Moderate": "~260 controls", "High": "~340 controls"}


def categorize(info_types):
    """Return (overall, per_objective_high) using the FIPS 199 high-water mark."""
    highs = {"confidentiality": "Low", "integrity": "Low", "availability": "Low"}
    for it in info_types:
        for obj in highs:
            val = it.get(obj, "Low")
            if val not in IMPACT_RANK:
                raise ValueError(f"information type '{it.get('name','?')}' has invalid {obj} '{val}'")
            if IMPACT_RANK[val] > IMPACT_RANK[highs[obj]]:
                highs[obj] = val
    overall = max(highs.values(), key=lambda v: IMPACT_RANK[v])
    return overall, highs


def render(data):
    sysmeta = data.get("system", {})
    info_types = data.get("information_types", [])
    if not info_types:
        raise ValueError("information_types is required to categorize the system")

    overall, highs = categorize(info_types)

    lines = []
    lines.append(f"# Authorization Package Summary - {sysmeta.get('name','System')}")
    lines.append("")
    if sysmeta.get("ao"):
        lines.append(f"- **Authorizing Official:** {sysmeta['ao']}")
    lines.append("")

    # categorization
    lines.append("## FIPS 199 Categorization")
    lines.append("")
    lines.append("| Objective | High-water mark |")
    lines.append("|---|---|")
    lines.append(f"| Confidentiality | {highs['confidentiality']} |")
    lines.append(f"| Integrity | {highs['integrity']} |")
    lines.append(f"| Availability | {highs['availability']} |")
    lines.append(f"| **Overall system impact** | **{overall}** |")
    lines.append("")
    lines.append(f"**Selected SP 800-53B baseline:** {overall} ({BASELINE_SIZE[overall]}). "
                 "Tailor from this baseline; document scoping, compensating controls, and "
                 "organization-defined parameter values in the SSP.")
    lines.append("")

    lines.append("### Information types")
    lines.append("")
    lines.append("| Information type | C | I | A |")
    lines.append("|---|---|---|---|")
    for it in info_types:
        lines.append(f"| {it.get('name','-')} | {it.get('confidentiality','-')} "
                     f"| {it.get('integrity','-')} | {it.get('availability','-')} |")
    lines.append("")

    # implementation status
    impl = data.get("implementation")
    if impl:
        lines.append("## Control Implementation Status (by family)")
        lines.append("")
        lines.append("| Family | Implemented | Total | % |")
        lines.append("|---|---|---|---|")
        tot_i = tot_t = 0
        for fam, c in sorted(impl.items()):
            i, t = c.get("implemented", 0), c.get("total", 0)
            tot_i += i
            tot_t += t
            pct = f"{(100*i/t):.0f}%" if t else "-"
            lines.append(f"| {fam} | {i} | {t} | {pct} |")
        overall_pct = f"{(100*tot_i/tot_t):.0f}%" if tot_t else "-"
        lines.append(f"| **Total** | **{tot_i}** | **{tot_t}** | **{overall_pct}** |")
        lines.append("")

    # POA&M
    findings = data.get("findings", [])
    open_high = []
    if findings:
        findings_sorted = sorted(
            findings,
            key=lambda f: SEVERITY_RANK.get(f.get("severity", "Low"), 0),
            reverse=True,
        )
        lines.append("## Plan of Action & Milestones (POA&M)")
        lines.append("")
        lines.append("| ID | Control | Weakness | Severity | Status | Remediation | Owner | Milestone |")
        lines.append("|---|---|---|---|---|---|---|---|")
        for f in findings_sorted:
            sev = f.get("severity", "-")
            status = f.get("status", "-")
            is_open = status.strip().lower() != "satisfied"
            is_high = SEVERITY_RANK.get(sev, 0) >= SEVERITY_RANK["High"]
            if is_open and is_high:
                open_high.append(f)
            lines.append("| {id} | {ctl} | {wk} | {sev} | {st} | {rem} | {own} | {ms} |".format(
                id=f.get("id", "-"), ctl=f.get("control", "-"), wk=f.get("weakness", "-"),
                sev=sev, st=status, rem=f.get("remediation", "-"),
                own=f.get("owner", "-"), ms=f.get("milestone", "-"),
            ))
        lines.append("")
        lines.append(f"_Open High/Critical findings: {len(open_high)}_")
        lines.append("")

    # decision scaffold
    lines.append("## Authorization Decision (to be completed by the AO)")
    lines.append("")
    lines.append("- **Decision:** [ ATO | cATO | DATO ]")
    lines.append("- **Term / conditions:** ____")
    lines.append("- **Residual-risk statement:** ____")
    lines.append(f"- **Authorizing Official:** {sysmeta.get('ao','____')}")

    return "\n".join(lines), overall, open_high


def main():
    ap = argparse.ArgumentParser(description="NIST RMF baseline selector + POA&M generator")
    ap.add_argument("--input", "-i", required=True, help="Path to system JSON")
    ap.add_argument("--output", "-o", help="Write Markdown package summary to this path")
    ap.add_argument("--fail-open-high", action="store_true",
                    help="Exit non-zero if any High/Critical finding remains open")
    args = ap.parse_args()

    try:
        with open(args.input) as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        print(f"ERROR: could not read input JSON: {e}", file=sys.stderr)
        return 2

    try:
        md, overall, open_high = render(data)
    except ValueError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 2

    if args.output:
        with open(args.output, "w") as f:
            f.write(md + "\n")
        print(f"Package summary written to {args.output}", file=sys.stderr)
    else:
        print(md)

    print(f"Overall categorization: {overall}. Open High/Critical findings: {len(open_high)}.",
          file=sys.stderr)

    if args.fail_open_high and open_high:
        ids = ", ".join(f.get("id", "?") for f in open_high)
        print(f"FAIL: {len(open_high)} open High/Critical finding(s): {ids}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
