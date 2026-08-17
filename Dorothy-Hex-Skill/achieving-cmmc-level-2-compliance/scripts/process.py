#!/usr/bin/env python3
"""
CMMC Level 2 / NIST SP 800-171 Rev 2 SPRS score calculator.

Implements the DoD Assessment Methodology arithmetic: start at 110 and subtract
the weighted value (1, 3, or 5) of each NOT MET requirement, with partial credit
for the small set of requirements that allow it. Reports the SPRS score, the gap
to a perfect 110 and to the 88-point (80%) conditional-certification threshold,
and flags higher-weighted unmet requirements whose POA&M eligibility must be
verified against 32 CFR Part 170.

NOTE: per-requirement point weights are defined by the DoD NIST SP 800-171
Assessment Methodology. Supply each requirement's official weight in the input
(this tool does not invent weights). Use status 'partial' with 'partial_deduction'
only for requirements the methodology allows partial credit on (e.g., 3.5.3 MFA,
3.13.11 FIPS crypto).

Input JSON shape:
{
  "org": {"name": "Acme Defense LLC", "scope": "CUI enclave"},
  "requirements": [
    {"id": "3.1.1",  "family": "3.1", "status": "met",      "weight": 5},
    {"id": "3.5.3",  "family": "3.5", "status": "partial",  "weight": 5, "partial_deduction": 3},
    {"id": "3.3.1",  "family": "3.3", "status": "not_met",  "weight": 5},
    {"id": "3.8.9",  "family": "3.8", "status": "not_met",  "weight": 1},
    {"id": "3.2.1",  "family": "3.2", "status": "na",       "weight": 1}
  ]
}

status: met | not_met | partial | na

Usage:
  python process.py --input controls.json [--output readiness.md]
  python process.py --input controls.json --require-conditional   # exit 1 if score < 88
"""

import argparse
import json
import sys

START_SCORE = 110
CONDITIONAL_THRESHOLD = 88   # 80% of 110
VALID_STATUS = {"met", "not_met", "partial", "na"}
VALID_WEIGHTS = {1, 3, 5}


def compute(data):
    reqs = data.get("requirements", [])
    if not reqs:
        raise ValueError("requirements list is required")

    deductions = 0
    counts = {"met": 0, "not_met": 0, "partial": 0, "na": 0}
    poam_flags = []   # higher-weight unmet -> verify POA&M eligibility
    by_family = {}    # family -> {met,not_met,partial,na}
    detail = []

    for r in reqs:
        rid = r.get("id", "?")
        status = r.get("status")
        weight = r.get("weight")
        if status not in VALID_STATUS:
            raise ValueError(f"{rid}: status '{status}' invalid (met|not_met|partial|na)")
        if status in ("not_met", "partial", "met") and weight not in VALID_WEIGHTS:
            raise ValueError(f"{rid}: weight '{weight}' invalid (must be 1, 3, or 5)")

        fam = r.get("family", rid.rsplit(".", 1)[0])
        fam_rec = by_family.setdefault(fam, {"met": 0, "not_met": 0, "partial": 0, "na": 0})
        fam_rec[status] += 1
        counts[status] += 1

        ded = 0
        if status == "not_met":
            ded = weight
            if weight > 1:
                poam_flags.append((rid, weight))
        elif status == "partial":
            ded = r.get("partial_deduction")
            if ded is None:
                raise ValueError(f"{rid}: status 'partial' requires 'partial_deduction'")
            if ded < 0 or ded > weight:
                raise ValueError(f"{rid}: partial_deduction {ded} out of range (0..{weight})")
            if ded > 1:
                poam_flags.append((rid, ded))
        deductions += ded
        detail.append((rid, fam, status, weight, ded))

    score = START_SCORE - deductions
    return {
        "score": score,
        "deductions": deductions,
        "counts": counts,
        "by_family": by_family,
        "poam_flags": poam_flags,
        "detail": detail,
    }


def render(data, res):
    org = data.get("org", {})
    lines = []
    lines.append(f"# CMMC Level 2 Readiness - {org.get('name','Organization')}")
    lines.append("")
    if org.get("scope"):
        lines.append(f"- **Scope:** {org['scope']}")
    lines.append("")

    score = res["score"]
    lines.append("## SPRS Score (DoD Assessment Methodology)")
    lines.append("")
    lines.append(f"- **Score:** **{score}** / 110  (started at 110, deducted {res['deductions']})")
    lines.append(f"- **Gap to perfect (110):** {110 - score}")
    if score >= CONDITIONAL_THRESHOLD:
        lines.append(f"- **Conditional threshold (>= {CONDITIONAL_THRESHOLD}):** MET "
                     f"(margin {score - CONDITIONAL_THRESHOLD}) - eligible for Conditional status "
                     "if remaining items are POA&M-eligible.")
    else:
        lines.append(f"- **Conditional threshold (>= {CONDITIONAL_THRESHOLD}):** NOT MET "
                     f"(short by {CONDITIONAL_THRESHOLD - score}) - not eligible for Conditional "
                     "certification until the score reaches 88.")
    c = res["counts"]
    lines.append(f"- **Status tally:** met {c['met']}, partial {c['partial']}, "
                 f"not met {c['not_met']}, N/A {c['na']}")
    lines.append("")

    # by family
    lines.append("## Status by family")
    lines.append("")
    lines.append("| Family | Met | Partial | Not Met | N/A |")
    lines.append("|---|---|---|---|---|")
    for fam in sorted(res["by_family"]):
        f = res["by_family"][fam]
        lines.append(f"| {fam} | {f['met']} | {f['partial']} | {f['not_met']} | {f['na']} |")
    lines.append("")

    # POA&M eligibility flags
    lines.append("## POA&M eligibility check")
    lines.append("")
    if not res["poam_flags"]:
        lines.append("No unmet requirement carries more than 1 point of deduction. "
                     "Remaining gaps are most likely POA&M-eligible (still verify against 32 CFR Part 170).")
    else:
        lines.append("The following unmet/partial requirements carry **> 1 point**. The highest-weighted "
                     "security requirements generally **cannot** sit on a POA&M - verify each against "
                     "32 CFR Part 170 before relying on Conditional status:")
        lines.append("")
        lines.append("| Requirement | Points lost |")
        lines.append("|---|---|")
        for rid, w in sorted(res["poam_flags"], key=lambda x: -x[1]):
            lines.append(f"| {rid} | {w} |")
    lines.append("")
    lines.append("> All POA&M items must be closed within **180 days** to convert Conditional -> Final.")

    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser(description="CMMC L2 / NIST 800-171 SPRS score calculator")
    ap.add_argument("--input", "-i", required=True, help="Path to control-status JSON")
    ap.add_argument("--output", "-o", help="Write Markdown readiness report to this path")
    ap.add_argument("--require-conditional", action="store_true",
                    help="Exit non-zero if SPRS score < 88 (conditional threshold)")
    args = ap.parse_args()

    try:
        with open(args.input) as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        print(f"ERROR: could not read input JSON: {e}", file=sys.stderr)
        return 2

    try:
        res = compute(data)
        md = render(data, res)
    except ValueError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 2

    if args.output:
        with open(args.output, "w") as f:
            f.write(md + "\n")
        print(f"Readiness report written to {args.output}", file=sys.stderr)
    else:
        print(md)

    print(f"SPRS score {res['score']}/110 (deductions {res['deductions']}; "
          f"not met {res['counts']['not_met']}, partial {res['counts']['partial']}).",
          file=sys.stderr)

    if args.require_conditional and res["score"] < CONDITIONAL_THRESHOLD:
        print(f"FAIL: score {res['score']} < {CONDITIONAL_THRESHOLD} conditional threshold.",
              file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
