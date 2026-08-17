#!/usr/bin/env python3
"""
HIPAA Security Rule safeguard gap-assessment scorer.

Scores a safeguard-status inventory across the Administrative (164.308),
Physical (164.310), and Technical (164.312) safeguards. Required gaps are
weighted above addressable gaps, and any gap in the Risk Analysis or Risk
Management specifications is escalated (these are the most-cited OCR findings).
Emits a gap table, a weighted readiness score, and a prioritized remediation list.

Input JSON shape:
{
  "org": {"name": "Northstar Clinic", "role": "Covered Entity"},
  "safeguards": [
    {
      "id": "164.308(a)(1)(ii)(A)", "section": "308",
      "name": "Risk Analysis", "requirement": "required",
      "status": "gap"
    },
    {
      "id": "164.312(a)(2)(iv)", "section": "312",
      "name": "Encryption and Decryption", "requirement": "addressable",
      "status": "partial",
      "alternative_documented": false
    }
  ]
}

requirement: required | addressable
status: implemented | partial | gap

Usage:
  python process.py --input safeguards.json [--output gap.md]
  python process.py --input safeguards.json --fail-on-required-gap
"""

import argparse
import json
import sys

SECTION_NAMES = {
    "308": "Administrative (§164.308)",
    "310": "Physical (§164.310)",
    "312": "Technical (§164.312)",
}
VALID_REQ = {"required", "addressable"}
VALID_STATUS = {"implemented", "partial", "gap"}

# status -> credit fraction toward "implemented"
CREDIT = {"implemented": 1.0, "partial": 0.5, "gap": 0.0}
# weighting: required safeguards count more toward the score
WEIGHT = {"required": 2, "addressable": 1}

# Specifications whose absence OCR cites most often -> escalate
HIGH_PRIORITY_KEYS = ("risk analysis", "risk management")


def score(data):
    sgs = data.get("safeguards", [])
    if not sgs:
        raise ValueError("safeguards list is required")

    total_weight = 0.0
    earned_weight = 0.0
    required_gaps = []
    addressable_gaps = []
    escalated = []
    by_section = {}
    rows = []

    for s in sgs:
        sid = s.get("id", "?")
        req = s.get("requirement")
        status = s.get("status")
        if req not in VALID_REQ:
            raise ValueError(f"{sid}: requirement '{req}' invalid (required|addressable)")
        if status not in VALID_STATUS:
            raise ValueError(f"{sid}: status '{status}' invalid (implemented|partial|gap)")

        section = str(s.get("section", "")).replace("164.", "").strip()
        sec_rec = by_section.setdefault(section, {"implemented": 0, "partial": 0, "gap": 0})
        sec_rec[status] += 1

        w = WEIGHT[req]
        total_weight += w
        earned_weight += w * CREDIT[status]

        name = s.get("name", "")
        is_high = any(k in name.lower() for k in HIGH_PRIORITY_KEYS)

        # an addressable item with a documented equivalent alternative is acceptable
        addressable_ok = (
            req == "addressable"
            and status != "implemented"
            and s.get("alternative_documented") is True
        )

        if status in ("gap", "partial") and not addressable_ok:
            if req == "required":
                required_gaps.append(s)
            else:
                addressable_gaps.append(s)
            if is_high:
                escalated.append(s)

        rows.append((sid, section, name, req, status, s.get("alternative_documented", None), is_high))

    readiness = (100.0 * earned_weight / total_weight) if total_weight else 0.0
    return {
        "readiness": readiness,
        "required_gaps": required_gaps,
        "addressable_gaps": addressable_gaps,
        "escalated": escalated,
        "by_section": by_section,
        "rows": rows,
    }


def render(data, res):
    org = data.get("org", {})
    lines = []
    lines.append(f"# HIPAA Security Rule Gap Assessment - {org.get('name','Organization')}")
    lines.append("")
    if org.get("role"):
        lines.append(f"- **Role:** {org['role']}")
    lines.append(f"- **Weighted readiness:** **{res['readiness']:.0f}%** "
                 "(required specifications weighted 2x addressable)")
    lines.append(f"- **Required gaps:** {len(res['required_gaps'])} | "
                 f"Addressable gaps (no documented alternative): {len(res['addressable_gaps'])}")
    lines.append("")

    if res["escalated"]:
        lines.append("> **OCR-priority gap detected:** Risk Analysis / Risk Management is "
                     "incomplete. This is the most-cited HIPAA finding - remediate first.")
        lines.append("")

    # status by section
    lines.append("## Status by safeguard section")
    lines.append("")
    lines.append("| Section | Implemented | Partial | Gap |")
    lines.append("|---|---|---|---|")
    for sec in sorted(res["by_section"]):
        r = res["by_section"][sec]
        label = SECTION_NAMES.get(sec, sec)
        lines.append(f"| {label} | {r['implemented']} | {r['partial']} | {r['gap']} |")
    lines.append("")

    # full table
    lines.append("## Safeguard detail")
    lines.append("")
    lines.append("| Specification | Section | Requirement | Status | Alt. documented |")
    lines.append("|---|---|---|---|---|")
    for sid, sec, name, req, status, alt, _ in res["rows"]:
        altdisp = "-" if alt is None else ("yes" if alt else "no")
        secdisp = SECTION_NAMES.get(sec, sec)
        lines.append(f"| {sid} {name} | {secdisp} | {req} | {status} | {altdisp} |")
    lines.append("")

    # remediation priority
    lines.append("## Remediation priority")
    lines.append("")
    order = []
    order += [(s, "ESCALATED (Risk Analysis/Mgmt)") for s in res["escalated"]]
    order += [(s, "Required gap") for s in res["required_gaps"] if s not in res["escalated"]]
    order += [(s, "Addressable - implement or document alternative") for s in res["addressable_gaps"]]
    if not order:
        lines.append("No outstanding gaps. Maintain documentation and re-evaluate on change.")
    else:
        seen = set()
        i = 1
        for s, why in order:
            key = s.get("id")
            if key in seen:
                continue
            seen.add(key)
            lines.append(f"{i}. **{s.get('id')}** {s.get('name','')} - {why} "
                         f"(currently {s.get('status')}).")
            i += 1

    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser(description="HIPAA Security Rule safeguard gap-assessment scorer")
    ap.add_argument("--input", "-i", required=True, help="Path to safeguard-status JSON")
    ap.add_argument("--output", "-o", help="Write Markdown gap assessment to this path")
    ap.add_argument("--fail-on-required-gap", action="store_true",
                    help="Exit non-zero if any required specification is partial/gap")
    args = ap.parse_args()

    try:
        with open(args.input) as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        print(f"ERROR: could not read input JSON: {e}", file=sys.stderr)
        return 2

    try:
        res = score(data)
        md = render(data, res)
    except ValueError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 2

    if args.output:
        with open(args.output, "w") as f:
            f.write(md + "\n")
        print(f"Gap assessment written to {args.output}", file=sys.stderr)
    else:
        print(md)

    print(f"Readiness {res['readiness']:.0f}%; required gaps {len(res['required_gaps'])}; "
          f"escalated {len(res['escalated'])}.", file=sys.stderr)

    if args.fail_on_required_gap and res["required_gaps"]:
        ids = ", ".join(s.get("id", "?") for s in res["required_gaps"])
        print(f"FAIL: {len(res['required_gaps'])} required specification gap(s): {ids}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
