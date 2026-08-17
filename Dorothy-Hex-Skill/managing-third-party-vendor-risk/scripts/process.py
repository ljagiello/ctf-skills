#!/usr/bin/env python3
"""
Third-party vendor inherent-risk tiering and evidence-gap checker.

Scores a vendor's inherent risk from a profile, assigns a tier
(Critical/High/Moderate/Low), sets the assessment depth and reassessment
cadence for that tier, and flags evidence that is missing or stale for the
assigned tier.

Input JSON shape:
{
  "vendor": {"name": "PayWorks", "service": "Payroll processing"},
  "profile": {
    "data_sensitivity": "regulated",   # regulated | confidential | internal | public
    "access": "system",                # system | network | physical | none
    "criticality": "high",             # high | medium | low
    "regulated_scope": ["PII"],        # list; non-empty raises risk
    "integration": "deep",             # deep | moderate | none
    "concentration": true              # single-source / large dependency
  },
  "evidence": {                        # OPTIONAL; what you have on file
    "sig": "core",                     # full | core | lite | caiq | none
    "soc2_type": "II",                 # II | I | none
    "soc2_period_months": 12,
    "iso27001": true,
    "pentest_age_months": 8
  }
}

Usage:
  python process.py --input vendor.json [--output assessment.md]
  python process.py --input vendor.json --fail-on-evidence-gap
"""

import argparse
import json
import sys

# inherent-risk points per factor
DATA_POINTS = {"regulated": 4, "confidential": 3, "internal": 1, "public": 0}
ACCESS_POINTS = {"system": 4, "network": 3, "physical": 2, "none": 0}
CRIT_POINTS = {"high": 4, "medium": 2, "low": 1}
INTEG_POINTS = {"deep": 2, "moderate": 1, "none": 0}

# tier thresholds on total inherent score (max ~17)
def tier_for(score):
    if score >= 13:
        return "Critical"
    if score >= 9:
        return "High"
    if score >= 5:
        return "Moderate"
    return "Low"

# per-tier expectations
TIER_PLAYBOOK = {
    "Critical": {
        "depth": "Full SIG + SOC 2 Type II (12-month period) + ISO 27001 + recent pen-test + assessor call",
        "cadence": "Reassess annually; continuous security-ratings monitoring",
        "require": {"sig": ("full", "core"), "soc2_type": ("II",), "iso27001": True, "pentest_max_months": 12},
    },
    "High": {
        "depth": "SIG Core + SOC 2 Type II + pen-test summary",
        "cadence": "Reassess annually",
        "require": {"sig": ("full", "core"), "soc2_type": ("II",), "iso27001": False, "pentest_max_months": 18},
    },
    "Moderate": {
        "depth": "SIG Lite or CAIQ + key attestations",
        "cadence": "Reassess every 2 years",
        "require": {"sig": ("full", "core", "lite", "caiq"), "soc2_type": ("II", "I"), "iso27001": False, "pentest_max_months": None},
    },
    "Low": {
        "depth": "Lightweight questionnaire / self-attestation",
        "cadence": "Reassess every 3 years or on change",
        "require": {"sig": ("full", "core", "lite", "caiq", "none"), "soc2_type": ("II", "I", "none"), "iso27001": False, "pentest_max_months": None},
    },
}


def score_inherent(p):
    breakdown = {}
    breakdown["data_sensitivity"] = DATA_POINTS.get(p.get("data_sensitivity", "internal"), 1)
    breakdown["access"] = ACCESS_POINTS.get(p.get("access", "none"), 0)
    breakdown["criticality"] = CRIT_POINTS.get(p.get("criticality", "low"), 1)
    breakdown["integration"] = INTEG_POINTS.get(p.get("integration", "none"), 0)
    breakdown["regulated_scope"] = 2 if p.get("regulated_scope") else 0
    breakdown["concentration"] = 1 if p.get("concentration") else 0
    total = sum(breakdown.values())
    return total, breakdown


def check_evidence(tier, ev):
    req = TIER_PLAYBOOK[tier]["require"]
    gaps = []
    sig = (ev.get("sig") or "none").lower()
    if sig not in req["sig"]:
        gaps.append(f"Questionnaire '{sig}' insufficient for {tier} (need one of {', '.join(req['sig'])})")
    soc = (ev.get("soc2_type") or "none")
    if soc not in req["soc2_type"]:
        gaps.append(f"SOC 2 type '{soc}' insufficient for {tier} (need {', '.join(req['soc2_type'])})")
    if soc == "II" and ev.get("soc2_period_months", 0) < 6:
        gaps.append("SOC 2 Type II period under 6 months - limited operating-effectiveness assurance")
    if req["iso27001"] and not ev.get("iso27001"):
        gaps.append(f"ISO 27001 certificate expected for {tier}")
    pmax = req["pentest_max_months"]
    if pmax is not None:
        age = ev.get("pentest_age_months")
        if age is None:
            gaps.append(f"No pen-test on file (expected within {pmax} months for {tier})")
        elif age > pmax:
            gaps.append(f"Pen-test is {age} months old (>{pmax} for {tier}) - request a current test")
    return gaps


def render(data):
    vendor = data.get("vendor", {})
    profile = data.get("profile", {})
    evidence = data.get("evidence", {})
    if not profile:
        raise ValueError("profile is required to tier the vendor")

    total, breakdown = score_inherent(profile)
    tier = tier_for(total)
    play = TIER_PLAYBOOK[tier]
    gaps = check_evidence(tier, evidence) if evidence else ["No evidence provided - collect tier-appropriate evidence"]

    lines = []
    lines.append(f"# Vendor Risk Assessment - {vendor.get('name','Vendor')}")
    lines.append("")
    if vendor.get("service"):
        lines.append(f"- **Service:** {vendor['service']}")
    lines.append(f"- **Inherent-risk score:** {total} -> **Tier: {tier}**")
    lines.append("")

    lines.append("## Inherent-risk breakdown")
    lines.append("")
    lines.append("| Factor | Value | Points |")
    lines.append("|---|---|---|")
    lines.append(f"| Data sensitivity | {profile.get('data_sensitivity','-')} | {breakdown['data_sensitivity']} |")
    lines.append(f"| Access | {profile.get('access','-')} | {breakdown['access']} |")
    lines.append(f"| Criticality | {profile.get('criticality','-')} | {breakdown['criticality']} |")
    lines.append(f"| Integration | {profile.get('integration','-')} | {breakdown['integration']} |")
    lines.append(f"| Regulated scope | {', '.join(profile.get('regulated_scope', [])) or 'none'} | {breakdown['regulated_scope']} |")
    lines.append(f"| Concentration | {profile.get('concentration', False)} | {breakdown['concentration']} |")
    lines.append(f"| **Total** | | **{total}** |")
    lines.append("")

    lines.append(f"## {tier}-tier playbook")
    lines.append("")
    lines.append(f"- **Assessment depth:** {play['depth']}")
    lines.append(f"- **Reassessment cadence:** {play['cadence']}")
    lines.append("")

    lines.append("## Evidence gaps")
    lines.append("")
    if not gaps:
        lines.append(f"Evidence on file meets the {tier}-tier bar. Proceed to findings review and contracting.")
    else:
        for g in gaps:
            lines.append(f"- {g}")
    lines.append("")

    lines.append("## Next steps")
    lines.append("")
    lines.append("1. Close the evidence gaps above (or document risk-accepted exceptions).")
    lines.append("2. Review collected evidence critically (SOC 2 exceptions, ISO scope, CAIQ 'no' answers).")
    lines.append("3. Record findings, residual risk, and a risk-owner decision.")
    lines.append("4. Codify security terms, breach SLA, right-to-audit, and subprocessor flowdown in the contract.")
    lines.append("5. Enroll in continuous monitoring per the cadence above.")

    return "\n".join(lines), tier, gaps


def main():
    ap = argparse.ArgumentParser(description="Vendor inherent-risk tiering + evidence-gap checker")
    ap.add_argument("--input", "-i", required=True, help="Path to vendor profile JSON")
    ap.add_argument("--output", "-o", help="Write Markdown assessment to this path")
    ap.add_argument("--fail-on-evidence-gap", action="store_true",
                    help="Exit non-zero if any evidence gap remains for the tier")
    args = ap.parse_args()

    try:
        with open(args.input) as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        print(f"ERROR: could not read input JSON: {e}", file=sys.stderr)
        return 2

    try:
        md, tier, gaps = render(data)
    except ValueError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 2

    if args.output:
        with open(args.output, "w") as f:
            f.write(md + "\n")
        print(f"Assessment written to {args.output}", file=sys.stderr)
    else:
        print(md)

    print(f"Tier: {tier}; evidence gaps: {len(gaps)}.", file=sys.stderr)

    if args.fail_on_evidence_gap and gaps:
        print(f"FAIL: {len(gaps)} evidence gap(s) for {tier} tier.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
