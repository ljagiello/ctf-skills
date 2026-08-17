#!/usr/bin/env python3
"""
NIST SP 800-30 Rev 1 risk-register scoring engine.

Reads a risk-input JSON file describing threat events with their assessed
likelihood and impact, computes a risk level for each using the 800-30 5x5
reference matrix (configurable), ranks the register highest-risk-first, and
emits a Markdown risk register plus a top-risks summary.

Input JSON shape:
{
  "assessment": {
    "name": "Q2 FY26 Enterprise Risk Assessment",
    "scope": "Internet-facing application tier",
    "tier": 3
  },
  "matrix": {                      # OPTIONAL - overrides the default 800-30 matrix
    "High": {"Very High": "Very High", ...}
  },
  "risks": [
    {
      "id": "R-01",
      "threat_event": "Adversary phishes credentials and moves laterally",
      "threat_source": "Adversarial",
      "asset": "Customer portal / identity provider",
      "attack_techniques": ["T1566", "T1021"],
      "likelihood": "High",
      "impact": "Very High",
      "vulnerabilities": ["No phishing-resistant MFA", "Flat internal network"],
      "treatment": "Mitigate",
      "owner": "IAM Lead",
      "residual_risk": "Moderate"
    }
  ]
}

Likelihood / impact values must be one of:
  Very Low | Low | Moderate | High | Very High

Usage:
  python process.py --input risks.json [--output register.md] [--fail-on High]
  python process.py --print-matrix
"""

import argparse
import json
import sys

LEVELS = ["Very Low", "Low", "Moderate", "High", "Very High"]
RANK = {lvl: i for i, lvl in enumerate(LEVELS)}

# 800-30 Rev 1 reference 5x5 matrix: MATRIX[likelihood][impact] -> risk level
MATRIX = {
    "Very High": {"Very Low": "Very Low", "Low": "Low", "Moderate": "Moderate", "High": "High", "Very High": "Very High"},
    "High":      {"Very Low": "Very Low", "Low": "Low", "Moderate": "Moderate", "High": "High", "Very High": "Very High"},
    "Moderate":  {"Very Low": "Very Low", "Low": "Low", "Moderate": "Moderate", "High": "Moderate", "Very High": "High"},
    "Low":       {"Very Low": "Very Low", "Low": "Low", "Moderate": "Low", "High": "Low", "Very High": "Moderate"},
    "Very Low":  {"Very Low": "Very Low", "Low": "Very Low", "Moderate": "Very Low", "High": "Low", "Very High": "Low"},
}


def validate_level(value, field, rid):
    if value not in LEVELS:
        raise ValueError(
            f"risk {rid}: {field} '{value}' is not a valid 800-30 level "
            f"(expected one of {LEVELS})"
        )
    return value


def score_risk(risk, matrix):
    rid = risk.get("id", "?")
    likelihood = validate_level(risk.get("likelihood"), "likelihood", rid)
    impact = validate_level(risk.get("impact"), "impact", rid)
    level = matrix[likelihood][impact]
    return level


def render_markdown(data, matrix):
    meta = data.get("assessment", {})
    risks = data.get("risks", [])

    scored = []
    for r in risks:
        level = score_risk(r, matrix)
        scored.append((r, level))

    # rank highest risk first; tie-break by impact then likelihood
    scored.sort(
        key=lambda rl: (
            RANK[rl[1]],
            RANK[rl[0].get("impact", "Very Low")],
            RANK[rl[0].get("likelihood", "Very Low")],
        ),
        reverse=True,
    )

    lines = []
    title = meta.get("name", "Risk Assessment")
    lines.append(f"# Risk Register - {title}")
    lines.append("")
    if meta.get("scope"):
        lines.append(f"- **Scope:** {meta['scope']}")
    if meta.get("tier"):
        lines.append(f"- **Risk-management tier (SP 800-39):** Tier {meta['tier']}")
    lines.append(f"- **Risks assessed:** {len(scored)}")
    lines.append("")
    lines.append("Risk level computed from likelihood x impact on the NIST SP 800-30 Rev 1 5x5 matrix.")
    lines.append("")

    # main register
    header = (
        "| ID | Threat event | Source | Asset | ATT&CK | Likelihood | Impact "
        "| Risk | Key vulnerabilities | Treatment | Residual | Owner |"
    )
    sep = "|" + "---|" * 12
    lines.append(header)
    lines.append(sep)
    for r, level in scored:
        attck = ", ".join(r.get("attack_techniques", [])) or "-"
        vulns = "; ".join(r.get("vulnerabilities", [])) or "-"
        lines.append(
            "| {id} | {event} | {src} | {asset} | {attck} | {like} | {imp} "
            "| **{risk}** | {vulns} | {treat} | {res} | {owner} |".format(
                id=r.get("id", "-"),
                event=r.get("threat_event", "-"),
                src=r.get("threat_source", "-"),
                asset=r.get("asset", "-"),
                attck=attck,
                like=r.get("likelihood", "-"),
                imp=r.get("impact", "-"),
                risk=level,
                vulns=vulns,
                treat=r.get("treatment", "-"),
                res=r.get("residual_risk", "-"),
                owner=r.get("owner", "-"),
            )
        )

    # top risks summary
    top = [rl for rl in scored if RANK[rl[1]] >= RANK["High"]]
    lines.append("")
    lines.append("## Top risks (High and above)")
    lines.append("")
    if not top:
        lines.append("_No risks scored High or above._")
    else:
        for r, level in top:
            lines.append(f"- **{level}** - {r.get('id','-')}: {r.get('threat_event','-')} "
                         f"(impact {r.get('impact','-')}, likelihood {r.get('likelihood','-')})")

    # distribution
    dist = {lvl: 0 for lvl in LEVELS}
    for _, level in scored:
        dist[level] += 1
    lines.append("")
    lines.append("## Risk distribution")
    lines.append("")
    lines.append("| Risk level | Count |")
    lines.append("|---|---|")
    for lvl in reversed(LEVELS):
        lines.append(f"| {lvl} | {dist[lvl]} |")

    return "\n".join(lines), scored, dist


def main():
    ap = argparse.ArgumentParser(description="NIST SP 800-30 risk-register scoring engine")
    ap.add_argument("--input", "-i", help="Path to risk-input JSON")
    ap.add_argument("--output", "-o", help="Write Markdown register to this path")
    ap.add_argument("--fail-on", choices=LEVELS,
                    help="Exit non-zero if any risk scores at or above this level (for pipelines)")
    ap.add_argument("--print-matrix", action="store_true", help="Print the active risk matrix and exit")
    args = ap.parse_args()

    if args.print_matrix:
        print("NIST SP 800-30 Rev 1 reference 5x5 matrix (likelihood x impact -> risk):\n")
        hdr = "Likelihood \\ Impact | " + " | ".join(LEVELS)
        print(hdr)
        print("-" * len(hdr))
        for like in reversed(LEVELS):
            row = " | ".join(MATRIX[like][imp] for imp in LEVELS)
            print(f"{like} | {row}")
        return 0

    if not args.input:
        ap.error("--input is required unless --print-matrix is used")

    try:
        with open(args.input) as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        print(f"ERROR: could not read input JSON: {e}", file=sys.stderr)
        return 2

    matrix = data.get("matrix", MATRIX)

    try:
        md, scored, dist = render_markdown(data, matrix)
    except ValueError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 2

    if args.output:
        with open(args.output, "w") as f:
            f.write(md + "\n")
        print(f"Risk register written to {args.output}", file=sys.stderr)
    else:
        print(md)

    # summary to stderr
    summary = ", ".join(f"{lvl}:{dist[lvl]}" for lvl in reversed(LEVELS) if dist[lvl])
    print(f"Scored {len(scored)} risks ({summary}).", file=sys.stderr)

    if args.fail_on:
        threshold = RANK[args.fail_on]
        breaches = [(r.get("id", "?"), lvl) for r, lvl in scored if RANK[lvl] >= threshold]
        if breaches:
            ids = ", ".join(f"{rid}={lvl}" for rid, lvl in breaches)
            print(f"FAIL: {len(breaches)} risk(s) at or above {args.fail_on}: {ids}", file=sys.stderr)
            return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
