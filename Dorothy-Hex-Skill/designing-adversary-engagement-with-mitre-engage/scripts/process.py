#!/usr/bin/env python3
"""
MITRE Engage operation planner.

Given a threat model (a list of ATT&CK technique IDs the target adversary uses),
this maps each technique to the Engage Activities that expose its weakness,
reports coverage gaps, and emits an Adversary Engagement Operation Plan skeleton.

The embedded ATT&CK -> Engage Activity table is a *starter* map. Reconcile against
the live matrix at https://engage.mitre.org/matrix/ before operational use.

Usage:
    python process.py --threat-model tm.json --out plan.md
    python process.py --list-techniques

tm.json format:
    {
      "operation_name": "VPN-actor engagement",
      "target_actor": "Suspected access broker",
      "strategic_goal": "Generate first-party CTI on the VPN actor",
      "techniques": ["T1078", "T1046", "T1021", "T1552"]
    }
"""
import argparse
import json
import sys
from datetime import date

# Starter map: ATT&CK technique -> (short name, [candidate Engage Activities]).
# Activities use canonical Engage names; resolve EAC numeric IDs from the live matrix.
TECHNIQUE_TO_ACTIVITIES = {
    "T1078": ("Valid Accounts", ["Decoy Credentials", "Lures", "Decoy Account"]),
    "T1110": ("Brute Force", ["Decoy Credentials", "Security Controls"]),
    "T1552": ("Unsecured Credentials", ["Decoy Credentials", "Artifact Diversity", "Pocket Litter"]),
    "T1083": ("File and Directory Discovery", ["Decoy Content", "Pocket Litter", "Artifact Diversity"]),
    "T1046": ("Network Service Discovery", ["Network Diversity", "Network Manipulation"]),
    "T1021": ("Remote Services", ["Network Manipulation", "Isolation", "Decoy Content"]),
    "T1018": ("Remote System Discovery", ["Network Diversity", "Decoy Content"]),
    "T1057": ("Process Discovery", ["System Activity Monitoring", "Software Manipulation"]),
    "T1071": ("Application Layer Protocol (C2)", ["Network Monitoring", "Network Manipulation"]),
    "T1105": ("Ingress Tool Transfer", ["Malware Detonation", "Network Monitoring"]),
    "T1190": ("Exploit Public-Facing Application", ["Introduced Vulnerabilities", "Application Diversity"]),
    "T1059": ("Command and Scripting Interpreter", ["System Activity Monitoring", "API Monitoring"]),
    "T1567": ("Exfiltration Over Web Service", ["Network Monitoring", "Decoy Content"]),
}

ENGAGEMENT_GOALS = ["Expose", "Affect", "Elicit"]


def build_coverage(techniques):
    covered, gaps = {}, []
    for t in techniques:
        t = t.strip().upper()
        if t in TECHNIQUE_TO_ACTIVITIES:
            name, acts = TECHNIQUE_TO_ACTIVITIES[t]
            covered[t] = {"name": name, "activities": acts}
        else:
            gaps.append(t)
    return covered, gaps


def render_plan(tm, covered, gaps):
    lines = []
    lines.append(f"# Adversary Engagement Operation Plan: {tm.get('operation_name', 'UNNAMED')}")
    lines.append(f"\n_Generated {date.today().isoformat()} — DRAFT, requires legal sign-off before deployment._\n")
    lines.append("## 1. Strategic context")
    lines.append(f"- **Target actor:** {tm.get('target_actor', 'TBD')}")
    lines.append(f"- **Strategic goal (Prepare):** {tm.get('strategic_goal', 'TBD')}")
    lines.append("- **Executive sponsor:** TBD")
    lines.append("- **Legal sign-off reference:** TBD (REQUIRED before deployment)\n")

    lines.append("## 2. Engagement Goals + Operational Objectives")
    for g in ENGAGEMENT_GOALS:
        lines.append(f"- **{g}:** define ≥1 falsifiable, time-bound objective (e.g., alert latency, dwell-time reduction, indicators gained).")
    lines.append("")

    lines.append("## 3. Activity selection matrix")
    lines.append("| ATT&CK | Technique | Weakness → Engage Activities | Deployment owner |")
    lines.append("|---|---|---|---|")
    for t, info in covered.items():
        acts = ", ".join(info["activities"])
        lines.append(f"| {t} | {info['name']} | {acts} | TBD |")
    if not covered:
        lines.append("| — | — | (no mapped techniques) | — |")
    lines.append("")

    if gaps:
        lines.append("## 3a. Coverage GAPS (no starter mapping — check live matrix)")
        for t in gaps:
            lines.append(f"- {t}: resolve against https://engage.mitre.org/matrix/")
        lines.append("")

    lines.append("## 4. Engagement environment design")
    lines.append("- Honeynet type (standalone / connected / integrated): TBD")
    lines.append("- Artifact diversity plan (Persona Creation, Pocket Litter, Artifact/Application/Network Diversity): TBD\n")

    lines.append("## 5. Gating criteria & rules of engagement")
    lines.append("- Max blast radius: TBD")
    lines.append("- Tear-down / IR hand-off trigger: TBD")
    lines.append("- Evidence handling & chain of custody: TBD")
    lines.append("- Escalation authority: TBD")
    lines.append("- Affect Activities limited to defender-owned network only (hard constraint).\n")

    lines.append("## 6. Measurement plan")
    lines.append("- Metric per objective; baseline before deployment; review cadence: TBD\n")

    lines.append("## 7. After-action report (post-operation)")
    lines.append("- Objectives met/missed, intel produced, detections promoted to production, threat-model updates: TBD")
    return "\n".join(lines)


def main():
    p = argparse.ArgumentParser(description="MITRE Engage operation planner")
    p.add_argument("--threat-model", help="Path to threat-model JSON")
    p.add_argument("--out", help="Output markdown path (default: stdout)")
    p.add_argument("--list-techniques", action="store_true", help="List techniques in the starter map")
    args = p.parse_args()

    if args.list_techniques:
        for t, (name, acts) in sorted(TECHNIQUE_TO_ACTIVITIES.items()):
            print(f"{t:8} {name:40} -> {', '.join(acts)}")
        return

    if not args.threat_model:
        p.error("--threat-model is required (or use --list-techniques)")

    with open(args.threat_model) as f:
        tm = json.load(f)

    techniques = tm.get("techniques", [])
    if not techniques:
        print("WARNING: threat model has no 'techniques' list", file=sys.stderr)

    covered, gaps = build_coverage(techniques)
    total = len(techniques)
    pct = (len(covered) / total * 100) if total else 0
    print(f"Coverage: {len(covered)}/{total} techniques mapped ({pct:.0f}%); {len(gaps)} gap(s).",
          file=sys.stderr)

    plan = render_plan(tm, covered, gaps)
    if args.out:
        with open(args.out, "w") as f:
            f.write(plan + "\n")
        print(f"Wrote operation plan -> {args.out}", file=sys.stderr)
    else:
        print(plan)


if __name__ == "__main__":
    main()
