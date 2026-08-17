#!/usr/bin/env python3
"""
Cloud deception deployment validator.

Reads a decoy-inventory JSON, checks each decoy for the controls that make a
cloud decoy trustworthy (detection wiring, deny-all/least-privilege, validation,
internal tagging), renders a Cloud Deception Deployment Record, and exits non-zero
if any decoy is missing a required control.

Usage:
    python process.py --inventory decoys.json --out record.md

decoys.json format:
    {
      "account": "acme-prod (AWS 1111...)",
      "decoys": [
        {
          "name": "svc-backup-prod",
          "cloud": "aws",
          "type": "canary_access_key",
          "placement": "CI variables + private repo .env",
          "deny_all": true,
          "detection": {"source": "CloudTrail", "rule": "decoy-key-used", "sink": "sns:soc-deception-alerts", "playbook": "IR-CLOUD-07"},
          "validated": {"date": "2026-05-20", "by": "redteam", "latency_sec": 90, "passed": true},
          "internal_tag": "deception=true"
        }
      ]
    }
"""
import argparse
import json
import sys
from datetime import date

REQUIRED = ["name", "cloud", "type", "placement"]
VALID_CLOUDS = {"aws", "azure", "gcp"}


def check_decoy(d):
    """Return list of issues for one decoy."""
    issues = []
    for k in REQUIRED:
        if not d.get(k):
            issues.append(f"missing required field '{k}'")
    if d.get("cloud") and d["cloud"].lower() not in VALID_CLOUDS:
        issues.append(f"unknown cloud '{d.get('cloud')}'")

    det = d.get("detection") or {}
    for k in ("source", "rule", "sink"):
        if not det.get(k):
            issues.append(f"detection wiring missing '{k}' (decoy is blind)")
    if not det.get("playbook"):
        issues.append("no IR playbook reference for the alert")

    # Credential/principal decoys must be deny-all / least privilege.
    cred_types = {"canary_access_key", "decoy_principal", "decoy_service_account",
                  "decoy_service_principal", "decoy_iam_user"}
    if d.get("type") in cred_types and not d.get("deny_all"):
        issues.append("credential/principal decoy is not marked deny_all (liability risk)")

    val = d.get("validated") or {}
    if not val.get("passed"):
        issues.append("not validated end-to-end (assume non-functional)")
    if not d.get("internal_tag"):
        issues.append("no internal deception tag/label (audit-cleanup risk)")
    return issues


def render(inv, results):
    lines = [f"# Cloud Deception Deployment Record",
             f"\n_Account: {inv.get('account', 'UNKNOWN')} — generated {date.today().isoformat()}_\n",
             "## 1. Decoy inventory & detection wiring",
             "| Decoy | Cloud | Type | Placement | Detection (source→rule→sink) | Playbook | Validated | Status |",
             "|---|---|---|---|---|---|---|---|"]
    for d, issues in results:
        det = d.get("detection") or {}
        wiring = f"{det.get('source','?')}→{det.get('rule','?')}→{det.get('sink','?')}"
        val = d.get("validated") or {}
        vstr = f"{val.get('date','-')} ({val.get('latency_sec','?')}s)" if val.get("passed") else "NO"
        status = "OK" if not issues else f"{len(issues)} issue(s)"
        lines.append(f"| {d.get('name','?')} | {d.get('cloud','?')} | {d.get('type','?')} | "
                     f"{d.get('placement','?')} | {wiring} | {det.get('playbook','-')} | {vstr} | {status} |")

    problem = [(d, i) for d, i in results if i]
    if problem:
        lines.append("\n## 2. Issues to remediate before relying on these decoys")
        for d, issues in problem:
            lines.append(f"\n**{d.get('name','?')}** ({d.get('cloud','?')}):")
            for it in issues:
                lines.append(f"- {it}")
    else:
        lines.append("\n## 2. Issues\nNone — all decoys have detection wiring, least privilege, and validation.")

    lines.append("\n## 3. Maintenance")
    lines.append("- Rotation cadence: TBD  ·  Review owner: TBD")
    lines.append("- Keep this record separate from attacker-visible metadata.")
    return "\n".join(lines)


def main():
    p = argparse.ArgumentParser(description="Cloud deception deployment validator")
    p.add_argument("--inventory", required=True, help="Path to decoy-inventory JSON")
    p.add_argument("--out", help="Output markdown path (default: stdout)")
    args = p.parse_args()

    with open(args.inventory) as f:
        inv = json.load(f)

    decoys = inv.get("decoys", [])
    results = [(d, check_decoy(d)) for d in decoys]
    total_issues = sum(len(i) for _, i in results)
    healthy = sum(1 for _, i in results if not i)

    print(f"{len(decoys)} decoy(s): {healthy} healthy, {total_issues} total issue(s).",
          file=sys.stderr)

    out = render(inv, results)
    if args.out:
        with open(args.out, "w") as f:
            f.write(out + "\n")
        print(f"Wrote deployment record -> {args.out}", file=sys.stderr)
    else:
        print(out)

    # Non-zero exit if any decoy has issues, so this can gate a pipeline.
    sys.exit(1 if total_issues else 0)


if __name__ == "__main__":
    main()
