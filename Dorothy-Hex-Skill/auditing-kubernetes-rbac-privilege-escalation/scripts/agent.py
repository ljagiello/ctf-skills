#!/usr/bin/env python3
# For authorized Kubernetes security assessments only. Run against clusters you
# own or are explicitly authorized in writing to test.
"""Kubernetes RBAC privilege-escalation auditor.

Wraps `kubectl auth can-i` to enumerate effective permissions for service
accounts and flag the RBAC primitives that are equivalent to cluster-admin
(create pods, read secrets, escalate/bind/impersonate, token minting, wildcards),
per the Kubernetes "RBAC Good Practices" guidance.
"""

import argparse
import json
import shutil
import subprocess
import sys
from datetime import datetime, timezone

# (verb, resource) probes that indicate escalation potential
DANGEROUS_CHECKS = [
    ("*", "*"),
    ("create", "pods"),
    ("create", "pods/exec"),
    ("create", "pods/attach"),
    ("create", "pods/ephemeralcontainers"),
    ("get", "secrets"),
    ("list", "secrets"),
    ("create", "serviceaccounts/token"),
    ("impersonate", "users"),
    ("escalate", "roles"),
    ("bind", "clusterroles"),
    ("update", "clusterrolebindings"),
    ("update", "mutatingwebhookconfigurations"),
    ("create", "nodes/proxy"),
]


def _kubectl(args):
    cmd = ["kubectl"] + args
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        return p.returncode, p.stdout.strip(), p.stderr.strip()
    except FileNotFoundError:
        print("[!] kubectl not found on PATH", file=sys.stderr)
        sys.exit(2)
    except subprocess.TimeoutExpired:
        return 124, "", "timeout"


def list_service_accounts(namespace=None):
    args = ["get", "serviceaccounts", "-o",
            "jsonpath={range .items[*]}{.metadata.namespace}/{.metadata.name}{\"\\n\"}{end}"]
    if namespace:
        args += ["-n", namespace]
    else:
        args += ["--all-namespaces"]
    rc, out, err = _kubectl(args)
    if rc != 0:
        print(f"[!] failed to list service accounts: {err}", file=sys.stderr)
        return []
    return [line for line in out.splitlines() if "/" in line]


def can_i(verb, resource, subject=None, all_ns=True):
    """Return True if the (optionally impersonated) subject can verb/resource."""
    args = ["auth", "can-i", verb, resource]
    if all_ns:
        args.append("--all-namespaces")
    if subject:
        args.append(f"--as=system:serviceaccount:{subject.split('/')[0]}:{subject.split('/')[1]}")
    rc, out, _ = _kubectl(args)
    return out.strip() == "yes"


def audit_subject(subject):
    findings = []
    for verb, resource in DANGEROUS_CHECKS:
        if can_i(verb, resource, subject=subject):
            findings.append({"verb": verb, "resource": resource})
    severity = "none"
    flat = {(f["verb"], f["resource"]) for f in findings}
    if ("*", "*") in flat or ("escalate", "roles") in flat or \
            ("bind", "clusterroles") in flat or ("impersonate", "users") in flat:
        severity = "critical"
    elif ("create", "pods") in flat or ("list", "secrets") in flat or \
            ("create", "serviceaccounts/token") in flat:
        severity = "high"
    elif findings:
        severity = "medium"
    return {"subject": subject, "severity": severity,
            "dangerous_permissions": findings}


def cluster_admin_bindings():
    rc, out, _ = _kubectl([
        "get", "clusterrolebindings", "-o", "json"])
    if rc != 0:
        return []
    try:
        data = json.loads(out)
    except json.JSONDecodeError:
        return []
    result = []
    for item in data.get("items", []):
        if item.get("roleRef", {}).get("name") == "cluster-admin":
            subs = [f"{s.get('kind')}:{s.get('name')}"
                    for s in (item.get("subjects") or [])]
            result.append({"binding": item["metadata"]["name"], "subjects": subs})
    return result


def main():
    ap = argparse.ArgumentParser(
        description="Audit Kubernetes RBAC for privilege-escalation paths")
    ap.add_argument("-n", "--namespace", help="limit to one namespace")
    ap.add_argument("-s", "--subject",
                    help="audit a single subject NS/SA instead of all")
    ap.add_argument("-o", "--output", help="write JSON report to file")
    args = ap.parse_args()

    if not shutil.which("kubectl"):
        print("[!] kubectl is required", file=sys.stderr)
        return 2

    print("=" * 60)
    print("  KUBERNETES RBAC PRIVILEGE-ESCALATION AUDIT")
    print(f"  {datetime.now(timezone.utc).isoformat()}")
    print("=" * 60)

    admins = cluster_admin_bindings()
    print(f"\n[+] cluster-admin bindings ({len(admins)}):")
    for a in admins:
        print(f"    {a['binding']} -> {', '.join(a['subjects']) or '(none)'}")

    subjects = [args.subject] if args.subject else list_service_accounts(args.namespace)
    print(f"\n[+] Auditing {len(subjects)} service account(s)...")

    results = []
    for subj in subjects:
        r = audit_subject(subj)
        results.append(r)
        if r["severity"] != "none":
            perms = ", ".join(f"{f['verb']} {f['resource']}"
                              for f in r["dangerous_permissions"])
            print(f"  [{r['severity'].upper():8}] {subj}: {perms}")

    report = {
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "cluster_admin_bindings": admins,
        "subject_findings": results,
        "summary": {
            "critical": sum(1 for r in results if r["severity"] == "critical"),
            "high": sum(1 for r in results if r["severity"] == "high"),
            "medium": sum(1 for r in results if r["severity"] == "medium"),
        },
    }
    print(f"\n[+] Summary: {report['summary']}")

    if args.output:
        with open(args.output, "w") as fh:
            json.dump(report, fh, indent=2)
        print(f"[+] Report written to {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
