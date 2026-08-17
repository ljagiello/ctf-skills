#!/usr/bin/env python3
"""
Stratus Red Team detection-validation helper.

Drives the `stratus` CLI to run a controlled warmup -> detonate -> (optional revert)
-> cleanup lifecycle across one or more techniques, optionally filtered by platform
and MITRE ATT&CK tactic. Designed for purple-team detection-coverage runs.

Authorized-use only: this detonates real attack techniques against the cloud
account whose credentials are in your environment. Use a dedicated lab account.

Examples:
  python agent.py --list --platform aws
  python agent.py --technique aws.credential-access.ec2-steal-instance-credentials --detonate --cleanup
  python agent.py --platform aws --tactic persistence --detonate --cleanup
"""
import argparse
import json
import shutil
import subprocess
import sys
import time


def require_stratus():
    if shutil.which("stratus") is None:
        sys.exit("error: 'stratus' binary not found in PATH. Install from "
                 "https://github.com/DataDog/stratus-red-team")


def run(args, capture=True, check=False):
    """Run a stratus subcommand and return (rc, stdout, stderr)."""
    cmd = ["stratus"] + args
    try:
        proc = subprocess.run(
            cmd,
            capture_output=capture,
            text=True,
            timeout=900,
        )
    except subprocess.TimeoutExpired:
        return 124, "", f"timeout running: {' '.join(cmd)}"
    except OSError as exc:
        return 1, "", f"failed to execute {' '.join(cmd)}: {exc}"
    if check and proc.returncode != 0:
        sys.stderr.write(proc.stderr or "")
    return proc.returncode, (proc.stdout or ""), (proc.stderr or "")


def list_techniques(platform=None, tactic=None):
    args = ["list"]
    if platform:
        args += ["--platform", platform]
    if tactic:
        args += ["--mitre-attack-tactic", tactic]
    rc, out, err = run(args)
    if rc != 0:
        sys.exit(f"error listing techniques: {err.strip()}")
    ids = []
    for line in out.splitlines():
        line = line.strip()
        # Technique IDs look like aws.persistence.iam-create-admin-user
        token = line.split()[0] if line else ""
        if token.count(".") >= 2 and "." in token and token[0].isalpha():
            ids.append(token)
    return ids


def lifecycle(technique, detonate, revert, cleanup):
    print(f"\n=== {technique} ===")
    rc, out, err = run(["warmup", technique], capture=False)
    if rc != 0:
        print(f"  [!] warmup failed (rc={rc}): {err.strip()}")
        return {"technique": technique, "status": "warmup_failed"}
    result = {"technique": technique, "status": "warmed"}

    if detonate:
        print("  [*] detonating ...")
        rc, out, err = run(["detonate", technique], capture=False)
        result["status"] = "detonated" if rc == 0 else "detonate_failed"
        if rc != 0:
            print(f"  [!] detonate failed: {err.strip()}")
        time.sleep(2)

    if revert and result["status"] == "detonated":
        print("  [*] reverting ...")
        run(["revert", technique], capture=False)
        result["status"] = "reverted"

    if cleanup:
        print("  [*] cleaning up ...")
        rc, out, err = run(["cleanup", technique], capture=False)
        result["cleaned"] = (rc == 0)
        if rc != 0:
            print(f"  [!] cleanup failed: {err.strip()}")
    return result


def main():
    p = argparse.ArgumentParser(description="Stratus Red Team lifecycle helper")
    p.add_argument("--list", action="store_true", help="list matching techniques and exit")
    p.add_argument("--platform", help="filter: aws|azure|gcp|kubernetes|eks")
    p.add_argument("--tactic", help="filter by MITRE ATT&CK tactic, e.g. credential-access")
    p.add_argument("--technique", action="append", default=[],
                   help="explicit technique ID (repeatable)")
    p.add_argument("--detonate", action="store_true", help="detonate after warmup")
    p.add_argument("--revert", action="store_true", help="revert detonation side effects")
    p.add_argument("--cleanup", action="store_true", help="cleanup prerequisites after run")
    p.add_argument("--json", action="store_true", help="emit JSON summary")
    args = p.parse_args()

    require_stratus()

    if args.list:
        for t in list_techniques(args.platform, args.tactic):
            print(t)
        return

    targets = list(args.technique)
    if not targets:
        targets = list_techniques(args.platform, args.tactic)
    if not targets:
        sys.exit("error: no techniques selected (use --technique or --platform/--tactic)")

    print(f"[+] {len(targets)} technique(s) selected")
    results = []
    try:
        for t in targets:
            results.append(lifecycle(t, args.detonate, args.revert, args.cleanup))
    except KeyboardInterrupt:
        print("\n[!] interrupted — run 'stratus cleanup --all' to remove residual infra")
        sys.exit(130)

    if args.json:
        print(json.dumps(results, indent=2))
    else:
        print("\n=== Summary ===")
        for r in results:
            print(f"  {r['technique']}: {r['status']}"
                  + (f" cleaned={r['cleaned']}" if "cleaned" in r else ""))


if __name__ == "__main__":
    main()
