#!/usr/bin/env python3
"""
CloudFox enumeration driver.

Runs a curated set of CloudFox commands against an AWS profile (or `all-checks`),
captures output into a structured directory, and prints a triage summary that
highlights the high-value findings (role-trusts, secrets, endpoints).

Authorized-use only: CloudFox performs reconnaissance against a live cloud
account. Run ONLY within a signed scope/Rules of Engagement.

Examples:
  python agent.py --profile assess --all
  python agent.py --profile assess --commands endpoints secrets role-trusts -o ./loot
"""
import argparse
import os
import shutil
import subprocess
import sys

HIGH_VALUE = {"role-trusts", "secrets", "endpoints", "access-keys", "permissions"}
DEFAULT_COMMANDS = [
    "inventory", "endpoints", "instances", "principals",
    "permissions", "role-trusts", "access-keys", "secrets", "buckets",
]


def require_cloudfox():
    if shutil.which("cloudfox") is None:
        sys.exit("error: 'cloudfox' not found in PATH. Install: brew install cloudfox "
                 "or go install github.com/BishopFox/cloudfox@latest")


def run_command(provider, profile, command, outdir):
    cmd = ["cloudfox", provider]
    if provider == "aws" and profile:
        cmd += ["--profile", profile]
    if outdir:
        cmd += ["-o", outdir]
    cmd += [command]
    print(f"[*] cloudfox {provider} {command} ...")
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=1200)
    except subprocess.TimeoutExpired:
        print(f"  [!] {command} timed out")
        return None
    except OSError as exc:
        print(f"  [!] failed to run {command}: {exc}")
        return None
    if proc.returncode != 0:
        print(f"  [!] {command} rc={proc.returncode}: {proc.stderr.strip()[:200]}")
    return proc.stdout


def summarize_outdir(outdir):
    base = os.path.join(outdir, "cloudfox-output")
    if not os.path.isdir(base):
        print("[!] no cloudfox-output directory produced")
        return
    print("\n=== Output files ===")
    for root, _dirs, files in os.walk(base):
        for f in sorted(files):
            path = os.path.join(root, f)
            try:
                size = os.path.getsize(path)
            except OSError:
                size = -1
            rel = os.path.relpath(path, outdir)
            flag = " <-- HIGH VALUE" if any(h in f for h in HIGH_VALUE) else ""
            print(f"  {rel} ({size} bytes){flag}")


def main():
    p = argparse.ArgumentParser(description="CloudFox enumeration driver")
    p.add_argument("--provider", default="aws", choices=["aws", "azure"])
    p.add_argument("--profile", help="AWS named profile")
    p.add_argument("--all", action="store_true", help="run all-checks (AWS) / inventory (Azure)")
    p.add_argument("--commands", nargs="+", help="specific CloudFox commands to run")
    p.add_argument("-o", "--outdir", default="./cloudfox-loot", help="output directory")
    args = p.parse_args()

    require_cloudfox()
    print("[!] AUTHORIZED USE ONLY — confirm the target account is in scope.")
    os.makedirs(args.outdir, exist_ok=True)

    if args.all:
        commands = ["all-checks"] if args.provider == "aws" else ["inventory"]
    elif args.commands:
        commands = args.commands
    else:
        commands = DEFAULT_COMMANDS if args.provider == "aws" else ["inventory", "rbac", "storage", "vms"]

    for c in commands:
        out = run_command(args.provider, args.profile, c, args.outdir)
        if out and c in HIGH_VALUE:
            lines = [l for l in out.splitlines() if l.strip()]
            print(f"  [+] {c}: {len(lines)} output lines")

    summarize_outdir(args.outdir)
    print(f"\n[+] done. Review loot under {args.outdir}/cloudfox-output/")


if __name__ == "__main__":
    main()
