#!/usr/bin/env python3
"""
SBOM generation + vulnerability correlation helper.

Wraps Syft (SBOM generation), Grype (vulnerability scanning), and Cosign
(attestation) with real flags. Can run the full pipeline (generate -> scan ->
optionally attest) and summarize Grype JSON by severity for CI gating.

References:
  https://github.com/anchore/syft
  https://github.com/anchore/grype
  https://github.com/sigstore/cosign
"""
import argparse
import json
import shutil
import subprocess
import sys
from collections import Counter

SEVERITY_ORDER = ["negligible", "low", "medium", "high", "critical"]


def require(tool):
    path = shutil.which(tool)
    if not path:
        print(f"[!] '{tool}' not found on PATH", file=sys.stderr)
    return path


def run(cmd, dry_run, capture=False):
    print("[*] " + " ".join(cmd), file=sys.stderr)
    if dry_run:
        return 0, ""
    try:
        if capture:
            proc = subprocess.run(cmd, check=False, text=True, capture_output=True)
            if proc.returncode != 0 and proc.stderr:
                print(proc.stderr, file=sys.stderr)
            return proc.returncode, proc.stdout
        return subprocess.run(cmd, check=False).returncode, ""
    except FileNotFoundError:
        print(f"[!] command not found: {cmd[0]}", file=sys.stderr)
        return 127, ""


def syft_generate(source, fmt, outfile, dry_run):
    syft = require("syft") or "syft"
    cmd = [syft, source, "-o", f"{fmt}={outfile}"]
    rc, _ = run(cmd, dry_run)
    return rc


def grype_scan(sbom_path, out_json, fail_on=None, only_fixed=False, dry_run=False):
    grype = require("grype") or "grype"
    cmd = [grype, f"sbom:{sbom_path}", "-o", "json"]
    if only_fixed:
        cmd.append("--only-fixed")
    if fail_on:
        cmd += ["--fail-on", fail_on]
    rc, out = run(cmd, dry_run, capture=True)
    if out and not dry_run:
        with open(out_json, "w", encoding="utf-8") as fh:
            fh.write(out)
    return rc, out


def summarize(grype_json_text):
    """Count vulnerabilities by severity from Grype JSON output."""
    try:
        data = json.loads(grype_json_text)
    except (json.JSONDecodeError, TypeError):
        print("[!] could not parse Grype JSON", file=sys.stderr)
        return Counter()
    counts = Counter()
    for match in data.get("matches", []):
        sev = (match.get("vulnerability", {})
                    .get("severity", "Unknown")).lower()
        counts[sev] += 1
    return counts


def print_summary(counts):
    total = sum(counts.values())
    print(f"[+] Total vulnerabilities: {total}")
    for sev in reversed(SEVERITY_ORDER):
        if counts.get(sev):
            print(f"    {sev:>10}: {counts[sev]}")
    for sev, n in counts.items():
        if sev not in SEVERITY_ORDER:
            print(f"    {sev:>10}: {n}")


def cosign_attest(image, predicate, attest_type, key, dry_run):
    cosign = require("cosign") or "cosign"
    cmd = [cosign, "attest", "--predicate", predicate, "--type", attest_type, image]
    if key:
        cmd[2:2] = ["--key", key]  # insert after 'attest'
    rc, _ = run(cmd, dry_run)
    return rc


def main():
    p = argparse.ArgumentParser(description="SBOM generate/scan/attest helper")
    p.add_argument("--dry-run", action="store_true")
    sub = p.add_subparsers(dest="cmd", required=True)

    g = sub.add_parser("generate", help="Generate an SBOM with Syft")
    g.add_argument("--source", required=True, help="image, dir:., file:..., etc.")
    g.add_argument("--format", default="cyclonedx-json")
    g.add_argument("--out", required=True)

    s = sub.add_parser("scan", help="Scan an SBOM with Grype")
    s.add_argument("--sbom", required=True)
    s.add_argument("--out", default="vulns.json")
    s.add_argument("--fail-on")
    s.add_argument("--only-fixed", action="store_true")

    pl = sub.add_parser("pipeline", help="generate -> scan -> summarize (+attest)")
    pl.add_argument("--source", required=True)
    pl.add_argument("--format", default="cyclonedx-json")
    pl.add_argument("--sbom-out", default="sbom.json")
    pl.add_argument("--vulns-out", default="vulns.json")
    pl.add_argument("--fail-on")
    pl.add_argument("--only-fixed", action="store_true")
    pl.add_argument("--attest-image", help="If set, attest the SBOM to this image")
    pl.add_argument("--attest-type", default="cyclonedx")
    pl.add_argument("--cosign-key")

    args = p.parse_args()

    if args.cmd == "generate":
        return syft_generate(args.source, args.format, args.out, args.dry_run)

    if args.cmd == "scan":
        rc, out = grype_scan(args.sbom, args.out, args.fail_on,
                             args.only_fixed, args.dry_run)
        if out:
            print_summary(summarize(out))
        return rc

    if args.cmd == "pipeline":
        rc = syft_generate(args.source, args.format, args.sbom_out, args.dry_run)
        if rc not in (0,) and not args.dry_run:
            print("[!] SBOM generation failed", file=sys.stderr)
            return rc
        scan_rc, out = grype_scan(args.sbom_out, args.vulns_out, args.fail_on,
                                  args.only_fixed, args.dry_run)
        if out:
            print_summary(summarize(out))
        if args.attest_image:
            cosign_attest(args.attest_image, args.sbom_out, args.attest_type,
                          args.cosign_key, args.dry_run)
        return scan_rc
    return 2


if __name__ == "__main__":
    sys.exit(main())
