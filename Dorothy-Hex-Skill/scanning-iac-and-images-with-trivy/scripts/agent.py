#!/usr/bin/env python3
"""Trivy scanning helper.

Wraps the Trivy CLI to scan container images, filesystems/IaC, and SBOMs,
parse the JSON results, summarise findings by severity, and exit non-zero
when findings at or above a chosen threshold are present (CI/CD gating).

Requires the `trivy` binary on PATH. See https://github.com/aquasecurity/trivy
"""

import argparse
import json
import shutil
import subprocess
import sys
from collections import Counter
from datetime import datetime, timezone

SEVERITY_ORDER = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]


def ensure_trivy() -> str:
    """Return the trivy executable path or exit with guidance."""
    path = shutil.which("trivy")
    if not path:
        print("[!] trivy not found on PATH. Install: "
              "https://trivy.dev/latest/getting-started/installation/",
              file=sys.stderr)
        sys.exit(2)
    return path


def build_command(trivy: str, args: argparse.Namespace) -> list:
    """Construct the trivy command line for the requested target."""
    cmd = [trivy, args.target]
    cmd += ["--scanners", args.scanners]
    if args.severity:
        cmd += ["--severity", args.severity]
    if args.ignore_unfixed:
        cmd.append("--ignore-unfixed")
    # Always request JSON so this helper can parse + gate deterministically.
    cmd += ["--format", "json"]
    # exit-code 0 here; gating is enforced in Python after parsing.
    cmd += ["--exit-code", "0"]
    cmd.append(args.subject)
    return cmd


def run_scan(cmd: list, timeout: int) -> dict:
    """Execute trivy and return the parsed JSON report."""
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        print(f"[!] Trivy scan timed out after {timeout}s", file=sys.stderr)
        sys.exit(3)
    if proc.returncode not in (0,):
        # Trivy writes scan results to stdout; real errors go to stderr.
        if not proc.stdout.strip():
            print(f"[!] Trivy failed (rc={proc.returncode}): {proc.stderr.strip()}",
                  file=sys.stderr)
            sys.exit(proc.returncode)
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError:
        print("[!] Could not parse Trivy JSON output.", file=sys.stderr)
        print(proc.stderr.strip(), file=sys.stderr)
        sys.exit(4)


def summarise(report: dict) -> tuple:
    """Return (severity Counter, list of finding dicts) from a Trivy report."""
    counts = Counter()
    findings = []
    for result in report.get("Results", []) or []:
        target = result.get("Target", "")
        for vuln in result.get("Vulnerabilities", []) or []:
            sev = (vuln.get("Severity") or "UNKNOWN").upper()
            counts[sev] += 1
            findings.append({
                "type": "vuln",
                "target": target,
                "id": vuln.get("VulnerabilityID"),
                "pkg": vuln.get("PkgName"),
                "installed": vuln.get("InstalledVersion"),
                "fixed": vuln.get("FixedVersion"),
                "severity": sev,
            })
        for mis in result.get("Misconfigurations", []) or []:
            sev = (mis.get("Severity") or "UNKNOWN").upper()
            counts[sev] += 1
            findings.append({
                "type": "misconfig",
                "target": target,
                "id": mis.get("ID"),
                "title": mis.get("Title"),
                "severity": sev,
            })
        for sec in result.get("Secrets", []) or []:
            sev = (sec.get("Severity") or "UNKNOWN").upper()
            counts[sev] += 1
            findings.append({
                "type": "secret",
                "target": target,
                "id": sec.get("RuleID"),
                "title": sec.get("Title"),
                "severity": sev,
            })
    return counts, findings


def gate(counts: Counter, threshold: str) -> bool:
    """Return True if any finding is at or above threshold severity."""
    if threshold not in SEVERITY_ORDER:
        return False
    idx = SEVERITY_ORDER.index(threshold)
    blocking = SEVERITY_ORDER[idx:]
    return any(counts.get(s, 0) > 0 for s in blocking)


def main() -> None:
    parser = argparse.ArgumentParser(description="Trivy scan + CI/CD gate helper")
    parser.add_argument("subject", help="Image ref, directory, repo URL, or SBOM file")
    parser.add_argument("--target", default="image",
                        choices=["image", "fs", "config", "repo", "sbom"],
                        help="Trivy scan target subcommand")
    parser.add_argument("--scanners", default="vuln",
                        help="Comma list: vuln,misconfig,secret,license")
    parser.add_argument("--severity", default="HIGH,CRITICAL",
                        help="Severities to include")
    parser.add_argument("--ignore-unfixed", action="store_true",
                        help="Skip vulns with no fix available")
    parser.add_argument("--gate", default="", choices=["", *SEVERITY_ORDER],
                        help="Exit non-zero if findings >= this severity")
    parser.add_argument("--timeout", type=int, default=600, help="Scan timeout (s)")
    parser.add_argument("--output", help="Write JSON summary to file")
    args = parser.parse_args()

    trivy = ensure_trivy()
    cmd = build_command(trivy, args)
    print(f"[*] {datetime.now(timezone.utc).isoformat()} running: {' '.join(cmd)}")
    report = run_scan(cmd, args.timeout)
    counts, findings = summarise(report)

    print("\n=== TRIVY FINDINGS BY SEVERITY ===")
    for sev in reversed(SEVERITY_ORDER):
        print(f"  {sev:<9}: {counts.get(sev, 0)}")
    print(f"  TOTAL    : {sum(counts.values())}")

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            json.dump({"counts": dict(counts), "findings": findings}, fh, indent=2)
        print(f"[+] Summary written to {args.output}")

    if args.gate and gate(counts, args.gate):
        print(f"[!] GATE FAILED: findings at or above {args.gate}", file=sys.stderr)
        sys.exit(1)
    print("[+] Scan complete.")


if __name__ == "__main__":
    main()
