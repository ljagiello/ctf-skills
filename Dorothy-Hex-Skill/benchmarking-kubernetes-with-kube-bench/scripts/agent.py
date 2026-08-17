#!/usr/bin/env python3
"""kube-bench helper.

Runs kube-bench with JSON output, parses the CIS Kubernetes Benchmark
results, summarises PASS/FAIL/WARN/INFO totals per section, lists failing
checks with their remediation, and optionally exits non-zero when failures
exist (for CI/CD compliance gating).

Requires the `kube-bench` binary on PATH (or run inside the aquasec/kube-bench
container). See https://github.com/aquasecurity/kube-bench
"""

import argparse
import json
import shutil
import subprocess
import sys
from collections import Counter
from datetime import datetime, timezone


def ensure_kube_bench() -> str:
    """Return the kube-bench path or exit with install guidance."""
    path = shutil.which("kube-bench")
    if not path:
        print("[!] kube-bench not found on PATH. Install: "
              "https://github.com/aquasecurity/kube-bench/releases",
              file=sys.stderr)
        sys.exit(2)
    return path


def run_kube_bench(binary: str, targets: str, benchmark: str, timeout: int) -> dict:
    """Execute kube-bench with JSON output and return the parsed report."""
    cmd = [binary, "run", "--targets", targets, "--json"]
    if benchmark:
        cmd += ["--benchmark", benchmark]
    print(f"[*] running: {' '.join(cmd)}")
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        print(f"[!] kube-bench timed out after {timeout}s", file=sys.stderr)
        sys.exit(3)
    # kube-bench may exit non-zero when checks fail; results are still on stdout.
    if not proc.stdout.strip():
        print(f"[!] kube-bench produced no output (rc={proc.returncode}): "
              f"{proc.stderr.strip()}", file=sys.stderr)
        sys.exit(proc.returncode or 4)
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError:
        print("[!] Could not parse kube-bench JSON output.", file=sys.stderr)
        print(proc.stderr.strip(), file=sys.stderr)
        sys.exit(4)


def iter_checks(report: dict):
    """Yield (section_id, section_text, check) tuples across all controls."""
    # kube-bench JSON: top-level "Controls" -> "tests" -> "results".
    controls = report.get("Controls")
    if controls is None and isinstance(report, list):
        controls = report
    for control in controls or []:
        for section in control.get("tests", []) or []:
            sid = section.get("section", "")
            stext = section.get("desc", "")
            for check in section.get("results", []) or []:
                yield sid, stext, check


def summarise(report: dict):
    """Return overall Counter, per-section Counters, and failing checks."""
    overall = Counter()
    per_section = {}
    failures = []
    for sid, stext, check in iter_checks(report):
        state = (check.get("status") or "").upper()
        overall[state] += 1
        per_section.setdefault(sid, [stext, Counter()])
        per_section[sid][1][state] += 1
        if state in ("FAIL", "WARN"):
            failures.append({
                "section": sid,
                "id": check.get("test_number"),
                "desc": check.get("test_desc"),
                "status": state,
                "remediation": (check.get("remediation") or "").strip(),
            })
    return overall, per_section, failures


def main() -> None:
    parser = argparse.ArgumentParser(description="kube-bench CIS compliance helper")
    parser.add_argument("--targets", default="master,node",
                        help="Comma list: master,node,etcd,policies,controlplane")
    parser.add_argument("--benchmark", default="", help="Pin benchmark, e.g. cis-1.8")
    parser.add_argument("--timeout", type=int, default=300, help="Run timeout (s)")
    parser.add_argument("--show-remediation", action="store_true",
                        help="Print remediation text for each failing check")
    parser.add_argument("--fail-on-warn", action="store_true",
                        help="Treat WARN as gating in addition to FAIL")
    parser.add_argument("--gate", action="store_true",
                        help="Exit non-zero when failing checks exist")
    parser.add_argument("--output", help="Write JSON summary to file")
    args = parser.parse_args()

    binary = ensure_kube_bench()
    report = run_kube_bench(binary, args.targets, args.benchmark, args.timeout)
    overall, per_section, failures = summarise(report)

    print(f"\n=== kube-bench summary {datetime.now(timezone.utc).isoformat()} ===")
    for state in ("PASS", "FAIL", "WARN", "INFO"):
        print(f"  {state:<5}: {overall.get(state, 0)}")

    print("\n--- Per section ---")
    for sid in sorted(per_section):
        text, counts = per_section[sid]
        print(f"  [{sid}] {text}: "
              f"PASS={counts.get('PASS',0)} FAIL={counts.get('FAIL',0)} "
              f"WARN={counts.get('WARN',0)}")

    print(f"\n--- Findings requiring action ({len(failures)}) ---")
    for f in failures:
        print(f"  {f['status']} {f['id']}: {f['desc']}")
        if args.show_remediation and f["remediation"]:
            print(f"      -> {f['remediation']}")

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            json.dump({"overall": dict(overall), "failures": failures}, fh, indent=2)
        print(f"[+] Summary written to {args.output}")

    if args.gate:
        blocking = overall.get("FAIL", 0)
        if args.fail_on_warn:
            blocking += overall.get("WARN", 0)
        if blocking > 0:
            print(f"[!] GATE FAILED: {blocking} non-compliant checks", file=sys.stderr)
            sys.exit(1)
    print("[+] Done.")


if __name__ == "__main__":
    main()
