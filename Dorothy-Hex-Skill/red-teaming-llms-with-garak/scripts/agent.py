#!/usr/bin/env python3
"""
garak red-team automation helper.

Wraps the NVIDIA garak LLM vulnerability scanner (https://github.com/NVIDIA/garak)
via subprocess to run a scoped probe suite against a target model, then parses the
resulting .report.jsonl to rank findings by hit rate. Use only against models you
are authorized to test.

Examples:
  python agent.py run --target-type openai --target-name gpt-4o-mini \
      --probes promptinject,dan,leakreplay --report-prefix assessment
  python agent.py parse --report assessment.report.jsonl
  python agent.py list-probes
"""
import argparse
import glob
import json
import os
import shutil
import subprocess
import sys
from collections import defaultdict


def _garak_cmd():
    """Return the command prefix to invoke garak (prefer the module form)."""
    if shutil.which("garak"):
        return ["garak"]
    return [sys.executable, "-m", "garak"]


def list_probes(_args):
    cmd = _garak_cmd() + ["--list_probes"]
    try:
        subprocess.run(cmd, check=True)
    except FileNotFoundError:
        sys.exit("garak is not installed. Run: python -m pip install -U garak")
    except subprocess.CalledProcessError as exc:
        sys.exit(f"garak --list_probes failed with exit code {exc.returncode}")


def run_scan(args):
    cmd = _garak_cmd()
    cmd += ["--target_type", args.target_type, "--target_name", args.target_name]
    if args.probes:
        cmd += ["--probes", args.probes]
    if args.generations:
        cmd += ["--generations", str(args.generations)]
    if args.parallel_attempts:
        cmd += ["--parallel_attempts", str(args.parallel_attempts)]
    if args.generator_option_file:
        cmd += ["-G", args.generator_option_file]
    if args.report_prefix:
        cmd += ["--report_prefix", args.report_prefix]

    if args.target_type == "openai" and not os.environ.get("OPENAI_API_KEY"):
        print("[!] OPENAI_API_KEY is not set; openai target will fail.", file=sys.stderr)

    print("[*] Executing:", " ".join(cmd))
    try:
        result = subprocess.run(cmd, check=False)
    except FileNotFoundError:
        sys.exit("garak is not installed. Run: python -m pip install -U garak")
    if result.returncode != 0:
        print(f"[!] garak exited non-zero ({result.returncode}); a non-zero exit "
              "can indicate findings were detected.", file=sys.stderr)

    # Locate the most recent matching report and summarize it.
    pattern = f"{args.report_prefix}*.report.jsonl" if args.report_prefix else "garak.*.report.jsonl"
    reports = sorted(glob.glob(pattern), key=os.path.getmtime)
    if reports:
        print(f"[*] Parsing latest report: {reports[-1]}")
        _summarize(reports[-1])
    else:
        print("[!] No report.jsonl found to summarize.", file=sys.stderr)


def _summarize(report_path):
    """Aggregate garak eval rows into per-probe/detector hit rates."""
    if not os.path.exists(report_path):
        sys.exit(f"Report not found: {report_path}")

    rows = []
    with open(report_path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if obj.get("entry_type") == "eval":
                rows.append(obj)

    if not rows:
        print("[!] No eval rows found in report (run may be incomplete).")
        return

    findings = []
    for r in rows:
        probe = r.get("probe", "?")
        detector = r.get("detector", "?")
        passed = r.get("passed", 0)
        total = r.get("total", 0) or 1
        hit_rate = 1.0 - (passed / total)  # fraction of attempts that succeeded as attacks
        findings.append((hit_rate, probe, detector, passed, total))

    findings.sort(reverse=True)
    print("\n=== garak findings (ranked by attack success rate) ===")
    print(f"{'HIT%':>6}  {'PROBE':<40} {'DETECTOR':<28} PASS/TOTAL")
    for hit_rate, probe, detector, passed, total in findings:
        sev = "HIGH" if hit_rate >= 0.5 else "MED " if hit_rate >= 0.1 else "low "
        print(f"{hit_rate*100:6.1f}  {probe:<40} {detector:<28} {passed}/{total}  [{sev}]")


def parse_report(args):
    _summarize(args.report)


def build_parser():
    p = argparse.ArgumentParser(description="garak red-team automation helper")
    sub = p.add_subparsers(dest="command", required=True)

    lp = sub.add_parser("list-probes", help="List garak probes")
    lp.set_defaults(func=list_probes)

    rs = sub.add_parser("run", help="Run a garak scan and summarize")
    rs.add_argument("--target-type", required=True, help="e.g. openai, huggingface, rest")
    rs.add_argument("--target-name", required=True, help="model name")
    rs.add_argument("--probes", help="comma-separated probe spec")
    rs.add_argument("--generations", type=int, default=0)
    rs.add_argument("--parallel-attempts", type=int, default=0)
    rs.add_argument("--generator-option-file", help="JSON generator spec (-G), e.g. rest.json")
    rs.add_argument("--report-prefix", default="garak_run")
    rs.set_defaults(func=run_scan)

    pr = sub.add_parser("parse", help="Parse an existing report.jsonl")
    pr.add_argument("--report", required=True)
    pr.set_defaults(func=parse_report)
    return p


def main():
    args = build_parser().parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
