#!/usr/bin/env python3
"""Hayabusa timeline helper.

Drives the Hayabusa binary to update rules and generate a CSV (and optionally
JSONL) forensic timeline from a directory of .evtx files, then summarizes the
detections by severity and top rule titles for fast triage.
"""

import argparse
import csv
import json
import os
import shutil
import subprocess
import sys
from collections import Counter
from datetime import datetime, timezone


def find_binary(explicit):
    """Locate the hayabusa binary."""
    if explicit:
        if os.path.isfile(explicit):
            return explicit
        sys.exit(f"[!] Binary not found: {explicit}")
    for name in ("hayabusa", "hayabusa.exe"):
        path = shutil.which(name)
        if path:
            return path
    sys.exit("[!] hayabusa not found on PATH; pass --bin /path/to/hayabusa")


def run(cmd):
    """Run a subprocess and stream a short status line."""
    print(f"[*] {' '.join(cmd)}")
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        print(proc.stderr[-1000:], file=sys.stderr)
    return proc


def update_rules(binary):
    run([binary, "update-rules"])


def csv_timeline(binary, src, out, profile, min_level, live):
    cmd = [binary, "csv-timeline", "-o", out, "-p", profile,
           "-m", min_level, "-w", "-U"]
    cmd += ["-l"] if live else ["-d", src]
    proc = run(cmd)
    if not os.path.isfile(out):
        sys.exit(f"[!] Timeline not produced. {proc.stderr[-500:]}")
    return out


def json_timeline(binary, src, out, profile, min_level, live):
    cmd = [binary, "json-timeline", "-L", "-o", out, "-p", profile,
           "-m", min_level, "-w"]
    cmd += ["-l"] if live else ["-d", src]
    run(cmd)
    return out


def summarize_csv(path):
    """Summarize a Hayabusa CSV timeline by level and rule title."""
    levels, titles = Counter(), Counter()
    total = 0
    with open(path, newline="", encoding="utf-8", errors="replace") as f:
        reader = csv.DictReader(f)
        # Hayabusa columns include "Level" and "RuleTitle"
        lvl_key = next((k for k in (reader.fieldnames or []) if k.lower() == "level"), None)
        title_key = next((k for k in (reader.fieldnames or [])
                          if k.lower().replace(" ", "") == "ruletitle"), None)
        for row in reader:
            total += 1
            if lvl_key:
                levels[row.get(lvl_key, "")] += 1
            if title_key:
                titles[row.get(title_key, "")] += 1
    return {"total_detections": total,
            "by_level": dict(levels),
            "top_rules": titles.most_common(15)}


def main():
    p = argparse.ArgumentParser(description="Hayabusa timeline helper")
    p.add_argument("-d", "--directory", help="Directory of .evtx files")
    p.add_argument("--live", action="store_true", help="Live-analyze local logs")
    p.add_argument("--bin", help="Path to hayabusa binary")
    p.add_argument("-o", "--output", default="timeline.csv", help="CSV output path")
    p.add_argument("--jsonl", help="Also write a JSONL timeline to this path")
    p.add_argument("-p", "--profile", default="verbose",
                   help="Output profile (minimal/standard/verbose/...)")
    p.add_argument("-m", "--min-level", default="medium",
                   choices=["informational", "low", "medium", "high", "critical"])
    p.add_argument("--no-update", action="store_true", help="Skip update-rules")
    p.add_argument("--report", help="Write JSON summary to this path")
    args = p.parse_args()

    if not args.live and not args.directory:
        p.error("provide -d/--directory or --live")

    binary = find_binary(args.bin)
    if not args.no_update:
        update_rules(binary)

    csv_path = csv_timeline(binary, args.directory, args.output,
                            args.profile, args.min_level, args.live)
    if args.jsonl:
        json_timeline(binary, args.directory, args.jsonl,
                      args.profile, args.min_level, args.live)

    summary = summarize_csv(csv_path)
    summary["generated"] = datetime.now(timezone.utc).isoformat()
    summary["timeline"] = csv_path

    print(f"\n[+] {summary['total_detections']} detections")
    print(f"[+] By level: {summary['by_level']}")
    print("[+] Top rules:")
    for title, count in summary["top_rules"]:
        print(f"    {count:5d}  {title}")

    if args.report:
        with open(args.report, "w") as f:
            json.dump(summary, f, indent=2)
        print(f"[+] Summary written to {args.report}")


if __name__ == "__main__":
    main()
