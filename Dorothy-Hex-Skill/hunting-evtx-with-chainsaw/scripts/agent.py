#!/usr/bin/env python3
"""Chainsaw EVTX hunting helper.

Drives the Chainsaw binary to run a Sigma+Chainsaw hunt over a directory of
.evtx files, emits JSON, and summarizes detections by rule and level. Can also
run a targeted keyword/regex search to confirm a hypothesis.
"""

import argparse
import json
import os
import shutil
import subprocess
import sys
from collections import Counter
from datetime import datetime, timezone


def find_binary(explicit):
    """Locate the chainsaw binary."""
    if explicit:
        if os.path.isfile(explicit):
            return explicit
        sys.exit(f"[!] Binary not found: {explicit}")
    for name in ("chainsaw", "chainsaw.exe"):
        path = shutil.which(name)
        if path:
            return path
    # common build location
    local = os.path.join("target", "release", "chainsaw")
    if os.path.isfile(local):
        return local
    sys.exit("[!] chainsaw not found; pass --bin /path/to/chainsaw")


def run_json(cmd):
    """Run a chainsaw command expected to emit JSON on stdout."""
    print(f"[*] {' '.join(cmd)}", file=sys.stderr)
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0 and not proc.stdout.strip():
        print(proc.stderr[-1500:], file=sys.stderr)
        sys.exit(f"[!] chainsaw exited {proc.returncode}")
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError:
        return []


def hunt(binary, evtx, sigma, mapping, rules, level, status):
    cmd = [binary, "hunt", evtx, "-s", sigma, "--mapping", mapping, "--json"]
    if rules:
        cmd += ["-r", rules]
    if level:
        cmd += ["--level", level]
    if status:
        cmd += ["--status", status]
    return run_json(cmd)


def search(binary, evtx, pattern, regex, ignore_case):
    cmd = [binary, "search"]
    if regex:
        cmd += ["-e", pattern]
    else:
        cmd += [pattern]
    if ignore_case:
        cmd += ["-i"]
    cmd += [evtx, "--json"]
    return run_json(cmd)


def summarize(detections):
    """Summarize Chainsaw hunt JSON by rule name and level."""
    rules, levels = Counter(), Counter()
    total = 0
    for group in detections:
        # Chainsaw JSON groups detections; each carries name/level metadata
        name = group.get("name") or group.get("group") or "unknown"
        level = group.get("level", "unknown")
        docs = group.get("document") or group.get("documents") or [group]
        n = len(docs) if isinstance(docs, list) else 1
        total += n
        rules[name] += n
        levels[level] += n
    return {"total_hits": total,
            "by_level": dict(levels),
            "top_rules": rules.most_common(15)}


def main():
    p = argparse.ArgumentParser(description="Chainsaw EVTX hunting helper")
    p.add_argument("evtx", help="Directory or file of .evtx logs")
    p.add_argument("--bin", help="Path to chainsaw binary")
    p.add_argument("-s", "--sigma", help="SigmaHQ rules directory (for hunt)")
    p.add_argument("--mapping", help="Sigma->event mapping yml (for hunt)")
    p.add_argument("-r", "--rules", help="Chainsaw rules directory")
    p.add_argument("--level", help="Filter by Sigma level (e.g. high)")
    p.add_argument("--status", help="Filter by rule status (e.g. stable)")
    p.add_argument("--search", dest="search_pattern", help="Run a search instead of a hunt")
    p.add_argument("--regex", action="store_true", help="Treat --search as a regex")
    p.add_argument("-i", "--ignore-case", action="store_true")
    p.add_argument("--report", help="Write JSON output to this path")
    args = p.parse_args()

    binary = find_binary(args.bin)

    if args.search_pattern:
        results = search(binary, args.evtx, args.search_pattern,
                         args.regex, args.ignore_case)
        out = {"mode": "search", "pattern": args.search_pattern,
               "hits": len(results) if isinstance(results, list) else 0}
        print(f"[+] search hits: {out['hits']}")
    else:
        if not (args.sigma and args.mapping):
            p.error("hunt mode requires --sigma and --mapping")
        results = hunt(binary, args.evtx, args.sigma, args.mapping,
                       args.rules, args.level, args.status)
        out = summarize(results)
        out["mode"] = "hunt"
        print(f"[+] {out['total_hits']} hits across {len(out['top_rules'])} rules")
        print(f"[+] By level: {out['by_level']}")
        for name, count in out["top_rules"]:
            print(f"    {count:5d}  {name}")

    out["generated"] = datetime.now(timezone.utc).isoformat()
    if args.report:
        with open(args.report, "w") as f:
            json.dump({"summary": out, "raw": results}, f, indent=2)
        print(f"[+] Report written to {args.report}")


if __name__ == "__main__":
    main()
