#!/usr/bin/env python3
"""
Falco rule helper: validate custom rules and triage Falco JSON output.

Two modes:
  --validate <rules.yaml>  : structurally check a Falco rules file (and run
                             `falco --validate` if the falco binary is present).
  --triage <alerts.json>   : parse Falco JSON-formatted alerts (one JSON object
                             per line, as emitted with `json_output: true`) and
                             summarize by rule, priority, and container.

Defensive detection-engineering tool.

Examples:
  python agent.py --validate ./falco_rules.local.yaml
  python agent.py --triage /var/log/falco/events.json --min-priority WARNING
"""
import argparse
import json
import shutil
import subprocess
import sys
from collections import Counter

PRIORITIES = ["DEBUG", "INFO", "NOTICE", "WARNING", "ERROR",
              "CRITICAL", "ALERT", "EMERGENCY"]
REQUIRED_RULE_FIELDS = {"rule", "desc", "condition", "output", "priority"}


def validate_rules(path):
    try:
        import yaml
    except ImportError:
        sys.exit("error: PyYAML required for --validate. Install: pip install pyyaml")

    try:
        with open(path, "r", encoding="utf-8") as fh:
            docs = list(yaml.safe_load_all(fh))
    except (OSError, yaml.YAMLError) as exc:
        sys.exit(f"error: cannot parse {path}: {exc}")

    items = []
    for doc in docs:
        if isinstance(doc, list):
            items.extend(doc)
        elif isinstance(doc, dict):
            items.append(doc)

    rules = [i for i in items if isinstance(i, dict) and "rule" in i]
    macros = [i for i in items if isinstance(i, dict) and "macro" in i]
    lists = [i for i in items if isinstance(i, dict) and "list" in i]
    print(f"[+] parsed {len(rules)} rule(s), {len(macros)} macro(s), {len(lists)} list(s)")

    errors = 0
    for r in rules:
        missing = REQUIRED_RULE_FIELDS - set(r.keys())
        if missing:
            print(f"  [!] rule '{r.get('rule')}' missing fields: {sorted(missing)}")
            errors += 1
        prio = str(r.get("priority", "")).upper()
        if prio and prio not in PRIORITIES:
            print(f"  [!] rule '{r.get('rule')}' invalid priority: {prio}")
            errors += 1

    # If the falco binary is available, run the authoritative validator.
    if shutil.which("falco"):
        print("[*] running 'falco --validate' ...")
        try:
            proc = subprocess.run(["falco", "--validate", path],
                                  capture_output=True, text=True, timeout=60)
            sys.stdout.write(proc.stdout)
            sys.stderr.write(proc.stderr)
            if proc.returncode != 0:
                errors += 1
        except (OSError, subprocess.TimeoutExpired) as exc:
            print(f"  [!] could not run falco --validate: {exc}")
    else:
        print("[i] falco binary not found; performed structural validation only")

    if errors:
        print(f"[!] validation found {errors} issue(s)")
        sys.exit(1)
    print("[+] rules look structurally valid")


def triage_alerts(path, min_priority):
    threshold = PRIORITIES.index(min_priority.upper()) if min_priority else 0
    by_rule = Counter()
    by_priority = Counter()
    by_container = Counter()
    total = kept = 0

    try:
        fh = open(path, "r", encoding="utf-8")
    except OSError as exc:
        sys.exit(f"error: cannot open {path}: {exc}")

    with fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            total += 1
            try:
                ev = json.loads(line)
            except json.JSONDecodeError:
                continue
            prio = str(ev.get("priority", "")).upper()
            if prio in PRIORITIES and PRIORITIES.index(prio) < threshold:
                continue
            kept += 1
            by_rule[ev.get("rule", "<unknown>")] += 1
            by_priority[prio or "<none>"] += 1
            fields = ev.get("output_fields") or {}
            cname = fields.get("container.name") or fields.get("container.id") or "host"
            by_container[cname] += 1

    print(f"[+] parsed {total} alert lines, {kept} at/above {min_priority or 'DEBUG'}\n")
    print("== By priority ==")
    for p, c in sorted(by_priority.items(), key=lambda x: -x[1]):
        print(f"  {p:10s} {c}")
    print("\n== Top rules ==")
    for r, c in by_rule.most_common(15):
        print(f"  {c:5d}  {r}")
    print("\n== Top containers ==")
    for cn, c in by_container.most_common(15):
        print(f"  {c:5d}  {cn}")


def main():
    p = argparse.ArgumentParser(description="Falco rule validator / alert triage")
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("--validate", metavar="RULES_YAML", help="validate a Falco rules file")
    g.add_argument("--triage", metavar="ALERTS_JSON", help="triage Falco JSON output")
    p.add_argument("--min-priority", default="DEBUG",
                   help="minimum priority to include in triage")
    args = p.parse_args()

    if args.validate:
        validate_rules(args.validate)
    else:
        triage_alerts(args.triage, args.min_priority)


if __name__ == "__main__":
    main()
