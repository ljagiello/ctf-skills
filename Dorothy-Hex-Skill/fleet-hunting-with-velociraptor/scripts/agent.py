#!/usr/bin/env python3
"""
Velociraptor fleet-hunting helper.

Wraps the velociraptor binary to: run ad-hoc VQL queries, list/collect
artifacts, validate custom artifact YAML, and scaffold a custom hunt artifact.
All commands are real velociraptor subcommands.

Reference: https://docs.velociraptor.app/
"""
import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path

try:
    import yaml  # PyYAML, used only for --validate
except ImportError:
    yaml = None


def find_binary(explicit):
    """Locate the velociraptor binary."""
    if explicit:
        return explicit
    for name in ("velociraptor", "velociraptor.exe"):
        path = shutil.which(name)
        if path:
            return path
    return None


def run_query(binary, vql, fmt="json", dry_run=False):
    """Run a VQL query via `velociraptor query`."""
    cmd = [binary, "query", vql]
    if fmt:
        cmd += ["--format", fmt]
    return _exec(cmd, dry_run, capture=True)


def list_artifacts(binary, dry_run=False):
    return _exec([binary, "artifacts", "list"], dry_run, capture=True)


def collect_artifact(binary, name, output, dry_run=False):
    cmd = [binary, "artifacts", "collect", name, "--output", output]
    return _exec(cmd, dry_run, capture=False)


def validate_artifact(path):
    """Validate a custom artifact YAML has the required structure."""
    if yaml is None:
        print("[!] PyYAML not installed; run: pip install pyyaml", file=sys.stderr)
        return 2
    try:
        doc = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    except Exception as e:
        print(f"[!] YAML parse error: {e}", file=sys.stderr)
        return 1
    errors = []
    if not isinstance(doc, dict):
        errors.append("top-level document must be a mapping")
        doc = {}
    if not doc.get("name"):
        errors.append("missing required 'name'")
    sources = doc.get("sources")
    if not sources or not isinstance(sources, list):
        errors.append("missing 'sources' list")
    else:
        for i, s in enumerate(sources):
            if not isinstance(s, dict) or "query" not in s:
                errors.append(f"sources[{i}] missing 'query'")
    if errors:
        for e in errors:
            print(f"[!] {e}", file=sys.stderr)
        return 1
    print(f"[+] Artifact '{doc['name']}' is structurally valid "
          f"({len(sources)} source(s)).")
    return 0


def scaffold(name, regex):
    """Emit a custom hunt artifact YAML to stdout."""
    doc = {
        "name": name,
        "description": "Auto-generated fleet hunt artifact.",
        "parameters": [{"name": "regex", "default": regex}],
        "sources": [{
            "query": (
                "SELECT Pid, Name, CommandLine, "
                "timestamp(epoch=now()) AS Collected\n"
                "FROM pslist()\n"
                "WHERE Name =~ \"powershell\" AND CommandLine =~ regex\n"
            )
        }],
    }
    if yaml:
        print(yaml.safe_dump(doc, sort_keys=False))
    else:
        print(json.dumps(doc, indent=2))
    return 0


def _exec(cmd, dry_run, capture):
    print("[*] " + " ".join(cmd), file=sys.stderr)
    if dry_run:
        return 0
    try:
        if capture:
            proc = subprocess.run(cmd, check=False, text=True,
                                  capture_output=True)
            if proc.stdout:
                print(proc.stdout)
            if proc.returncode != 0 and proc.stderr:
                print(proc.stderr, file=sys.stderr)
            return proc.returncode
        return subprocess.run(cmd, check=False).returncode
    except FileNotFoundError:
        print(f"[!] binary not found: {cmd[0]}", file=sys.stderr)
        return 127


def main():
    p = argparse.ArgumentParser(description="Velociraptor fleet-hunting helper")
    p.add_argument("--binary", help="Path to velociraptor binary")
    p.add_argument("--dry-run", action="store_true")
    sub = p.add_subparsers(dest="cmd", required=True)

    q = sub.add_parser("query", help="Run a VQL query")
    q.add_argument("vql")
    q.add_argument("--format", default="json")

    sub.add_parser("artifacts", help="List artifacts")

    c = sub.add_parser("collect", help="Collect an artifact")
    c.add_argument("name")
    c.add_argument("--output", default="results.zip")

    v = sub.add_parser("validate", help="Validate a custom artifact YAML")
    v.add_argument("path")

    s = sub.add_parser("scaffold", help="Emit a custom hunt artifact")
    s.add_argument("--name", default="Custom.Hunt.SuspiciousPowershell")
    s.add_argument("--regex",
                   default="(?i)(-enc|frombase64string|downloadstring|-w hidden|iex)")

    args = p.parse_args()

    if args.cmd == "validate":
        return validate_artifact(args.path)
    if args.cmd == "scaffold":
        return scaffold(args.name, args.regex)

    binary = find_binary(args.binary)
    if not binary:
        print("[!] velociraptor binary not found (use --binary)", file=sys.stderr)
        return 127

    if args.cmd == "query":
        return run_query(binary, args.vql, args.format, args.dry_run)
    if args.cmd == "artifacts":
        return list_artifacts(binary, args.dry_run)
    if args.cmd == "collect":
        return collect_artifact(binary, args.name, args.output, args.dry_run)
    return 2


if __name__ == "__main__":
    sys.exit(main())
