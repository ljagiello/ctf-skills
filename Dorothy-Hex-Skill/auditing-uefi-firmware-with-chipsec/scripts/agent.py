#!/usr/bin/env python3
"""
chipsec-audit — run a CHIPSEC firmware-posture baseline and parse results.

Wraps the real CHIPSEC CLIs:
  - chipsec_main : module runner
  - chipsec_util : SPI/UEFI utilities
Project: https://github.com/chipsec/chipsec

Install:
    pip install chipsec     # needs root and a kernel driver build

Examples:
    sudo python agent.py baseline --log chipsec.log --json report.json
    sudo python agent.py module --name common.bios_wp
    sudo python agent.py dump --out rom.bin
"""
import argparse
import json
import os
import re
import shutil
import subprocess
import sys

# CHIPSEC prints lines like:  [+] PASSED: BIOS region write protection ...
RESULT_RE = re.compile(r"\[[+\-!*]\]\s*(PASSED|FAILED|WARNING|ERROR|NOT APPLICABLE|INFORMATION)\b[:\s]*(.*)",
                       re.IGNORECASE)

CORE_MODULES = [
    "common.bios_wp",
    "common.spi_lock",
    "common.spi_desc",
    "common.smm",
    "common.secureboot.variables",
]


def _require(tool: str) -> None:
    if shutil.which(tool) is None:
        sys.exit(f"error: '{tool}' not found on PATH. Install CHIPSEC: pip install chipsec")


def _warn_root() -> None:
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        print("[!] warning: CHIPSEC needs root/Administrator to load its driver.", file=sys.stderr)


def _run(argv: list) -> subprocess.CompletedProcess:
    print(f"[*] {' '.join(argv)}", file=sys.stderr)
    return subprocess.run(argv, capture_output=True, text=True)


def parse_results(stdout: str) -> list:
    findings = []
    for line in stdout.splitlines():
        m = RESULT_RE.search(line)
        if m:
            findings.append({"result": m.group(1).upper(), "detail": m.group(2).strip()})
    return findings


def cmd_baseline(args) -> int:
    _require("chipsec_main")
    _warn_root()
    argv = ["chipsec_main"]
    if args.log:
        argv += ["-l", args.log]
    proc = _run(argv)
    findings = parse_results(proc.stdout)
    fails = [f for f in findings if f["result"] in ("FAILED", "ERROR")]
    warns = [f for f in findings if f["result"] == "WARNING"]
    summary = {
        "total_results": len(findings),
        "failed": len(fails),
        "warnings": len(warns),
        "failures": fails,
        "warning_items": warns,
    }
    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump({"summary": summary, "all": findings}, fh, indent=2)
        print(f"[+] report written to {args.json}", file=sys.stderr)
    print(json.dumps(summary, indent=2))
    return 1 if fails else 0


def cmd_module(args) -> int:
    _require("chipsec_main")
    _warn_root()
    targets = [args.name] if args.name else CORE_MODULES
    out = {}
    rc = 0
    for mod in targets:
        proc = _run(["chipsec_main", "-m", mod])
        res = parse_results(proc.stdout)
        out[mod] = res
        if any(r["result"] in ("FAILED", "ERROR") for r in res):
            rc = 1
    print(json.dumps(out, indent=2))
    return rc


def cmd_dump(args) -> int:
    _require("chipsec_util")
    _warn_root()
    _run(["chipsec_util", "spi", "info"])
    proc = _run(["chipsec_util", "spi", "dump", args.out])
    if proc.returncode != 0 or not os.path.exists(args.out):
        print("[!] SPI dump failed", file=sys.stderr)
        print(proc.stderr, file=sys.stderr)
        return 1
    size = os.path.getsize(args.out)
    print(json.dumps({"dump": args.out, "bytes": size}, indent=2))
    print("[*] decode offline with: chipsec_util uefi decode " + args.out, file=sys.stderr)
    return 0


def main() -> int:
    p = argparse.ArgumentParser(description="CHIPSEC firmware-posture audit helper.")
    sub = p.add_subparsers(dest="cmd", required=True)

    b = sub.add_parser("baseline", help="run full chipsec_main and summarize")
    b.add_argument("--log", help="CHIPSEC log file path")
    b.add_argument("--json", help="write parsed JSON report here")
    b.set_defaults(func=cmd_baseline)

    m = sub.add_parser("module", help="run one or the core security modules")
    m.add_argument("--name", help="specific module, e.g. common.bios_wp (default: core set)")
    m.set_defaults(func=cmd_module)

    d = sub.add_parser("dump", help="dump SPI flash (read-only)")
    d.add_argument("--out", default="rom.bin")
    d.set_defaults(func=cmd_dump)

    args = p.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
