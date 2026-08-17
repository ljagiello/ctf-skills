#!/usr/bin/env python3
"""
EZ Tools batch driver.

Runs Eric Zimmerman's forensic parsers over a KAPE-style collection or mounted
image, writing per-artifact CSV/JSON into an output tree. Each command uses the
real EZ Tools flags. Works as a dry-run command generator on any platform.

Reference: https://ericzimmerman.github.io/
"""
import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path

# Map of artifact -> (tool exe, builder(collection_root, out_dir) -> argv)
def _mft(tool, root, out):
    mft = os.path.join(root, "$MFT")
    return [tool, "-f", mft, "--csv", out, "--csvf", "MFT.csv"]

def _usn(tool, root, out):
    j = os.path.join(root, "$Extend", "$J")
    return [tool, "-f", j, "--csv", out, "--csvf", "UsnJrnl.csv"]

def _prefetch(tool, root, out):
    d = os.path.join(root, "Windows", "Prefetch")
    return [tool, "-d", d, "--csv", out, "--csvf", "Prefetch.csv",
            "--json", os.path.join(out, "json")]

def _amcache(tool, root, out):
    f = os.path.join(root, "Windows", "AppCompat", "Programs", "Amcache.hve")
    return [tool, "-f", f, "--csv", out, "-i"]

def _shimcache(tool, root, out):
    f = os.path.join(root, "Windows", "System32", "config", "SYSTEM")
    return [tool, "-f", f, "--csv", out]

def _evtx(tool, root, out):
    d = os.path.join(root, "Windows", "System32", "winevt", "Logs")
    return [tool, "-d", d, "--csv", out, "--csvf", "EventLogs.csv"]

def _registry(tool, root, out, batch):
    d = os.path.join(root, "Windows", "System32", "config")
    return [tool, "-d", d, "--bn", batch, "--csv", out, "--csvf", "Registry.csv"]


ARTIFACTS = {
    "mft":       ("MFTECmd.exe", _mft),
    "usn":       ("MFTECmd.exe", _usn),
    "prefetch":  ("PECmd.exe", _prefetch),
    "amcache":   ("AmcacheParser.exe", _amcache),
    "shimcache": ("AppCompatCacheParser.exe", _shimcache),
    "evtx":      ("EvtxECmd.exe", _evtx),
}


def resolve_tool(tools_dir, exe):
    """Find a tool either in tools_dir or on PATH."""
    if tools_dir:
        candidate = Path(tools_dir) / exe
        if candidate.exists():
            return str(candidate)
        # also try without .exe on Linux .NET builds
        alt = Path(tools_dir) / exe.replace(".exe", "")
        if alt.exists():
            return str(alt)
    found = shutil.which(exe) or shutil.which(exe.replace(".exe", ""))
    return found or str(Path(tools_dir or ".") / exe)


def run_one(name, tools_dir, root, out_root, batch, dry_run):
    exe, builder = ARTIFACTS[name]
    tool = resolve_tool(tools_dir, exe)
    out = os.path.join(out_root, name)
    os.makedirs(out, exist_ok=True)
    if name == "registry":
        cmd = _registry(tool, root, out, batch)
    else:
        cmd = builder(tool, root, out)
    print("[*] " + " ".join(f'"{c}"' if " " in c else c for c in cmd))
    if dry_run:
        return 0
    try:
        return subprocess.run(cmd, check=False).returncode
    except FileNotFoundError:
        print(f"[!] tool not found: {tool}", file=sys.stderr)
        return 127


def main():
    p = argparse.ArgumentParser(description="EZ Tools batch driver")
    p.add_argument("--collection", required=True,
                   help="Root of the collection (the 'C' directory)")
    p.add_argument("--out", required=True, help="Output root directory")
    p.add_argument("--tools-dir", help="Directory containing EZ Tools binaries")
    p.add_argument("--batch", help="RECmd batch (.reb) file for registry")
    p.add_argument("--artifacts", default="mft,prefetch,amcache,shimcache,evtx",
                   help="Comma-separated: " + ",".join(list(ARTIFACTS) + ["registry"]))
    p.add_argument("--dry-run", action="store_true")
    args = p.parse_args()

    if not os.path.isdir(args.collection):
        print(f"[!] collection not found: {args.collection}", file=sys.stderr)
        return 2
    os.makedirs(args.out, exist_ok=True)

    requested = [a.strip() for a in args.artifacts.split(",") if a.strip()]
    rc = 0
    for name in requested:
        if name == "registry":
            if not args.batch:
                print("[!] registry requires --batch (.reb file); skipping",
                      file=sys.stderr)
                rc = rc or 2
                continue
            r = run_one("registry", args.tools_dir, args.collection, args.out,
                        args.batch, args.dry_run)
        elif name in ARTIFACTS:
            r = run_one(name, args.tools_dir, args.collection, args.out,
                        args.batch, args.dry_run)
        else:
            print(f"[!] unknown artifact: {name}", file=sys.stderr)
            r = 2
        rc = rc or r
    print(f"[+] done (exit {rc})")
    return rc


if __name__ == "__main__":
    sys.exit(main())
