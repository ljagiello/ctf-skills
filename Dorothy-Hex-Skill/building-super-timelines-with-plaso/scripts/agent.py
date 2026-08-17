#!/usr/bin/env python3
"""
Plaso super-timeline helper.

Builds and runs validated log2timeline.py / psort.py / psteal.py commands and
optionally imports the result into Timesketch with timesketch_importer. Supports
running the tools natively or through the official Docker image.

Reference: https://plaso.readthedocs.io/
"""
import argparse
import shutil
import subprocess
import sys
from pathlib import Path


def base_cmd(tool, use_docker, data_dir):
    """Return the argv prefix to invoke a plaso tool, native or via Docker."""
    if use_docker:
        # Mount data_dir at /data inside the container
        return ["docker", "run", "--rm", "-v", f"{data_dir}:/data",
                "log2timeline/plaso", tool]
    found = shutil.which(tool)
    if not found:
        print(f"[!] {tool} not on PATH; consider --docker", file=sys.stderr)
    return [tool]


def map_path(p, use_docker):
    """When using Docker, rewrite host paths under data_dir to /data/..."""
    # The caller is expected to pass paths relative to data_dir for Docker.
    return p


def extract(args):
    cmd = base_cmd("log2timeline.py", args.docker, args.data_dir)
    cmd += ["--storage-file", args.storage]
    if args.parsers:
        cmd += ["--parsers", args.parsers]
    if args.vss:
        cmd += ["--vss-stores", "all"]
    if args.hashers:
        cmd += ["--hashers", args.hashers]
    cmd.append(args.source)
    return run(cmd, args.dry_run)


def info(args):
    cmd = base_cmd("pinfo.py", args.docker, args.data_dir)
    cmd.append(args.storage)
    return run(cmd, args.dry_run)


def export(args):
    cmd = base_cmd("psort.py", args.docker, args.data_dir)
    cmd += ["--output-time-zone", args.tz, "-o", args.output_module,
            "-w", args.output, args.storage]
    if args.filter:
        cmd.append(args.filter)
    return run(cmd, args.dry_run)


def psteal(args):
    cmd = base_cmd("psteal.py", args.docker, args.data_dir)
    cmd += ["--source", args.source, "-o", args.output_module, "-w", args.output]
    return run(cmd, args.dry_run)


def tsimport(args):
    tool = shutil.which("timesketch_importer") or "timesketch_importer"
    cmd = [tool, "--host", args.host, "--username", args.username,
           "--timeline_name", args.timeline_name,
           "--sketch_id", str(args.sketch_id), args.file]
    return run(cmd, args.dry_run)


def run(cmd, dry_run):
    print("[*] " + " ".join(f'"{c}"' if " " in c else c for c in cmd))
    if dry_run:
        return 0
    try:
        return subprocess.run(cmd, check=False).returncode
    except FileNotFoundError:
        print(f"[!] command not found: {cmd[0]}", file=sys.stderr)
        return 127


def main():
    p = argparse.ArgumentParser(description="Plaso super-timeline helper")
    p.add_argument("--docker", action="store_true",
                   help="Run plaso tools via the log2timeline/plaso image")
    p.add_argument("--data-dir", default="/cases",
                   help="Host dir mounted at /data when using --docker")
    p.add_argument("--dry-run", action="store_true")
    sub = p.add_subparsers(dest="cmd", required=True)

    e = sub.add_parser("extract", help="log2timeline.py")
    e.add_argument("--source", required=True)
    e.add_argument("--storage", required=True)
    e.add_argument("--parsers")
    e.add_argument("--vss", action="store_true")
    e.add_argument("--hashers")
    e.set_defaults(func=extract)

    i = sub.add_parser("info", help="pinfo.py")
    i.add_argument("--storage", required=True)
    i.set_defaults(func=info)

    x = sub.add_parser("export", help="psort.py")
    x.add_argument("--storage", required=True)
    x.add_argument("--output", required=True)
    x.add_argument("--output-module", default="l2tcsv")
    x.add_argument("--tz", default="UTC")
    x.add_argument("--filter")
    x.set_defaults(func=export)

    s = sub.add_parser("psteal", help="psteal.py (extract+export)")
    s.add_argument("--source", required=True)
    s.add_argument("--output", required=True)
    s.add_argument("--output-module", default="l2tcsv")
    s.set_defaults(func=psteal)

    t = sub.add_parser("import", help="timesketch_importer")
    t.add_argument("--host", required=True)
    t.add_argument("--username", default="admin")
    t.add_argument("--timeline-name", dest="timeline_name", required=True)
    t.add_argument("--sketch-id", dest="sketch_id", type=int, required=True)
    t.add_argument("--file", required=True)
    t.set_defaults(func=tsimport)

    args = p.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
