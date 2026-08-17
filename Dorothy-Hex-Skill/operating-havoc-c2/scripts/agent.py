#!/usr/bin/env python3
"""
Havoc C2 team-server operator helper.

Automates common operator setup tasks around the Havoc Framework binary
(https://github.com/HavocFramework/Havoc):

  * validate a Yaotl profile for required blocks before launch
  * build the team server / client via `make ts-build` / `make client-build`
  * launch the team server with a profile (subprocess wrapper)
  * scaffold a starter Yaotl profile

Havoc exposes a binary (`./havoc`) rather than a stable Python library, so this
helper wraps the real CLI via subprocess with the documented flags.

Authorized red-team / lab use only.
"""

import argparse
import os
import re
import shutil
import subprocess
import sys


REQUIRED_BLOCKS = ["Teamserver", "Operators", "Listeners", "Demon"]


def validate_profile(path):
    """Check a Yaotl profile contains the blocks Havoc requires to start."""
    if not os.path.isfile(path):
        raise FileNotFoundError(f"profile not found: {path}")
    text = open(path, "r", encoding="utf-8", errors="replace").read()
    missing = []
    for block in REQUIRED_BLOCKS:
        # Yaotl block opens like:  BlockName {
        if not re.search(rf"\b{re.escape(block)}\b\s*\{{", text):
            missing.append(block)
    # Basic sanity: at least one operator password and one listener port
    has_password = re.search(r"Password\s*=", text) is not None
    has_port = re.search(r"Port(Bind|Conn|)\s*=", text) is not None
    if missing:
        print(f"[!] profile missing block(s): {', '.join(missing)}")
    if not has_password:
        print("[!] no operator Password = ... found")
    if not has_port:
        print("[!] no listener Port/PortBind/PortConn found")
    ok = not missing and has_password and has_port
    print("[+] profile looks valid" if ok else "[!] profile incomplete")
    return ok


def scaffold_profile(path, host, listener_host, port):
    """Write a minimal working Yaotl profile."""
    if os.path.exists(path):
        raise FileExistsError(f"refusing to overwrite existing file: {path}")
    profile = f'''Teamserver {{
    Host = "{host}"
    Port = 40056

    Build {{
        Compiler64 = "/usr/bin/x86_64-w64-mingw32-gcc"
        Nasm = "/usr/bin/nasm"
    }}
}}

Operators {{
    user "operator1" {{
        Password = "CHANGE_ME_Str0ng!"
    }}
}}

Listeners {{
    Http {{
        Name     = "https-listener"
        Hosts    = ["{listener_host}"]
        HostBind = "0.0.0.0"
        PortBind = {port}
        PortConn = {port}
        Secure   = true
    }}
}}

Demon {{
    Sleep = 30
    Jitter = 25
    Injection {{
        Spawn64 = "C:\\\\Windows\\\\System32\\\\notepad.exe"
        Spawn32 = "C:\\\\Windows\\\\SysWOW64\\\\notepad.exe"
    }}
}}
'''
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(profile)
    print(f"[+] wrote starter profile: {path}")
    print("[!] change the operator Password before use.")


def run_make(havoc_dir, target):
    """Run a make build target inside the Havoc repo."""
    if shutil.which("make") is None:
        raise RuntimeError("`make` not found on PATH")
    if not os.path.isdir(havoc_dir):
        raise NotADirectoryError(f"Havoc dir not found: {havoc_dir}")
    print(f"[*] running: make {target} (cwd={havoc_dir})")
    return subprocess.call(["make", target], cwd=havoc_dir)


def launch_server(havoc_bin, profile, verbose, debug):
    """Launch the Havoc team server with the documented flags."""
    if not os.path.isfile(havoc_bin):
        raise FileNotFoundError(f"havoc binary not found: {havoc_bin}")
    if not validate_profile(profile):
        print("[!] profile failed validation; aborting launch")
        return 2
    cmd = [havoc_bin, "server", "--profile", profile]
    if verbose:
        cmd.append("--verbose")
    if debug:
        cmd.append("--debug")
    print(f"[*] launching: {' '.join(cmd)}")
    try:
        return subprocess.call(cmd)
    except KeyboardInterrupt:
        print("\n[*] team server interrupted by operator")
        return 0


def build_parser():
    p = argparse.ArgumentParser(description="Havoc C2 operator helper.")
    sub = p.add_subparsers(dest="action", required=True)

    v = sub.add_parser("validate", help="validate a Yaotl profile")
    v.add_argument("profile")

    s = sub.add_parser("scaffold", help="write a starter Yaotl profile")
    s.add_argument("profile")
    s.add_argument("--host", default="0.0.0.0", help="team server bind host")
    s.add_argument("--listener-host", default="c2.example.com",
                   help="Demon callback host")
    s.add_argument("--port", type=int, default=443, help="listener port")

    b = sub.add_parser("build", help="run make ts-build / client-build")
    b.add_argument("--dir", default=".", help="path to cloned Havoc repo")
    b.add_argument("--target", choices=["ts-build", "client-build"],
                   default="ts-build")

    r = sub.add_parser("serve", help="launch the team server")
    r.add_argument("--bin", default="./havoc", help="path to havoc binary")
    r.add_argument("--profile", required=True, help="Yaotl profile path")
    r.add_argument("--verbose", action="store_true")
    r.add_argument("--debug", action="store_true")

    return p


def main():
    args = build_parser().parse_args()
    try:
        if args.action == "validate":
            sys.exit(0 if validate_profile(args.profile) else 1)
        elif args.action == "scaffold":
            scaffold_profile(args.profile, args.host, args.listener_host,
                             args.port)
        elif args.action == "build":
            sys.exit(run_make(args.dir, args.target))
        elif args.action == "serve":
            sys.exit(launch_server(args.bin, args.profile, args.verbose,
                                   args.debug))
    except (FileNotFoundError, FileExistsError, NotADirectoryError,
            RuntimeError) as exc:
        sys.stderr.write(f"[!] {exc}\n")
        sys.exit(2)


if __name__ == "__main__":
    main()
