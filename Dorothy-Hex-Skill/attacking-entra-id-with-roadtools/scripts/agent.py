#!/usr/bin/env python3
"""ROADtools engagement orchestrator.

Authorized Entra ID assessment helper. Wraps the real roadrecon/roadtx binaries
to run an authenticated recon pass and a token-exchange pivot, then parses token
claims. Requires `roadrecon` and `roadtx` on PATH (pip install roadrecon roadtx).

Examples
--------
    python agent.py recon --device-code --gather --bloodhound
    python agent.py recon -u user@tenant.com -p 'Pass!' --gather
    python agent.py tokens -u user@tenant.com -p 'Pass!' -c azcli -r msgraph
    python agent.py pivot -r azrm          # exchange stored RT to ARM
    python agent.py describe                # decode .roadtools_auth token
"""
import argparse
import json
import shutil
import subprocess
import sys


def require(binary):
    if shutil.which(binary) is None:
        sys.exit(f"[!] '{binary}' not found on PATH. Install with: pip install {binary}")


def run(cmd):
    print("[>] " + " ".join(cmd), file=sys.stderr)
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True)
    except FileNotFoundError as exc:
        sys.exit(f"[!] failed to execute {cmd[0]}: {exc}")
    if proc.stdout:
        print(proc.stdout)
    if proc.returncode != 0:
        print(proc.stderr, file=sys.stderr)
        print(f"[!] {cmd[0]} exited {proc.returncode}", file=sys.stderr)
    return proc.returncode, proc.stdout


def auth_args(args):
    if args.device_code:
        return ["--device-code"]
    if args.access_token:
        return ["--access-token", args.access_token]
    if args.refresh_token:
        return ["--refresh-token", args.refresh_token]
    if args.user and args.password:
        return ["-u", args.user, "-p", args.password]
    sys.exit("[!] provide an auth method: --device-code | --access-token | --refresh-token | -u/-p")


def cmd_recon(args):
    require("roadrecon")
    rc, _ = run(["roadrecon", "auth"] + auth_args(args))
    if rc != 0:
        sys.exit("[!] authentication failed")
    if args.gather:
        gather = ["roadrecon", "gather"]
        if args.mfa:
            gather.append("--mfa")
        run(gather)
    if args.bloodhound:
        run(["roadrecon", "plugin", "bloodhound"])
    if args.policies:
        run(["roadrecon", "plugin", "policies"])
    print("[+] recon complete. Run 'roadrecon gui' to explore roadrecon.db", file=sys.stderr)


def cmd_tokens(args):
    require("roadtx")
    cmd = ["roadtx", "gettokens"]
    if args.refresh_token:
        cmd += ["--refresh-token", args.refresh_token]
    elif args.user and args.password:
        cmd += ["-u", args.user, "-p", args.password]
    else:
        sys.exit("[!] provide -u/-p or --refresh-token")
    if args.client:
        cmd += ["-c", args.client]
    if args.resource:
        cmd += ["-r", args.resource]
    run(cmd)


def cmd_pivot(args):
    require("roadtx")
    cmd = ["roadtx", "refreshtokento", "-r", args.resource]
    if args.client:
        cmd += ["-c", args.client]
    run(cmd)


def cmd_describe(args):
    require("roadtx")
    if args.token:
        run(["roadtx", "describe", "-t", args.token])
    else:
        # roadtx describe reads .roadtools_auth from stdin
        try:
            with open(".roadtools_auth", "r", encoding="utf-8") as fh:
                data = fh.read()
        except FileNotFoundError:
            sys.exit("[!] .roadtools_auth not found; authenticate first or pass --token")
        proc = subprocess.run(["roadtx", "describe"], input=data, text=True,
                              capture_output=True)
        print(proc.stdout or proc.stderr)


def main():
    p = argparse.ArgumentParser(description="ROADtools engagement orchestrator (authorized use only)")
    sub = p.add_subparsers(dest="cmd", required=True)

    def add_auth(sp):
        sp.add_argument("-u", "--user"); sp.add_argument("-p", "--password")
        sp.add_argument("--device-code", action="store_true")
        sp.add_argument("--access-token"); sp.add_argument("--refresh-token")

    sr = sub.add_parser("recon"); add_auth(sr)
    sr.add_argument("--gather", action="store_true")
    sr.add_argument("--mfa", action="store_true")
    sr.add_argument("--bloodhound", action="store_true")
    sr.add_argument("--policies", action="store_true")

    st = sub.add_parser("tokens")
    st.add_argument("-u", "--user"); st.add_argument("-p", "--password")
    st.add_argument("--refresh-token")
    st.add_argument("-c", "--client", default="azcli")
    st.add_argument("-r", "--resource", default="msgraph")

    sp_ = sub.add_parser("pivot")
    sp_.add_argument("-r", "--resource", required=True)
    sp_.add_argument("-c", "--client")

    sd = sub.add_parser("describe"); sd.add_argument("--token")

    args = p.parse_args()
    {"recon": cmd_recon, "tokens": cmd_tokens,
     "pivot": cmd_pivot, "describe": cmd_describe}[args.cmd](args)


if __name__ == "__main__":
    main()
