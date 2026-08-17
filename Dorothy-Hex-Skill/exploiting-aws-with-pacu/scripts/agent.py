#!/usr/bin/env python3
"""
Pacu engagement driver.

Runs the standard AWS recon -> privesc-scan flow non-interactively via the Pacu
CLI (`pacu --session ... --module-name ... --exec`), then summarizes results from
the session SQLite database. Optionally exports collected data to JSON.

Authorized-use only: this performs active enumeration against a live AWS account.
Run ONLY within a signed scope/Rules of Engagement.

Examples:
  python agent.py --session engagement --recon
  python agent.py --session engagement --privesc
  python agent.py --session engagement --recon --privesc --export findings.json
"""
import argparse
import json
import os
import shutil
import sqlite3
import subprocess
import sys

RECON_MODULES = [
    "iam__enum_users_roles_policies_groups",
    "iam__enum_permissions",
    "ec2__enum",
    "s3__enum",
]
PRIVESC_MODULES = ["iam__privesc_scan"]


def require_pacu():
    if shutil.which("pacu") is None:
        sys.exit("error: 'pacu' not found in PATH. Install with: pip install pacu")


def run_module(session, module, module_args=None):
    cmd = ["pacu", "--session", session, "--module-name", module, "--exec"]
    if module_args:
        cmd += ["--module-args", module_args]
    print(f"[*] running {module} ...")
    try:
        proc = subprocess.run(cmd, text=True, timeout=1800)
    except subprocess.TimeoutExpired:
        print(f"  [!] {module} timed out")
        return False
    except OSError as exc:
        print(f"  [!] failed to run {module}: {exc}")
        return False
    if proc.returncode != 0:
        print(f"  [!] {module} exited rc={proc.returncode}")
    return proc.returncode == 0


def locate_db():
    """Pacu stores its sqlite DB under the install dir or ~/.local/share/pacu."""
    candidates = [
        os.path.expanduser("~/.local/share/pacu/sqlite.db"),
        os.path.expanduser("~/.pacu/sqlite.db"),
    ]
    for path in candidates:
        if os.path.isfile(path):
            return path
    return None


def export_session(session, out_path):
    db = locate_db()
    if not db:
        print("[!] could not locate Pacu sqlite.db; skipping export")
        return
    try:
        conn = sqlite3.connect(db)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = [r[0] for r in cur.fetchall()]
        dump = {"session": session, "tables": {}}
        for t in tables:
            try:
                cur.execute(f"SELECT * FROM {t} LIMIT 500")
                dump["tables"][t] = [dict(r) for r in cur.fetchall()]
            except sqlite3.Error:
                continue
        conn.close()
    except sqlite3.Error as exc:
        print(f"[!] could not read Pacu DB: {exc}")
        return
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(dump, fh, indent=2, default=str)
    print(f"[+] exported session data to {out_path}")


def main():
    p = argparse.ArgumentParser(description="Pacu AWS engagement driver")
    p.add_argument("--session", required=True, help="Pacu session name")
    p.add_argument("--recon", action="store_true", help="run recon/enumeration modules")
    p.add_argument("--privesc", action="store_true", help="run privilege-escalation scan")
    p.add_argument("--module", action="append", default=[],
                   help="run an explicit module (repeatable)")
    p.add_argument("--module-args", help="args for the explicit --module call")
    p.add_argument("--export", metavar="FILE", help="export session DB to JSON")
    args = p.parse_args()

    require_pacu()

    if not (args.recon or args.privesc or args.module):
        sys.exit("error: choose at least one of --recon / --privesc / --module")

    print("[!] AUTHORIZED USE ONLY — confirm this AWS account is in scope.")

    results = {}
    if args.recon:
        for m in RECON_MODULES:
            results[m] = run_module(args.session, m)
    if args.privesc:
        for m in PRIVESC_MODULES:
            results[m] = run_module(args.session, m)
    for m in args.module:
        results[m] = run_module(args.session, m, args.module_args)

    print("\n=== Module run summary ===")
    for m, ok in results.items():
        print(f"  {m}: {'OK' if ok else 'FAILED'}")

    if args.export:
        export_session(args.session, args.export)


if __name__ == "__main__":
    main()
