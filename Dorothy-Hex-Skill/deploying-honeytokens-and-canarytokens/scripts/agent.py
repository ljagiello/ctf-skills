#!/usr/bin/env python3
"""
honeytoken_agent.py — Generate, validate, and inventory Canarytokens.

Talks to a Canarytokens frontend (the public service at https://canarytokens.org
or a self-hosted thinkst/canarytokens-docker instance) via its POST /generate
and GET /history HTTP API. Maintains a local JSON inventory of every token
deployed, with its memo, planted location, and MITRE D3FEND mapping, so a blue
team can track deception coverage.

This is a defensive tool. Only generate tokens for assets you own or are
authorized to instrument, and never commit decoy artifacts to public repos.

Examples:
  # Generate an HTTP web-bug token on the public service
  python3 honeytoken_agent.py generate --type http \
      --email soc@example.com --memo "wiki admin-passwords page" \
      --location "https://wiki.internal/it/admin" --d3fend D3-DF

  # Generate against a self-hosted frontend with a webhook
  python3 honeytoken_agent.py generate --base-url https://canary.example.com \
      --type aws_keys --webhook https://hooks.slack.com/services/T/B/X \
      --memo "decoy keys jenkins host" --location "/root/.aws/credentials"

  # Show triggers (history) for a stored token
  python3 honeytoken_agent.py history --token-id <token> --auth <auth>

  # List the local inventory
  python3 honeytoken_agent.py inventory
"""
import argparse
import json
import os
import sys
from datetime import datetime, timezone

try:
    import requests
except ImportError:
    sys.stderr.write("ERROR: install dependency with: python3 -m pip install requests\n")
    sys.exit(2)

DEFAULT_BASE = "https://canarytokens.org"
INVENTORY = os.environ.get("CANARY_INVENTORY", "canarytoken_inventory.json")

VALID_TYPES = {
    "http", "dns", "aws_keys", "msword", "adobe_pdf", "slack_api",
    "kubeconfig", "azure_id", "qr_code", "web_image", "log4shell",
    "cmd", "cloned_web", "sql_server",
}


def _load_inventory():
    if not os.path.exists(INVENTORY):
        return []
    try:
        with open(INVENTORY, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (json.JSONDecodeError, OSError) as exc:
        sys.stderr.write(f"WARN: could not read inventory {INVENTORY}: {exc}\n")
        return []


def _save_inventory(items):
    try:
        with open(INVENTORY, "w", encoding="utf-8") as fh:
            json.dump(items, fh, indent=2)
    except OSError as exc:
        sys.stderr.write(f"ERROR: could not write inventory {INVENTORY}: {exc}\n")
        sys.exit(1)


def generate(args):
    if args.type not in VALID_TYPES:
        sys.stderr.write(f"ERROR: unknown type '{args.type}'. Valid: {sorted(VALID_TYPES)}\n")
        sys.exit(1)
    if not args.email and not args.webhook:
        sys.stderr.write("ERROR: provide --email and/or --webhook for alerting.\n")
        sys.exit(1)

    data = {"type": args.type, "memo": args.memo}
    if args.email:
        data["email"] = args.email
    if args.webhook:
        data["webhook_url"] = args.webhook

    url = args.base_url.rstrip("/") + "/generate"
    try:
        resp = requests.post(url, data=data, timeout=args.timeout)
        resp.raise_for_status()
    except requests.RequestException as exc:
        sys.stderr.write(f"ERROR: generate request failed: {exc}\n")
        sys.exit(1)

    try:
        body = resp.json()
    except ValueError:
        sys.stderr.write("ERROR: non-JSON response from server:\n" + resp.text[:500] + "\n")
        sys.exit(1)

    token_id = body.get("token") or body.get("canarytoken")
    record = {
        "type": args.type,
        "memo": args.memo,
        "location": args.location or "",
        "d3fend": args.d3fend or "",
        "token": token_id,
        "auth": body.get("auth"),
        "hostname": body.get("hostname"),
        "url": body.get("url"),
        "access_key_id": body.get("access_key_id"),
        "created": datetime.now(timezone.utc).isoformat(),
        "base_url": args.base_url.rstrip("/"),
    }
    inv = _load_inventory()
    inv.append(record)
    _save_inventory(inv)

    print(json.dumps({k: v for k, v in record.items() if v is not None}, indent=2))
    if args.type in ("msword", "adobe_pdf", "aws_keys") and token_id and record["auth"]:
        dl = (f"{record['base_url']}/download?fmt={args.type}"
              f"&token={token_id}&auth={record['auth']}")
        print(f"\nDownload artifact:\n  curl -s '{dl}' -o token_artifact")
    return 0


def history(args):
    url = args.base_url.rstrip("/") + "/history"
    try:
        resp = requests.get(url, params={"token": args.token_id, "auth": args.auth},
                            timeout=args.timeout)
        resp.raise_for_status()
    except requests.RequestException as exc:
        sys.stderr.write(f"ERROR: history request failed: {exc}\n")
        sys.exit(1)
    try:
        print(json.dumps(resp.json(), indent=2))
    except ValueError:
        print(resp.text)
    return 0


def inventory(_args):
    inv = _load_inventory()
    if not inv:
        print("(inventory empty)")
        return 0
    print(f"{'TYPE':<12} {'D3FEND':<8} {'MEMO':<40} LOCATION")
    print("-" * 90)
    for rec in inv:
        print(f"{rec.get('type',''):<12} {rec.get('d3fend',''):<8} "
              f"{(rec.get('memo','') or '')[:40]:<40} {rec.get('location','')}")
    print(f"\nTotal tokens deployed: {len(inv)}")
    return 0


def build_parser():
    p = argparse.ArgumentParser(description="Canarytoken generation, validation and inventory helper.")
    p.add_argument("--base-url", default=DEFAULT_BASE,
                   help=f"Canarytokens frontend base URL (default {DEFAULT_BASE})")
    p.add_argument("--timeout", type=int, default=20, help="HTTP timeout seconds")
    sub = p.add_subparsers(dest="cmd", required=True)

    g = sub.add_parser("generate", help="Create a new canarytoken")
    g.add_argument("--type", required=True, help="Token type (e.g. http, dns, aws_keys, msword)")
    g.add_argument("--email", help="Alert email address")
    g.add_argument("--webhook", help="Alert webhook URL")
    g.add_argument("--memo", required=True, help="Reminder of where the token is planted")
    g.add_argument("--location", help="Where the token will be planted (for inventory)")
    g.add_argument("--d3fend", help="MITRE D3FEND mapping, e.g. D3-DF or D3-DUC")
    g.set_defaults(func=generate)

    h = sub.add_parser("history", help="Show triggers for a token")
    h.add_argument("--token-id", required=True)
    h.add_argument("--auth", required=True)
    h.set_defaults(func=history)

    i = sub.add_parser("inventory", help="List the local token inventory")
    i.set_defaults(func=inventory)
    return p


def main():
    args = build_parser().parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
