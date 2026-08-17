#!/usr/bin/env python3
"""Microsoft Graph post-exploitation recon helper.

Authorized-use companion to GraphRunner. Drives the same Microsoft Graph REST
endpoints GraphRunner uses, from Python, given an existing Graph access token.
Supports device-code token acquisition (azcli first-party client) and read-only
recon: users, groups, app consent grants, and mailbox search.

Examples
--------
    # Acquire a token via device code (complete at microsoft.com/devicelogin)
    python agent.py auth --tenant <tenant-guid-or-domain> > tokens.json

    # Recon with a stored token
    python agent.py users   --token-file tokens.json --out users.json
    python agent.py groups  --token-file tokens.json
    python agent.py grants  --token-file tokens.json
    python agent.py mail    --token-file tokens.json --term password
"""
import argparse
import json
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

GRAPH = "https://graph.microsoft.com/v1.0"
# Microsoft Azure CLI first-party client (public, FOCI) — same class GraphRunner uses.
AZCLI_CLIENT_ID = "04b07795-8ddb-461a-bbee-02f9e1bf7b46"


def http_json(method, url, headers=None, data=None):
    headers = headers or {}
    body = None
    if data is not None:
        if isinstance(data, dict):
            body = urllib.parse.urlencode(data).encode()
            headers.setdefault("Content-Type", "application/x-www-form-urlencoded")
        else:
            body = data.encode()
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req) as resp:
            return resp.status, json.loads(resp.read().decode() or "{}")
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode(errors="replace")
        try:
            return exc.code, json.loads(detail)
        except json.JSONDecodeError:
            return exc.code, {"error": detail}


def device_code_auth(tenant):
    base = f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0"
    scope = "https://graph.microsoft.com/.default offline_access openid"
    status, dc = http_json("POST", f"{base}/devicecode",
                           data={"client_id": AZCLI_CLIENT_ID, "scope": scope})
    if status != 200:
        sys.exit(f"[!] devicecode request failed: {dc}")
    print(dc["message"], file=sys.stderr)
    interval = int(dc.get("interval", 5))
    while True:
        time.sleep(interval)
        status, tok = http_json("POST", f"{base}/token", data={
            "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
            "client_id": AZCLI_CLIENT_ID,
            "device_code": dc["device_code"],
        })
        if status == 200:
            return tok
        err = tok.get("error")
        if err == "authorization_pending":
            continue
        if err == "slow_down":
            interval += 5
            continue
        sys.exit(f"[!] token error: {tok}")


def load_token(path):
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    tok = data.get("access_token")
    if not tok:
        sys.exit("[!] no access_token in token file")
    return tok


def graph_get_all(token, path):
    headers = {"Authorization": f"Bearer {token}"}
    url = f"{GRAPH}{path}"
    items = []
    while url:
        status, body = http_json("GET", url, headers=headers)
        if status != 200:
            print(f"[!] {url} -> {status}: {body.get('error')}", file=sys.stderr)
            break
        items.extend(body.get("value", []))
        url = body.get("@odata.nextLink")
    return items


def cmd_auth(args):
    tok = device_code_auth(args.tenant)
    print(json.dumps(tok, indent=2))


def cmd_users(args):
    tok = load_token(args.token_file)
    users = graph_get_all(tok, "/users?$select=displayName,userPrincipalName,id,jobTitle")
    print(f"[+] {len(users)} users", file=sys.stderr)
    out = json.dumps(users, indent=2)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(out)
        print(f"[+] written to {args.out}", file=sys.stderr)
    else:
        print(out)


def cmd_groups(args):
    tok = load_token(args.token_file)
    groups = graph_get_all(tok, "/groups?$select=displayName,id,securityEnabled,groupTypes")
    print(f"[+] {len(groups)} groups", file=sys.stderr)
    for g in groups:
        gt = ",".join(g.get("groupTypes") or []) or "security"
        print(f"{g['id']}  {g.get('displayName')}  [{gt}]")


def cmd_grants(args):
    tok = load_token(args.token_file)
    grants = graph_get_all(tok, "/oauth2PermissionGrants")
    print(f"[+] {len(grants)} OAuth2 permission grants", file=sys.stderr)
    for gr in grants:
        print(f"client={gr.get('clientId')} resource={gr.get('resourceId')} scope={gr.get('scope')}")


def cmd_mail(args):
    tok = load_token(args.token_file)
    headers = {"Authorization": f"Bearer {tok}"}
    q = urllib.parse.quote(f'"{args.term}"')
    url = f'{GRAPH}/me/messages?$search={q}&$top={args.top}&$select=subject,from,receivedDateTime'
    status, body = http_json("GET", url, headers=headers)
    if status != 200:
        sys.exit(f"[!] mail search failed {status}: {body.get('error')}")
    msgs = body.get("value", [])
    print(f"[+] {len(msgs)} messages matching '{args.term}'", file=sys.stderr)
    for m in msgs:
        sender = (m.get("from") or {}).get("emailAddress", {}).get("address", "?")
        print(f"{m.get('receivedDateTime')}  {sender}  {m.get('subject')}")


def main():
    p = argparse.ArgumentParser(description="Microsoft Graph recon helper (authorized use only)")
    sub = p.add_subparsers(dest="cmd", required=True)

    sa = sub.add_parser("auth"); sa.add_argument("--tenant", required=True)
    su = sub.add_parser("users"); su.add_argument("--token-file", required=True); su.add_argument("--out")
    sg = sub.add_parser("groups"); sg.add_argument("--token-file", required=True)
    sgr = sub.add_parser("grants"); sgr.add_argument("--token-file", required=True)
    sm = sub.add_parser("mail"); sm.add_argument("--token-file", required=True)
    sm.add_argument("--term", required=True); sm.add_argument("--top", type=int, default=25)

    args = p.parse_args()
    {"auth": cmd_auth, "users": cmd_users, "groups": cmd_groups,
     "grants": cmd_grants, "mail": cmd_mail}[args.cmd](args)


if __name__ == "__main__":
    main()
