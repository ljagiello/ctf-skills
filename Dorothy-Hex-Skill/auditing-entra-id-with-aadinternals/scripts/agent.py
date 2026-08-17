#!/usr/bin/env python3
"""
agent.py - Entra ID outsider-recon helper + AADInternals (PowerShell) launcher.

Two capabilities:
  1. recon  : Pure-Python unauthenticated tenant reconnaissance hitting the SAME
              public Microsoft endpoints AADInternals' Invoke-AADIntReconAsOutsider
              uses (getuserrealm, OpenID configuration). No credentials needed.
  2. run    : Convenience launcher that invokes an AADInternals cmdlet through
              PowerShell (pwsh/powershell) for the authenticated/backdoor cmdlets.

AUTHORIZED USE ONLY. AADInternals can forge SAML tokens and backdoor federation.
Use only against tenants you own or are explicitly authorized to assess.

References:
  - AADInternals  https://aadinternals.com/aadinternals/
  - getuserrealm  https://login.microsoftonline.com/getuserrealm.srf
"""
import argparse
import json
import shutil
import subprocess
import sys
import urllib.parse
import urllib.request
import urllib.error

UA = "Mozilla/5.0 (AADInternals-audit-helper)"


def _get_json(url: str) -> dict:
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        return {"_error": f"HTTP {e.code}", "_body": e.read().decode(errors="replace")[:200]}
    except urllib.error.URLError as e:
        return {"_error": str(e.reason)}


def get_user_realm(domain: str) -> dict:
    """Mirror AADInternals: getuserrealm.srf reveals managed vs federated + auth URL."""
    user = f"nn@{domain}"
    url = ("https://login.microsoftonline.com/getuserrealm.srf?login="
           + urllib.parse.quote(user) + "&xml=0")
    return _get_json(url)


def get_tenant_id(domain: str) -> str:
    """OpenID configuration exposes the tenant GUID in the issuer/authorization_endpoint."""
    url = f"https://login.microsoftonline.com/{domain}/.well-known/openid-configuration"
    cfg = _get_json(url)
    issuer = cfg.get("issuer", "")
    # issuer looks like https://sts.windows.net/<tenant-guid>/
    parts = [p for p in issuer.split("/") if p]
    return parts[-1] if parts else ""


def recon(args) -> int:
    domain = args.domain
    print(f"[*] Outsider recon for: {domain}")
    realm = get_user_realm(domain)
    if "_error" in realm:
        print(f"[!] getuserrealm failed: {realm['_error']}", file=sys.stderr)
    else:
        ns = realm.get("NameSpaceType", "Unknown")
        print(f"    NameSpaceType  : {ns}  ({'Federated' if ns=='Federated' else 'Managed/cloud'})")
        print(f"    Brand          : {realm.get('FederationBrandName') or realm.get('DomainName')}")
        if realm.get("AuthURL"):
            print(f"    Federation Auth: {realm['AuthURL']}")
        if realm.get("federation_protocol"):
            print(f"    Fed protocol   : {realm['federation_protocol']}")
    tid = get_tenant_id(domain)
    if tid:
        print(f"    Tenant ID      : {tid}")
    if args.json:
        print(json.dumps({"realm": realm, "tenant_id": tid}, indent=2))
    return 0


def run_cmdlet(args) -> int:
    """Launch an AADInternals cmdlet via PowerShell."""
    shell = shutil.which("pwsh") or shutil.which("powershell")
    if not shell:
        print("[!] PowerShell (pwsh/powershell) not found on PATH", file=sys.stderr)
        return 3
    cmdlet = args.cmdlet
    extra = " " + " ".join(args.args) if args.args else ""
    script = f"Import-Module AADInternals; {cmdlet}{extra}"
    print(f"[*] {shell} -> {script}")
    try:
        return subprocess.run([shell, "-NoProfile", "-Command", script],
                              check=False).returncode
    except KeyboardInterrupt:
        return 130


def main() -> int:
    p = argparse.ArgumentParser(description="Entra outsider recon + AADInternals launcher.")
    sub = p.add_subparsers(dest="mode", required=True)

    r = sub.add_parser("recon", help="Unauthenticated outsider recon (pure Python)")
    r.add_argument("domain", help="Target tenant domain, e.g. target.com")
    r.add_argument("--json", action="store_true", help="Also print raw JSON")
    r.set_defaults(func=recon)

    c = sub.add_parser("run", help="Run an AADInternals cmdlet via PowerShell")
    c.add_argument("cmdlet", help="Cmdlet name, e.g. Get-AADIntAccessTokenForMSGraph")
    c.add_argument("args", nargs=argparse.REMAINDER,
                   help="Extra args passed verbatim (e.g. -SaveToCache)")
    c.set_defaults(func=run_cmdlet)

    args = p.parse_args()
    print("[i] AUTHORIZED TESTING ONLY -- confirm tenant is in scope.")
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
