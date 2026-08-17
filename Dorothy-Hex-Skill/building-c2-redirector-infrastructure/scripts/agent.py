#!/usr/bin/env python3
# For authorized red-team engagements and defensive research only.
# Deploying C2 infrastructure outside an agreed scope is illegal.
"""C2 redirector configuration generator and validator.

Generates a filtering nginx reverse-proxy redirector config from a set of C2
URI patterns + implant User-Agent (mirroring what cs2modrewrite/cs2nginx do),
and validates a live redirector: matching requests should proxy to the backend
while non-matching requests must be diverted (302) to a decoy.
"""

import argparse
import json
import sys
from datetime import datetime, timezone

NGINX_TEMPLATE = """server {{
    listen 443 ssl;
    server_name {domain};

    ssl_certificate     /etc/letsencrypt/live/{domain}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/{domain}/privkey.pem;

    location ~ {uri_regex} {{
        if ($http_user_agent != "{user_agent}") {{
            return 302 {decoy};
        }}
        proxy_pass {teamserver};
        proxy_ssl_verify off;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $remote_addr;
    }}

    location / {{
        return 302 {decoy};
    }}
}}
"""


def build_uri_regex(uris):
    """Turn a list of C2 URIs into an nginx location regex."""
    cleaned = [u.strip().lstrip("/") for u in uris if u.strip()]
    if not cleaned:
        sys.exit("[!] No C2 URIs provided")
    return "^/(" + "|".join(cleaned) + ")"


def generate_config(args):
    """Render the nginx redirector config."""
    cfg = NGINX_TEMPLATE.format(
        domain=args.domain,
        uri_regex=build_uri_regex(args.uri),
        user_agent=args.user_agent,
        teamserver=args.teamserver,
        decoy=args.decoy,
    )
    if args.output:
        with open(args.output, "w") as f:
            f.write(cfg)
        print(f"[+] nginx redirector config written to {args.output}")
    else:
        print(cfg)


def validate_redirector(args):
    """Probe a live redirector: decoy on miss, proxy on match."""
    try:
        import requests
        from urllib3.exceptions import InsecureRequestWarning
        requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
    except ImportError:
        sys.exit("[!] pip install requests for --validate")

    base = f"https://{args.domain}"
    report = {"checked": datetime.now(timezone.utc).isoformat(), "results": []}

    # 1. Non-matching request should be diverted (302/redirect to decoy)
    r1 = requests.get(base + "/", allow_redirects=False, verify=False, timeout=15)
    diverted = r1.status_code in (301, 302) and args.decoy.rstrip("/") in \
        r1.headers.get("Location", "")
    report["results"].append({"check": "non_c2_diverted", "status": r1.status_code,
                              "location": r1.headers.get("Location"), "pass": diverted})

    # 2. Matching request (correct UA + C2 URI) should be proxied (not 302-decoy)
    c2_path = "/" + args.uri[0].strip().lstrip("/").split("|")[0]
    r2 = requests.get(base + c2_path, headers={"User-Agent": args.user_agent},
                      allow_redirects=False, verify=False, timeout=15)
    proxied = not (r2.status_code in (301, 302) and
                   args.decoy.rstrip("/") in r2.headers.get("Location", ""))
    report["results"].append({"check": "c2_proxied", "path": c2_path,
                              "status": r2.status_code, "pass": proxied})

    print(json.dumps(report, indent=2))
    return all(x["pass"] for x in report["results"])


def main():
    p = argparse.ArgumentParser(description="C2 redirector config generator/validator")
    sub = p.add_subparsers(dest="cmd", required=True)

    g = sub.add_parser("generate", help="Generate an nginx redirector config")
    g.add_argument("--domain", required=True, help="Public redirector domain")
    g.add_argument("--teamserver", required=True, help="https://team-server backend URL")
    g.add_argument("--decoy", required=True, help="Decoy site URL for non-C2 traffic")
    g.add_argument("--uri", required=True, nargs="+", help="C2 URI patterns (no leading /)")
    g.add_argument("--user-agent", required=True, help="Implant User-Agent string")
    g.add_argument("--output", help="Write config to file")

    v = sub.add_parser("validate", help="Probe a live redirector")
    v.add_argument("--domain", required=True, help="Public redirector domain")
    v.add_argument("--decoy", required=True, help="Expected decoy URL")
    v.add_argument("--uri", required=True, nargs="+", help="C2 URI patterns")
    v.add_argument("--user-agent", required=True, help="Implant User-Agent string")

    args = p.parse_args()
    if args.cmd == "generate":
        generate_config(args)
    elif args.cmd == "validate":
        ok = validate_redirector(args)
        sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
