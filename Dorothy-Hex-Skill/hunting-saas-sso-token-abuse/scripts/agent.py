#!/usr/bin/env python3
"""
SaaS SSO token-abuse hunter (Okta System Log).

Pulls Okta System Log events over the API and flags session tokens
(externalSessionId) that are observed from multiple source IPs or user-agents
within the window — a strong indicator of session-cookie/token replay
(MITRE ATT&CK T1550.001 / pass-the-cookie).

Defensive tool. Requires a read-only Okta API token.

Examples:
  export OKTA_ORG=example.okta.com
  export OKTA_API_TOKEN=00xxxx
  python agent.py --since 2026-06-15T00:00:00Z --min-ips 2
  python agent.py --since 2026-06-15T00:00:00Z --event-type user.session.start --json out.json
"""
import argparse
import json
import os
import sys
from collections import defaultdict

try:
    import requests
except ImportError:
    sys.exit("error: 'requests' required. Install with: pip install requests")


def fetch_logs(org, token, since, event_type, page_limit):
    url = f"https://{org}/api/v1/logs"
    headers = {"Authorization": f"SSWS {token}", "Accept": "application/json"}
    params = {"since": since, "limit": 1000}
    if event_type:
        params["filter"] = f'eventType eq "{event_type}"'

    events = []
    pages = 0
    while url and pages < page_limit:
        try:
            resp = requests.get(url, headers=headers, params=params, timeout=60)
        except requests.RequestException as exc:
            sys.exit(f"error: request failed: {exc}")
        if resp.status_code == 401:
            sys.exit("error: 401 Unauthorized — check OKTA_API_TOKEN")
        if resp.status_code == 429:
            sys.exit("error: 429 rate limited — retry later")
        if resp.status_code != 200:
            sys.exit(f"error: Okta API returned {resp.status_code}: {resp.text[:200]}")
        batch = resp.json()
        if not batch:
            break
        events.extend(batch)
        params = None  # subsequent pages use the full 'next' link
        url = None
        link = resp.headers.get("link", "")
        for part in link.split(","):
            if 'rel="next"' in part:
                url = part[part.find("<") + 1:part.find(">")]
        pages += 1
    return events


def analyze(events, min_ips):
    sessions = defaultdict(lambda: {"ips": set(), "agents": set(), "users": set(), "count": 0})
    for ev in events:
        ctx = ev.get("authenticationContext") or {}
        sid = ctx.get("externalSessionId")
        if not sid or sid == "unknown":
            continue
        client = ev.get("client") or {}
        ua = (client.get("userAgent") or {}).get("rawUserAgent")
        actor = ev.get("actor") or {}
        rec = sessions[sid]
        if client.get("ipAddress"):
            rec["ips"].add(client["ipAddress"])
        if ua:
            rec["agents"].add(ua)
        if actor.get("alternateId"):
            rec["users"].add(actor["alternateId"])
        rec["count"] += 1

    findings = []
    for sid, rec in sessions.items():
        if len(rec["ips"]) >= min_ips or len(rec["agents"]) >= 2:
            findings.append({
                "session_id": sid,
                "users": sorted(rec["users"]),
                "distinct_ips": sorted(rec["ips"]),
                "distinct_user_agents": sorted(rec["agents"]),
                "event_count": rec["count"],
            })
    findings.sort(key=lambda f: len(f["distinct_ips"]), reverse=True)
    return findings


def main():
    p = argparse.ArgumentParser(description="Okta SSO token-abuse hunter")
    p.add_argument("--org", default=os.environ.get("OKTA_ORG"),
                   help="Okta org domain, e.g. example.okta.com (or OKTA_ORG)")
    p.add_argument("--token", default=os.environ.get("OKTA_API_TOKEN"),
                   help="Okta API token (or OKTA_API_TOKEN)")
    p.add_argument("--since", required=True, help="ISO-8601 start time")
    p.add_argument("--event-type", default="policy.evaluate_sign_on",
                   help="Okta eventType to query")
    p.add_argument("--min-ips", type=int, default=2,
                   help="flag sessions seen from >= this many IPs")
    p.add_argument("--max-pages", type=int, default=20, help="max API pages to pull")
    p.add_argument("--json", metavar="FILE", help="write findings JSON to file")
    args = p.parse_args()

    if not args.org or not args.token:
        sys.exit("error: provide --org/--token or set OKTA_ORG/OKTA_API_TOKEN")

    print(f"[*] fetching Okta '{args.event_type}' events since {args.since} ...")
    events = fetch_logs(args.org, args.token, args.since, args.event_type, args.max_pages)
    print(f"[+] retrieved {len(events)} events")

    findings = analyze(events, args.min_ips)
    print(f"[+] {len(findings)} suspicious session(s) (multi-IP / multi-UA)\n")
    for f in findings:
        print(f"  session {f['session_id']} user={','.join(f['users'])}")
        print(f"    IPs ({len(f['distinct_ips'])}): {', '.join(f['distinct_ips'])}")
        print(f"    UAs ({len(f['distinct_user_agents'])}): {len(f['distinct_user_agents'])} distinct")
        print(f"    events: {f['event_count']}")

    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(findings, fh, indent=2)
        print(f"\n[+] wrote {args.json}")

    sys.exit(1 if findings else 0)


if __name__ == "__main__":
    main()
