#!/usr/bin/env python3
"""
agent.py - BloodHound CE ingestion + Cypher helper.

Authenticates to a BloodHound Community Edition server's REST API, uploads a
SharpHound ZIP or AzureHound JSON file via the file-upload job workflow, and runs
Cypher queries (e.g. shortest path from owned principals to Domain Admins).

AUTHORIZED USE ONLY. BloodHound reveals privilege-escalation paths to full domain
/ tenant compromise. Use only against environments you are authorized to assess.

References:
  - BloodHound CE   https://github.com/SpecterOps/BloodHound
  - CE API docs     https://bloodhound.specterops.io/
"""
import argparse
import json
import os
import sys
import time
import urllib.request
import urllib.error

DA_SHORTEST_PATH = (
    'MATCH p=shortestPath((n {owned:true})-[*1..]->(g:Group)) '
    'WHERE g.objectid ENDS WITH "-512" RETURN p'
)


def _req(method, url, token=None, body=None, content_type="application/json", raw=False):
    headers = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    data = None
    if body is not None:
        if raw:
            data = body
            headers["Content-Type"] = content_type
        else:
            data = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            text = resp.read().decode()
            return json.loads(text) if text.strip() else {}
    except urllib.error.HTTPError as e:
        msg = e.read().decode(errors="replace")
        raise SystemExit(f"[!] API {method} {url} -> HTTP {e.code}: {msg}")
    except urllib.error.URLError as e:
        raise SystemExit(f"[!] cannot reach {url}: {e.reason}")


def login(base, username, secret):
    r = _req("POST", f"{base}/api/v2/login", body={
        "login_method": "secret", "username": username, "secret": secret})
    token = r.get("data", {}).get("session_token")
    if not token:
        raise SystemExit("[!] login failed: no session_token returned")
    print("[+] authenticated to BloodHound CE")
    return token


def upload(base, token, path):
    if not os.path.isfile(path):
        raise SystemExit(f"[!] file not found: {path}")
    job = _req("POST", f"{base}/api/v2/file-upload/start", token=token)
    job_id = job.get("data", {}).get("id")
    if job_id is None:
        raise SystemExit("[!] could not start upload job")
    ctype = "application/zip" if path.lower().endswith(".zip") else "application/json"
    with open(path, "rb") as fh:
        _req("PUT", f"{base}/api/v2/file-upload/{job_id}", token=token,
             body=fh.read(), content_type=ctype, raw=True)
    _req("POST", f"{base}/api/v2/file-upload/{job_id}/end", token=token)
    print(f"[+] uploaded {os.path.basename(path)} (job {job_id}); ingestion queued")
    return job_id


def run_cypher(base, token, query):
    r = _req("POST", f"{base}/api/v2/graphs/cypher", token=token,
             body={"query": query, "include_properties": True})
    nodes = r.get("data", {}).get("nodes", {})
    edges = r.get("data", {}).get("edges", [])
    print(f"[+] query returned {len(nodes)} nodes / {len(edges)} edges")
    for nid, node in list(nodes.items())[:50]:
        label = node.get("label") or node.get("objectId") or nid
        print(f"    - {node.get('kind','?')}: {label}")
    return r


def main():
    p = argparse.ArgumentParser(description="BloodHound CE ingest + Cypher helper.")
    p.add_argument("--url", default="http://localhost:8080", help="BloodHound CE base URL")
    p.add_argument("--user", default="admin", help="Admin username")
    p.add_argument("--secret", default=os.environ.get("BHE_SECRET"),
                   help="Admin password (or set BHE_SECRET)")
    p.add_argument("--upload", action="append", default=[],
                   help="Collector file to ingest (ZIP or JSON); repeatable")
    p.add_argument("--cypher", help="Cypher query to run")
    p.add_argument("--da-path", action="store_true",
                   help="Run the built-in owned->Domain Admins shortest-path query")
    args = p.parse_args()

    if not args.secret:
        raise SystemExit("[!] provide --secret or set BHE_SECRET")

    base = args.url.rstrip("/")
    token = login(base, args.user, args.secret)

    for f in args.upload:
        upload(base, token, f)
    if args.upload:
        print("[i] waiting 10s for ingestion to begin...")
        time.sleep(10)

    if args.da_path:
        run_cypher(base, token, DA_SHORTEST_PATH)
    if args.cypher:
        run_cypher(base, token, args.cypher)
    if not (args.upload or args.cypher or args.da_path):
        print("[i] nothing to do; pass --upload, --cypher, or --da-path")
    return 0


if __name__ == "__main__":
    sys.exit(main())
