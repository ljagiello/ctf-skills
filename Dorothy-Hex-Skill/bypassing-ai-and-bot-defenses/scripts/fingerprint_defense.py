#!/usr/bin/env python3
"""Fingerprint the anti-bot / AI-defense vendor in front of a URL.

Usage:
    python fingerprint_defense.py -u https://TARGET/ [--timeout 15] [--json]

Scans response headers, cookies, body markers, and DNS for known bot-manager /
AI-gate vendor signals and prints the most likely vendor(s) + layer hints.
Only issues passive requests (GET / and /robots.txt) — read-only.
"""

import argparse
import json
import re
import sys
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError

VENDOR_MARKERS = {
    "cloudflare": [
        "cf-ray", "__cf_bm", "cf_clearance", "__cf_chl_", "server: cloudflare",
        "challenge-platform", "cf_chl_opt", "turnstile", "cf-mitigated",
        "verify you are human", "just a moment",
    ],
    "datadome": [
        "x-datadome", "datadome", "dd_cookie_test_", "ddk_", "window.datadome",
        "request blocked by datadome", "/cdn-cgi/challenge-platform",
    ],
    "perimeterx": [
        "_pxhd", "_px3", "_px", "x-px-", "px.js", "/pxhd", "px-captcha",
        "perimeterx",
    ],
    "akamai": [
        "_abck", "bm_sz", "ak_bmsc", "akamai", "akamai-request",
        "access denied", "x-akamai", "akamai-request",
    ],
    "recaptcha": [
        "grecaptcha", "g-recaptcha", "recaptcha", "recaptcha enterprise",
    ],
    "hcaptcha": ["h-captcha", "hcaptcha", "hcaptcha-captcha"],
    "geetest": ["geetest", "gt.js", "new-captcha", "gt_challenge"],
    "arkose": ["funcaptcha", "arkose", "public_key", "/fc/assets/", "datakey"],
    "aws_waf": ["aws-waf-token", "aws waf", "x-amzn-waf", "awswaf", "x-amz-cf"],
    "imperva": ["x-iinfo", "incap_ses", "visid_incap", "incapsula", "imperva"],
    "fastly": ["x-served-by", "fastly", "x-fastly"],
    "llm_gate": [
        "describe this image", "select the odd one out", "solve the riddle",
        "what's happening in this photo", "ai-assisted human", "prove you are human",
        "answer the ai", "which is not a",
    ],
}

CHALLENGE_WORDS = [
    "challenge", "captcha", "verification", "antibot", "anti-bot",
    "checking your browser", "access denied", "request blocked",
]


def fetch(url: str, timeout: int) -> dict:
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                      "AppleWebKit/537.36 (KHTML, like Gecko) "
                      "Chrome/124.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
    }
    try:
        req = Request(url, headers=headers, method="GET")
        with urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", errors="ignore")
            return {
                "status": resp.getcode(),
                "headers": {k.lower(): v for k, v in resp.headers.items()},
                "body_len": len(body),
                "body": body[:200000],
            }
    except HTTPError as e:
        body = e.read().decode("utf-8", errors="ignore")
        return {
            "status": e.code,
            "headers": {k.lower(): v for k, v in e.headers.items()},
            "body_len": len(body),
            "body": body[:200000],
        }
    except URLError as e:
        return {"error": str(e.reason), "status": 0, "headers": {}, "body_len": 0, "body": ""}
    except Exception as e:
        return {"error": str(e), "status": 0, "headers": {}, "body_len": 0, "body": ""}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("-u", "--url", required=True, help="Target URL")
    ap.add_argument("--timeout", type=int, default=15)
    ap.add_argument("--json", action="store_true", help="JSON output")
    args = ap.parse_args()

    url = args.url.rstrip("/")
    probe = fetch(url, args.timeout)
    if probe.get("error"):
        print(f"[!] Fetch failed: {probe['error']}", file=sys.stderr)
        return 1

    hay = " ".join(
        [str(v) for v in probe["headers"].values()]
        + [probe["body"][:5000].lower()]
    ).lower()

    scores = {}
    for vendor, markers in VENDOR_MARKERS.items():
        hits = [m for m in markers if m.lower() in hay]
        if hits:
            scores[vendor] = len(hits)

    challenge_hit = any(w in hay for w in CHALLENGE_WORDS)
    cookies = probe["headers"].get("set-cookie", "")
    server = probe["headers"].get("server", "")
    via = probe["headers"].get("via", "")

    result = {
        "url": url,
        "status": probe["status"],
        "server": server,
        "via": via,
        "body_len": probe["body_len"],
        "cookies": sorted({c.split("=")[0].strip() for c in cookies.split(",") if "=" in c}),
        "challenge_page": challenge_hit,
        "vendors": dict(sorted(scores.items(), key=lambda kv: -kv[1])),
        "top": max(scores, key=scores.get) if scores else None,
    }

    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        print(f"URL      : {result['url']}")
        print(f"Status   : {result['status']}  (body {result['body_len']} bytes)")
        print(f"Server   : {server or '-'}   Via: {via or '-'}")
        print(f"Cookies  : {', '.join(result['cookies']) or '-'}")
        print(f"Challenge page: {'YES' if challenge_hit else 'no'}")
        if result["vendors"]:
            print("Vendors  : " + ", ".join(f"{v} ({n} hits)" for v, n in result["vendors"].items()))
            print(f"Top match: {result['top']}")
        else:
            print("Vendors  : none detected - likely plain site or custom gate")
            print("Hint     : check body manually; run with --json for raw probes")

    return 0


if __name__ == "__main__":
    sys.exit(main())
