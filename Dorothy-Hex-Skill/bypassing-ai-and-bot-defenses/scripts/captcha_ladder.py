#!/usr/bin/env python3
"""Orchestrate the CAPTCHA solving ladder: API-path -> token replay -> OCR -> paid solver.

Usage:
    python captcha_ladder.py --sitekey <sitekey> --pageurl https://TARGET/login \
        [--type recaptcha_v2|hcaptcha|turnstile|geetest|arkose] \
        [--solver-api-key <2captcha_key>] [--submit-url ...] [--dry]

Steps (in order, stops at first success):
  1. Try direct API path (no captcha token)  [--api-url + --api-payload]
  2. Try OCR on a custom simple text captcha [--image path]
  3. Use paid solver if --solver-api-key given
  4. Report which method produced a usable token/cookie.

This only obtains a token or tests API path acceptance — it does not run a
browser. For interactive widget solving, pair with scripts/stealth_browser.py.
"""

import argparse
import json
import re
import subprocess
import sys
import time
import urllib.parse
import urllib.request


class Solver:
    BASE = "https://2captcha.com"

    def __init__(self, api_key: str):
        self.key = api_key

    def _post(self, url: str, data: dict) -> dict:
        req = urllib.request.Request(url, data=urllib.parse.urlencode(data).encode())
        with urllib.request.urlopen(req, timeout=60) as r:
            return json.loads(r.read().decode())

    def solve_captcha(self, sitekey: str, pageurl: str, captcha_type: str) -> str | None:
        method = {
            "recaptcha_v2": "userrecaptcha",
            "hcaptcha": "hcaptcha",
            "turnstile": "turnstile",
            "geetest": "geetest",
            "arkose": "funcaptcha",
        }.get(captcha_type)
        if not method:
            print(f"[!] unsupported captcha type for solver: {captcha_type}")
            return None

        payload = {"key": self.key, "method": method, "sitekey": sitekey,
                   "pageurl": pageurl, "json": 1}
        if captcha_type == "arkose":
            payload["publickey"] = sitekey
            payload.pop("sitekey")
        created = self._post(f"{self.BASE}/in.php", payload)
        if created.get("status") != 1:
            print(f"[!] solver create failed: {created.get('request')}")
            return None
        cid = created["request"]
        for _ in range(120):
            time.sleep(3)
            res = self._post(
                f"{self.BASE}/res.php",
                {"key": self.key, "action": "get", "id": cid, "json": 1},
            )
            if res.get("status") == 1:
                return res["request"]
            if res.get("request") != "CAPCHA_NOT_READY":
                print(f"[!] solver error: {res.get('request')}")
                return None
        print("[!] solver timed out")
        return None


def try_api_path(api_url: str, payload: str) -> bool:
    print(f"[*] step 1: direct API path -> {api_url}")
    data = payload.encode() if payload else b"{}"
    req = urllib.request.Request(api_url, data=data,
                                 headers={"Content-Type": "application/json",
                                          "User-Agent": "Mozilla/5.0"})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            body = r.read().decode(errors="ignore")[:500]
            ok = r.status < 400 and not re.search(
                r"captcha|challenge|verif|blocked|forbidden", body, re.I)
            print(f"    status={r.status} ok_without_token={ok}")
            return ok
    except Exception as e:
        print(f"    direct API failed: {e}")
        return False


def try_ocr(image_path: str) -> str | None:
    print(f"[*] step 2: OCR {image_path}")
    try:
        from PIL import Image, ImageOps, ImageFilter
        img = Image.open(image_path).convert("L")
        img = ImageOps.autocontrast(img)
        img = img.point(lambda p: 255 if p > 140 else 0)
        img = img.filter(ImageFilter.MedianFilter(3))
        img.save("captcha_prep.png")
    except ImportError:
        print("    PIL not installed — skipping preprocessing")

    out = subprocess.run(
        ["tesseract", image_path, "stdout", "--psm", "7",
         "-c", "tessedit_char_whitelist=abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"],
        capture_output=True, text=True, timeout=60)
    token = out.stdout.strip()
    print(f"    OCR result: {token!r}")
    return token or None


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--sitekey")
    ap.add_argument("--pageurl")
    ap.add_argument("--type", default="recaptcha_v2",
                    choices=["recaptcha_v2", "hcaptcha", "turnstile", "geetest", "arkose"])
    ap.add_argument("--solver-api-key")
    ap.add_argument("--api-url", help="endpoint to test without a token")
    ap.add_argument("--api-payload", default="{}", help="JSON body for API test")
    ap.add_argument("--image", help="path to a simple text captcha for OCR")
    ap.add_argument("--dry", action="store_true", help="probe only, don't spend solver credit")
    args = ap.parse_args()

    if not (args.sitekey or args.api_url or args.image):
        ap.error("need --sitekey, --api-url, or --image")

    if args.api_url and try_api_path(args.api_url, args.api_payload):
        print("[+] BYPASS: endpoint accepts requests without a captcha token")
        return 0

    if args.image:
        token = try_ocr(args.image)
        if token:
            print(f"[+] OCR token obtained (validate against endpoint): {token}")
            return 0
        print("[.] OCR failed — continuing ladder")

    if args.sitekey and args.solver_api_key and not args.dry:
        print(f"[*] step 3: paid solver ({args.type})")
        token = Solver(args.solver_api_key).solve_captcha(
            args.sitekey, args.pageurl or "https://example.com", args.type)
        if token:
            print(f"[+] CAPTCHA token: {token}")
            return 0
        print("[!] solver failed")

    print("[-] no path yielded a usable token/cookie this run")
    return 1


if __name__ == "__main__":
    sys.exit(main())
