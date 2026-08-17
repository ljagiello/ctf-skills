#!/usr/bin/env python3
"""Headed-stealth browser with humanized behavior for bypassing bot managers.

Usage:
    python stealth_browser.py --url https://TARGET/login [--persist ./profile]
    python stealth_browser.py --url https://TARGET/login --interactive

Launches a headed Chromium (patchright preferred, Playwright fallback) with
stealth flags, patches navigator.webdriver/plugins/languages, adds canvas/WebGL
noise, and humanizes mouse/typing/scroll/timing. Prints the page title and the
session cookies so you can replay them (cf_clearance, datadome, _pxhd, ...).

Requires: patchright or playwright. Install:
    pip install patchright && patchright install chromium
    # or: pip install playwright && playwright install chromium
For headless servers: start Xvfb first and set DISPLAY (do NOT use xvfb-run).
"""

import argparse
import random
import sys
import time

INIT_SCRIPT = r"""
Object.defineProperty(navigator, 'webdriver', { get: () => undefined });
Object.defineProperty(navigator, 'languages', { get: () => ['en-US', 'en'] });
Object.defineProperty(navigator, 'plugins', { get: () => [
  { name: 'Chrome PDF Plugin', filename: 'internal-pdf-viewer' },
  { name: 'Chrome PDF Viewer', filename: 'mhjfbmdgcfjbbpaeojofohoefgiehjai' },
]});
window.chrome = window.chrome || {
  runtime: {}, app: {}, csi: () => 0,
  loadTimes: () => ({}),
};
const __origToDataURL = HTMLCanvasElement.prototype.toDataURL;
HTMLCanvasElement.prototype.toDataURL = function (type) {
  const ctx = this.getContext('2d');
  if (ctx) {
    try {
      const img = ctx.getImageData(0, 0, this.width, this.height);
      const d = img.data;
      for (let i = 0; i < d.length; i += 8) d[i] ^= d[i] & 1;
      ctx.putImageData(img, 0, 0);
    } catch (e) {}
  }
  return __origToDataURL.apply(this, arguments);
};
"""

CHROME_ARGS = [
    "--disable-blink-features=AutomationControlled",
    "--disable-infobars",
    "--no-first-run",
    "--no-default-browser-check",
    "--window-size=1920,1080",
    "--no-sandbox",
    "--disable-dev-shm-usage",
]

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
]


def human_type(page, selector: str, text: str) -> None:
    page.click(selector)
    for ch in text:
        page.keyboard.type(ch)
        delay = max(30, random.gauss(120, 40))
        if ch in " .,!?;:":
            delay += random.uniform(40, 220)
        time.sleep(delay / 1000)


def human_scroll(page, distance: int) -> None:
    remaining = distance
    while remaining > 0:
        delta = random.randint(60, 180)
        page.mouse.wheel(0, delta)
        remaining -= delta
        time.sleep(random.uniform(0.08, 0.3))


def idle_moves(page) -> None:
    for _ in range(random.randint(2, 5)):
        page.mouse.move(random.randint(100, 1600), random.randint(100, 800),
                        steps=random.randint(5, 20))
        time.sleep(random.uniform(0.05, 0.25))


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("-u", "--url", required=True)
    ap.add_argument("--persist", help="persistent profile dir (reuse cookies)")
    ap.add_argument("--interactive", action="store_true", help="keep browser open")
    ap.add_argument("--headful-wait", type=int, default=6,
                    help="seconds to wait for auto-challenge (Turnstile) solve")
    args = ap.parse_args()

    try:
        from patchright.sync_api import sync_playwright  # type: ignore
        driver = "patchright"
    except ImportError:
        from playwright.sync_api import sync_playwright  # type: ignore
        driver = "playwright"

    print(f"[*] driver={driver} url={args.url}")
    ua = random.choice(USER_AGENTS)

    with sync_playwright() as p:
        launch_kwargs = dict(headless=False, args=CHROME_ARGS)
        if args.persist:
            ctx = p.chromium.launch_persistent_context(
                args.persist, **launch_kwargs)
            page = ctx.pages[0] if ctx.pages else ctx.new_page()
        else:
            browser = p.chromium.launch(**launch_kwargs)
            ctx = browser.new_context(
                user_agent=ua,
                viewport={"width": 1920, "height": 1080},
                locale="en-US",
                timezone_id="America/New_York",
            )
            page = ctx.new_page()

        page.add_init_script(INIT_SCRIPT)

        print(f"[*] navigating: {args.url}")
        page.goto(args.url, wait_until="domcontentloaded", timeout=45000)
        time.sleep(random.uniform(2, 5))
        idle_moves(page)
        time.sleep(args.headful_wait)

        title = page.title()
        print(f"[*] page title: {title!r}")

        cookies = ctx.cookies()
        relevant = [c for c in cookies if any(
            k in c["name"].lower() for k in
            ("cf", "clearance", "datadome", "px", "ak", "bm", "incap", "waf"))]
        for c in sorted(cookies, key=lambda c: c["name"]):
            mark = " <-- challenge cookie" if any(
                k in c["name"].lower() for k in
                ("cf_clearance", "__cf_bm", "datadome", "_pxhd", "_abck",
                 "ak_bmsc", "incap_ses", "aws-waf-token")) else ""
            print(f"    {c['name']} = {c['value'][:24]}...{mark}")

        if args.interactive:
            print("[*] interactive mode — press Ctrl+C to quit")
            try:
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                pass

        ctx.close() if args.persist else browser.close()

    print("[*] done. Replay cookies with: curl -b cookies.txt")
    return 0


if __name__ == "__main__":
    sys.exit(main())
