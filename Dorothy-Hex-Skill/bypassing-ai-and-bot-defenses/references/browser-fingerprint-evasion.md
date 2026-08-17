# Browser, Network & Behavioral Evasion

Look human at every layer the vendor can inspect. Layered evasion compounds: fix the network/TLS fingerprint first, then the browser fingerprint, then behavior. Each layer is independently detectable.

## Layer 0 — Network / TLS (fix before anything else)

Active bot managers score the TLS ClientHello (JA3/JA4), HTTP/2 settings, and TCP options *before* JS even runs. A `curl` JA3 is a dead giveaway regardless of how human your browser is.

### TLS + HTTP2 impersonation

```bash
# curl-impersonate (or python curl_cffi with impersonate="chrome124")
curl_cffi requests:
    curl_cffi.requests.get(url, impersonate="chrome", headers=real_headers)
```

Match the TLS/HTTP2 fingerprint of the real Chrome/Firefox/Safari version you claim in the UA. `curl_cffi` `impersonate=` presets handle JA3/JA4 + HTTP2 + header order for you.

### Headers consistency

Every header must be consistent with the UA + geolocation you present:

- `User-Agent` — must match the real browser version you emulate.
- `Sec-CH-UA`, `Sec-CH-UA-Mobile`, `Sec-CH-UA-Platform` — must match the UA (Chrome sends these).
- `Accept`, `Accept-Language`, `Accept-Encoding` — realistic full set.
- `Referer` — for API calls, the SPA origin (a missing/wrong referer is a bot signal).
- Cookie consistency — send the session cookie set, not a lone token.

### IP reputation

| IP type | Risk | Use when |
|---|---|---|
| Datacenter (AWS/GCP/Azure/VPS) | High — penalized heavily | Only for API paths with no IP scoring |
| Commercial VPN | Medium | Low-value targets |
| Residential proxy / rotating | Low | Active bot mgmt (DataDome/PerX/Akamai) |
| Home ISP | Lowest | Ideal — Cloudflare Turnstile managed mode |

Note: `curl_cffi` + residential proxy + consistent headers solves the *majority* of passive-gate blocks with zero browser needed.

## Layer 1 — Browser automation detection

The big one. `navigator.webdriver === true`, CDP traces, headless leaks.

### Mandatory: headed mode

Never run headless against active bot management. For server/Docker, start Xvfb and set DISPLAY (do NOT use `xvfb-run` as an MCP wrapper — it breaks stdio).

```bash
Xvfb :99 -screen 0 1920x1080x24 &>/dev/null &
export DISPLAY=:99
```

### Chromium flags

```
--disable-blink-features=AutomationControlled   # kills navigator.webdriver=true
--disable-infobars
--no-first-run --no-default-browser-check
--window-size=1920,1080
--no-sandbox --disable-setuid-sandbox
--disable-dev-shm-usage
```

### Use a stealth-patched driver, not raw automation

| Tool | Notes |
|---|---|
| **patchright** (Playwright fork) | Modern, removes CDP traces, best current option |
| **undetected-chromedriver** (Selenium) | Classic, still works vs many |
| playwright-extra + stealth plugin (Node) | Quick patch layer |
| Camoufox | Firefox-based anti-fingerprint — strong for canvas/WebGL noise |

`scripts/stealth_browser.py` uses patchright-first with a Playwright fallback.

### init-script patches (belt & suspenders)

Inject these before page scripts run:

```javascript
Object.defineProperty(navigator, 'webdriver', { get: () => undefined });
Object.defineProperty(navigator, 'plugins', { get: () => [realPlugin('Chrome PDF Plugin'), realPlugin('Chrome PDF Viewer')] });
Object.defineProperty(navigator, 'languages', { get: () => ['en-US', 'en'] });
window.chrome = window.chrome || { runtime: {}, app: {}, csi: () => 0, loadTimes: () => ({}) };
```

## Layer 2 — Fingerprint surfaces (canvas/WebGL/audio/fonts)

Active bot managers fingerprint the canvas pixel hash, WebGL renderer, AudioContext, and font set. Headless/non-GPU environments leak (`SwiftShader`/`llvmpipe` renderer, empty fonts).

Best: use **Camoufox** or a fingerprint-rotating setup. Manual patches:

```javascript
// Canvas — inject deterministic noise
HTMLCanvasElement.prototype.toDataURL = function(type) {
    const ctx = this.getContext('2d');
    const img = ctx.getImageData(0, 0, this.width, this.height);
    for (let i = 0; i < img.data.length; i += 4) img.data[i] ^= (img.data[i] & 1); // LSB flip
    ctx.putImageData(img, 0, 0);
    return origToDataURL.apply(this, arguments);
};

// WebGL — generic GPU
WebGLRenderingContext.prototype.getParameter = function(p) {
    if (p === 37445) return 'Intel Inc.';           // VENDOR
    if (p === 37446) return 'Intel(R) UHD Graphics 630'; // RENDERER
    return origGetParameter.apply(this, [p]);
};
```

## Layer 3 — Behavioral biometrics

Bot managers and enterprise products score mouse path, keystroke cadence, scroll, dwell time. `scripts/stealth_browser.py` implements all of these:

- **Mouse:** Bézier curves, variable speed, overshoot, hover-before-click (50–500 ms).
- **Typing:** gaussian 50–200 ms keystrokes, longer pause on space/punctuation.
- **Scroll:** incremental wheel deltas, variable speed, pause while "reading".
- **Timing:** random 200 ms–3 s between actions; never uniform; idle micro-movements.
- **Page read time:** 1–30 s of dwell before interacting.

## Detection probes (run against yourself to confirm clean)

```javascript
navigator.webdriver                  // undefined = clean
Object.keys(navigator).includes('webdriver')  // should be false
window.chrome.runtime                // present in real Chrome
window.outerHeight                   // 0 = headless leak
navigator.plugins.length             // > 0 expected
navigator.languages                  // ['en-US', 'en']
new WebGLRenderingContext().getParameter(37446).toString()  // no SwiftShader/llvmpipe
document.querySelector('body') !== null  // page actually rendered
```

## Layer 4 — Session persistence & cookiejar hygiene

Once you pass, the gate hands out cookies (`cf_clearance`, `__cf_bm`, `datadome`, `_pxhd`, `ak_bmsc`, `aws-waf-token`). Preserve them:

- Use a persistent context (`launch_persistent_context`) or save/load the cookie jar between runs.
- Re-request before expiry; only re-solve when you get challenged again.
- For curl/ffuf: export cookies with `curl -b jar.txt -c jar.txt` from the solved session.

## Checklist before reporting a browser bypass

- [ ] Headed browser (never headless)
- [ ] `--disable-blink-features=AutomationControlled`
- [ ] `navigator.webdriver` patched + verified `undefined`
- [ ] Real UA + matching `Sec-CH-UA-*`/headers
- [ ] Canvas/WebGL patched or Camoufox used
- [ ] Humanized mouse/typing/scroll/timing
- [ ] Session cookies persisted
- [ ] Network layer: TLS impersonation (curl_cffi) or residential IP if scored
- [ ] Validated origin actually responded (`validation-and-false-positives.md`)

## Related

- `vendor-fingerprinting.md` — know which layer matters for your vendor.
- `captcha-solving-ladder.md` — what to do when behavior alone isn't enough.
- `llm-judge-gate-bypass.md` — when the gate is an LLM, not JS.