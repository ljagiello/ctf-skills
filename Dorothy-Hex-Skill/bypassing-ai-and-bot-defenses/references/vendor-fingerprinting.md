# Vendor Fingerprinting — Which Defense Is In Front?

Identify the exact anti-bot / AI-defense vendor in front of your target, then apply its specific bypass. Fingerprint FIRST — a Cloudflare challenge, DataDome 403, and an LLM-judge gate are solved completely differently.

## Quick Fingerprint

Run `scripts/fingerprint_defense.py -u https://TARGET/` or:

```bash
# Headers + cookies
curl -sI https://TARGET/ | grep -iE 'cf-|__cf|datadome|_px|px-|akam|imperva|ak-ai|set-cookie|server|via|x-powered|x-request'

# Body markers + JS loader URLs
curl -s https://TARGET/ | grep -oiE 'turnstile|cf-chl|challenge-platform|recaptcha|grecaptcha|hcaptcha|geetest|funcaptcha|arkose|datadome|/pxhd|/pxc|perimeterx|incapsula|imperva|akamai|/_dd|/antibot|"fingerprint|client-side' | sort -u

# DNS/TLS hints
dig +short TARGET | head
curl -sI https://TARGET/ -o /dev/null -D - 2>&1 | grep -iE '^(date|server|via|cf-ray|akamai|ah-|x-datadome|x-akamai)'
```

## Vendor Matrix

| Vendor | Header / cookie / body signals | Challenge type | Block symptom | Weakest bypass |
|---|---|---|---|---|
| **Cloudflare Bot Management / Turnstile** | `cf-ray`, `__cf_bm`, `cf_clearance`, `__cf_chl_`, `Server: cloudflare`, `challenge-platform` JS, `cf_chl_opt`, "Verify you are human" | Turnstile widget (managed/non-interactive/interactive), JS challenge interstitial | `403`, empty body, JS challenge page, `cf-mitigated` | Headed stealth browser + let Turnstile auto-solve; API path; session persistence of `cf_clearance` (see `reconnaissance/reference/anti-bot-bypass.md`) |
| **DataDome** | `x-datadome: protected`, `datadome` cookie, `dd_cookie_test_`, `ddk_`, body has `var dd =` / `window.DataDome` | JS challenge + CAPTCHA, blocks on bot score | `403` with "Request blocked by DataDome", empty body | Curl impersonation of a real browser TLS+headers; solve CAPTCHA via paid solver; residential IP (heavy IP scoring) |
| **PerimeterX / HUMAN (HUMAN Security)** | `_pxhd`, `_px`, `_px3`, `_pxde`, `x-px-*` headers, `px` cookie, `/px.js`, `/pxhd` calls | JS behavioral + reCAPTCHA-look | `403` with `PXV` block, empty body | Headed stealth browser (PerX is very fingerprint-sensitive); `undetected-chromedriver`; API path; periodic re-eval (cookies expire in minutes) |
| **Akamai Bot Manager** | `akamai` cookies (`_abck`, `bm_sz`, `ak_bmsc`), `AkamaiGHost`, `AKAMAI` headers, `X-Akamai-*`, "Access Denied / `Your IP is being used by a bot`" | JS challenge (`_abck` sensor), CAPTCHA at high score | `403` "Access Denied", sensor validation | Curl impersonation with consistent HTTP/2 + TLS + headers; solve `_abck` sensor via headed browser; long-lived session replay |
| **reCAPTCHA v2/v3 / Enterprise** | `g-recaptcha`, `recaptcha` JS, `reCAPTCHA Enterprise` in JS, `co=`, `hl=` params | v2 checkbox/image grid; v3 invisible score (0.0–1.0) | v3: actions silently downgraded / blocked; v2: widget | v3: real-human traffic + score >0.5, or use a browser and accept score; API path. v2: paid solver or audio. Token replay if not bound to session |
| **hCaptcha** | `h-captcha`, `hcaptcha` cookie, `st=`, `host=`, `sitekey` | Image grid, checkbox | Widget shown, no token → submit fails | Paid solver; audio; API path. (hCaptcha is the most CAPTCHA-resistant; no reliable pure-OCR) |
| **GeeTest** | `gt`, `challenge`, `new-captcha`, `geetest` JS | Slider puzzle / click-and-hold | Widget blocks submit | Paid solver; solve slider by drag (humanized); API path |
| **Arkose / Funcaptcha** | `funcaptcha`, `arkose`, `public_key`, `datakey`, `/fc/assets/` | Image-challenge puzzle (not OCR-able) | Widget, submit blocked | Paid solver only (Arkose is anti-OCR by design); API path; or find the protected endpoint bypass |
| **AWS WAF Bot Control** | `x-amzn-*`, `AWSALB`, `aws-waf-token`, "Request blocked" body with `AWS WAF` | Token-based (managed challenge), CAPTCHA rule | `403` with AWS WAF block page | Headed browser to generate `aws-waf-token`; API path; IP allowlist if in scope. Distinguish from plain WAF rule |
| **Imperva / Incapsula** | `X-Iinfo`, `incap_ses`, `visid_incap`, `_incap_`, `Imperva` | JS challenge + CAPTCHA | `403`, "Powered by Imperva" | Headed browser; session replay; API path |
| **Fastly (Next-Gen WAF / Bot)** | `X-Served-By: cache-...`, `Fastly` in headers, `fastly` cookies | Managed challenge / VCL rule | `403` "Blocked" | Headed browser + session; API path |
| **Google reCAPTCHA Enterprise on GCP** | `recaptchaEnterprise` in JS, `X-Goog-*`, GCP frontend | Score-based + widget | Score gates APIs | Legit-looking browser traffic; API path; score inflation via warm session |
| **Generic JS challenge** (custom) | Inline `setTimeout` redirect, `document.cookie` flip, "Checking your browser" | Refresh-challenge | First request `503`/`403`, then cookie → `200` | Just fetch twice / save the cookie; trivial |

**Unknown / custom gate:** treat as JS challenge + behavior; read `browser-fingerprint-evasion.md`.

## Passive vs Active Gate

- **Passive (risk-scored):** blocks or scores silently on headers/IP/TLS/behavior. No widget. → Evasion = look human at network + browser layer. Validation = origin responds with real content.
- **Active (challenge):** requires an interactive token (CAPTCHA/Turnstile/Arkose/AI challenge) before the app accepts requests. → Evasion = CAPTCHA ladder (`captcha-solving-ladder.md`) or API path. Validation = the protected endpoint returns app data with the token.

## Signal → Vendor Cheat (body markers)

```
challenge-platform, cf_chl, turnstile      → Cloudflare
window.DataDome, x-datadome, dd_cookie     → DataDome
_abck, bm_sz, AkamaiGHost, ak_bmsc         → Akamai
_pxhd, _px3, /px.js, PXV                   → PerimeterX/HUMAN
grecaptcha, g-recaptcha, recaptcha         → Google reCAPTCHA
h-captcha, hcaptcha                        → hCaptcha
geetest, new-captcha, gt_challenge         → GeeTest
funcaptcha, arkose, /fc/assets/            → Arkose/Funcaptcha
aws-waf-token, AWS WAF                     → AWS WAF Bot Control
X-Iinfo, incap_ses, visid_incap            → Imperva/Incapsula
"describe this image", "solve the riddle", "select the odd one out",
  "which is not an animal", LLM-judge wording, "verify you are a human
  (AI assisted)"                           → LLM/AI gate (llm-judge-gate-bypass.md)
```

## If Multiple Signals Match

Stacked defenses are common (e.g., Cloudflare Bot Management **+** reCAPTCHA on the app). Bypass the outer gate (CDN challenge) first, persist its cookie, then handle the app-level widget. Document both layers — a finding that only skips one layer is a partial bypass.

## Per-Vendor Bypass Notes

- **Cloudflare Turnstile:** managed mode auto-solves in a headed stealth browser within ~5–15s. Non-interactive completes automatically. Interactive → paid solver or manual. Persist `cf_clearance` (15–30 min). See `reconnaissance/reference/anti-bot-bypass.md` for the full playbook.
- **DataDome / PerimeterX:** the most fingerprint-sensitive. A headed stealth browser (patchright/undetected-chromedriver + real UA + humanized behavior) is mandatory for UI paths. API/mobile endpoints frequently skip the widget. Expect short cookie lifetimes (PerX: minutes) → script re-solves.
- **Akamai:** `_abck` requires running the full sensor JS; only a real browser (or careful JS replay) generates a valid cookie. Session replay of a captured `_abck`+`bm_sz`+`ak_bmsc` set works for the cookie lifetime. TLS+HTTP2 fingerprint consistency matters (`curl_cffi` impersonate=chrome).
- **reCAPTCHA v3:** it's a score, not a pass/fail. A clean headed browser with realistic traffic usually scores >0.5. Automating the widget itself is the wrong move; automate *around* it (API path) or accept a scored-but-working session.
- **Arkose/Funcaptcha:** deliberately non-OCR. Paid solver or API path only. Do not burn hours on OCR.
- **GeeTest:** drag-slider can be solved with humanized mouse drag (see `scripts/stealth_browser.py`), but a paid solver is more reliable.

## Related

- `browser-fingerprint-evasion.md` — how to look human once you know the vendor.
- `captcha-solving-ladder.md` — interactive widget handling per family.
- `llm-judge-gate-bypass.md` — when the "CAPTCHA" is really an LLM.
- `validation-and-false-positives.md` — prove the bypass actually landed.