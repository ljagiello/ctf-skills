---
name: bypassing-ai-and-bot-defenses
description: "Authorized penetration testing of targets protected by AI/anti-bot defenses that block AI agents and automation. Fingerprint the defense vendor (Cloudflare Turnstile/Bot Management, reCAPTCHA/Enterprise, hCaptcha, DataDome, PerimeterX/HUMAN, Kasada, Akamai Bot Manager, GeeTest, Arkose, AWS WAF Bot Control), then bypass per layer: browser/headless detection, network/TLS fingerprinting, behavioral biometrics, CAPTCHA solving ladder, direct API/mobile path, and LLM-judge/AI-gate evasion. Ends with validation that requests actually reached origin (no false-positive bypass claims). Use when a target 403s/challenges/blocks curl, Playwright, headless, or LLM-driven requests; when recon shows bot-management cookies (cf_clearance, __cf_bm, _pxhd, datadome), JS fingerprinting, CAPTCHA interstitials, or AI/LLM content gates. Requires written authorization — this is evasion of access controls on a scoped target, not for bypassing any other party's controls."
---

# Bypassing AI & Bot Defenses

Reach the origin application of a target that actively blocks AI agents, headless browsers, and automated tooling. This is the "how do I even GET a request through" problem that sits *before* web exploitation — a target that challenges every `curl` is unexploitable until the gate is passed.

Only for **authorized, in-scope** engagements. Every technique here defeats an access-control layer on a target you are permitted to test. Never use these to bypass protections that do not belong to your scope.

## When to Use

Load this skill when any of these is true:

- `curl`/`ffuf`/`sqlmap`/`burp` returns `403`, an interstitial, a blank body, or a JS-challenge page.
- Response headers or cookies reveal a bot manager (see `references/vendor-fingerprinting.md`).
- An LLM agent (opencode/Claude Playwright MCP, puppeteer, etc.) is instantly challenged while a human browser isn't.
- A CAPTCHA / Turnstile / reCAPTCHA / hCaptcha / Arkose widget appears on login, search, form, or submission endpoints.
- The target uses an AI/LLM layer as a gate (LLM judge on user input, AI content moderation, AI-generated captcha, "describe the image" challenge).

**Do NOT load** when the target is plain HTTP with no anti-automation layer — that's normal web testing (`ctf-web`, `performing-web-application-penetration-test`, `hunt-*`).

## Core Workflow

The bypass is a **layered funnel**, not one trick. Work top-down; each layer compounds.

```
1. FINGERPRINT the defense      → which vendor(s)? which layer blocks you?
2. PICK the cheapest valid path → API/mobile first, browser last
3. EVADE per layer              → network → browser → CAPTCHA → LLM-gate
4. VALIDATE real access         → prove origin responded (never assume)
5. RECORD what worked           → cookies + config for the rest of the engagement
```

### Step 1 — Fingerprint (5 min)

Run `scripts/fingerprint_defense.py -u <URL>` or do it by hand:

```bash
# Headers + cookies reveal the vendor
curl -sI https://TARGET/ | grep -iE 'cf-|datadome|_px|akam|imperva|__cf|samesite|Server|Via'
curl -s https://TARGET/ | grep -iE 'fingerprint|turnstile|recaptcha|hcaptcha|geetest|arkose|funcaptcha|datadome|perimeter|/pxhd|/cdc/|webdriver'
```

Map the signals to a vendor with `references/vendor-fingerprinting.md`. Two cases:

- **Passive gate** (no interactive challenge, just risk-scored blocks): evasion is about *looking human* at network+browser layer.
- **Active gate** (CAPTCHA/Turnstile/LLM challenge required to proceed): you need the *solving ladder*.

### Step 2 — Cheapest valid path first (the 80/20 rule)

Before fighting the browser, check for paths that bypass the browser entirely:

1. **Direct API endpoints** — the SPA talks to `api.TARGET` or `/api/*` that may have *weaker or no* bot protection than the UI. Login via API, reuse the token/cookie in the browser.
2. **Mobile / app versions** — `m.TARGET`, app UA, or endpoints reached with a mobile UA + API key often skip the web CAPTCHA (mobile SDKs get their own challenge type).
3. **Alternate hostname/port** — `www.`, bare domain, staging subdomain, alternate port, IP:port origin, `cdn.`/`static.` (many bot managers only front the main hostname).
4. **Legacy endpoints** — old login paths, `/api/v1` vs `/v2`, undocumented endpoints from JS bundles (see `hunt-source-leak`).

If a valid API path exists, capture the resulting auth cookie and feed it back to your main tooling. Many engagements never need a CAPTCHA solve.

### Step 3 — Evade per layer

Pick from `references/browser-fingerprint-evasion.md` (network + browser + behavior) and `references/captcha-solving-ladder.md` (interactive challenges). Order of effort:

| Layer | Blocks | Cheap wins |
|---|---|---|
| Network/TLS | JA3/JA4, IP reputation, HTTP2 fingerprint | `curl_cffi` impersonation, residential/rotating IP, real UA+headers, HTTP/2 profile match |
| Browser detection | `navigator.webdriver`, headless leaks, canvas/WebGL, plugins | headed browser + stealth flags, `patchright`, `undetected-chromedriver`, init-script patches |
| Behavioral | timing, mouse path, keystroke cadence, scroll | humanized helpers (see `scripts/stealth_browser.py`) |
| CAPTCHA | interactive widget | `references/captcha-solving-ladder.md` ladder |
| LLM/AI gate | LLM judge, AI moderation, AI captcha | `references/llm-judge-gate-bypass.md` |

### Step 4 — Validate (mandatory gate)

A bypass claim is worthless — and reportable as a finding — **only if you can prove origin responded**. Never assume the `200` you got is real application content vs a challenge page dressed as `200`.

Check with `references/validation-and-false-positives.md`. Minimum bar:

- Status + body length sanity (challenge pages are small and contain `challenge`, `cf-`, `antibot`, `recaptcha`, JS).
- Presence of app-specific markers (title, meta, a string unique to the app) in the response.
- Absence of the gate's own markers (`cf_clearance` challenge, `_px` 403, `datadome` 403 block page).
- If the gate hands out a clearance token, re-request with it and confirm the body changes from challenge → content.

### Step 5 — Record

Save the winning config (cookies, headers, TLS impersonation, proxy, behavior profile) — you'll reuse it for every subsequent request in the engagement. Persist `cf_clearance`/`datadome`/`_pxhd` cookies in your request tooling instead of re-solving.

## Key Decision Trees

### "curl gets 403 / empty body — what do I do?"

```
403 or empty body
├─ No bot cookies/headers, plain 403 → real ACL/WAF (see waf-bypass, hunt-*)
├─ Bot cookie present (__cf_bm, cf_clearance, datadome, _pxhd) → vendor fingerprint → evasion
├─ JS challenge page (challenge-platform, "cf-chl") → headed browser + stealth, let it solve
├─ Interactive CAPTCHA → captcha ladder (OCR → replay → API → paid)
└─ "Describe image / solve AI challenge" → LLM-judge gate bypass
```

### "Playwright/headless gets blocked instantly, human browser is fine"

That's **browser-layer detection** — headless leaks. Fix priority:

```
1. Headed browser (never headless against active bot mgmt)
2. --disable-blink-features=AutomationControlled
3. patch navigator.webdriver / chrome / plugins / languages (init script)
4. Real UA matching your Chrome version + Sec-CH-UA-* consistency
5. Xvfb/DISPLAY for headed-in-docker (NOT xvfb-run wrapper for MCP)
6. Then worry about network/TLS and behavior
```

### "CAPTCHA on every form"

Don't fight the widget — find the API it protects. CAPTCHAs guard UI flows; the underlying JSON endpoint frequently has none or a weaker check. If the API path is mandatory:

```
1. OCR (Tesseract + preprocessing) — only for simple text CAPTCHAs
2. Session/token replay — reuse a solved token if server doesn't bind it
3. Direct API + stolen/guessed challenge response (if not server-validated)
4. Audio CAPTCHA (weaker than visual) — transcribe
5. Paid solving service (2captcha/anti-captcha) — engagement-grade volume
```

Full details + per-vendor notes in `references/captcha-solving-ladder.md`.

## Critical Rules

- **Authorization required.** You are bypassing access controls. Confirm written scope, target list, and rules of engagement (RoE) — many RoEs *forbid* CAPTCHA bypass or rate-limit workaround; respect them.
- **Never defeat rate limits / lockouts** even if you can — those are usually out of scope (see RoE in `student_instruction.txt` example) and rarely constitute a finding.
- **Don't bypass *other people's* controls.** This skill is for your scoped target only, not for evading CDN/WAF protections belonging to a third party in front of the target's stack unless it's in scope.
- **Validate before reporting.** A solved CAPTCHA that still gets `403` = no bypass. A `200` that's actually a challenge page = no bypass.
- **Preserve evidence** per `evidence-hygiene` — cookies redacted in screenshots, challenge flow documented.

## Related Skills & Chains

- **`reconnaissance` / `hunt-source-leak`** — find the JS bundle, extract API endpoints & tokens *before* fighting the browser; often the cheapest bypass is an endpoint the gate forgot.
- **`waf-bypass`** — a WAF block is NOT a bot block. Distinguish by fingerprint, then apply the right skill.
- **`authentication`** — `reference/BOT_DETECTION.md` + `reference/CAPTCHA_BYPASS.md` contain the base evasion notes this skill expands into vendor-level playbooks.
- **`hunt-llm-ai` / `ai-threat-testing`** — once past the gate, if the *application itself* is an LLM (chatbot, RAG, agent), hunt those. This skill gets you *through* the door; those skills test what's behind it.
- **`redteam-mindset`** — the CAPTCHA cost ladder (don't give up at OCR failure; a paid solver is engagement-budget-cheap).
- **`evidence-hygiene`** — challenge/cookie redaction in screenshots.

## Files

- `SKILL.md` — this orchestrator.
- `references/vendor-fingerprinting.md` — map headers/cookies/JS to the exact defense vendor + per-vendor bypass notes.
- `references/browser-fingerprint-evasion.md` — network/TLS + browser + behavioral evasion in depth.
- `references/captcha-solving-ladder.md` — all CAPTCHA families + the solving ladder.
- `references/llm-judge-gate-bypass.md` — when the gate itself is an AI/LLM.
- `references/validation-and-false-positives.md` — prove origin answered; avoid fake bypasses.
- `scripts/fingerprint_defense.py` — automated vendor fingerprinting.
- `scripts/stealth_browser.py` — headed-stealth Playwright with humanized behavior.
- `scripts/captcha_ladder.py` — orchestrate the CAPTCHA solving ladder.