# CAPTCHA Solving Ladder

Interactive gate in the way? Work the ladder from cheapest to most robust. **Always try the API path first** (see SKILL.md Step 2) — most CAPTCHAs only guard the UI, and the JSON endpoint underneath often has no widget at all.

## CAPTCHA families & what's actually solvable

| Family | OCR-able? | Reliable path | Notes |
|---|---|---|---|
| Simple text CAPTCHA (custom) | Yes | Tesseract + preprocessing | Best case; still noisy |
| Math / basic word | Yes (if simple) | OCR, or answer via regex on rendered text | Sometimes answers appear in HTML/alt |
| **reCAPTCHA v2** | No (image grid) | Paid solver; audio path; token replay | Grid is deliberate anti-OCR |
| **hCaptcha** | No | Paid solver; audio | Most resistant of the interactive ones |
| **Turnstile** | N/A (invisible) | Headed stealth browser auto-solve | See anti-bot-bypass playbook |
| **GeeTest** | Partial (slider) | Humanized drag; paid solver | Slider is physics-scored |
| **Arkose / Funcaptcha** | No | Paid solver only | Designed non-OCR; don't waste time |
| **reCAPTCHA v3** | N/A (score) | Real-human traffic; API path | Score, not a widget — automate around it |

## Ladder steps (in order)

### 1. Bypass the widget entirely — API path

Find the endpoint the form submits to (JS bundle → `hunt-source-leak`). Call it directly with session cookies + a fake/empty `g-recaptcha-response`/`h-captcha-response`/`cf-turnstile-response`:

```bash
curl -s -X POST https://TARGET/api/login \
  -H "Content-Type: application/json" \
  -H "Referer: https://TARGET/login" \
  -b "session=..." \
  -d '{"user":"x","pass":"y"}'
```

If the server validates the token server-side, this fails — move to the next rung. If the field is `required: false` client-side only, you're done (that's often a finding by itself: CAPTCHA bypass by direct API call).

### 2. Token replay / reuse

Some implementations validate *presence* of a token, not *freshness*:

- Capture one valid token (manually solve once or via solver), then reuse it for multiple submits or across sessions.
- Check whether the token is bound to session (`?co=`/`hl=` params, host binding). If not, replay.
- Test whether an *expired-but-validly-signed* token still passes (weak time-check).

This is cheap and works surprisingly often on internal/buggy implementations.

### 3. Session / clearance-cookie replay

For JS-challenge gates (Turnstile, CF challenge, Akamai `_abck`), the *cookie* is the token. Solve once in a headed browser, persist `cf_clearance` / `__cf_bm` / `datadome` / `_abck`+`bm_sz`+`ak_bmsc`, then replay with curl until expiry. See `browser-fingerprint-evasion.md` Layer 4.

### 4. OCR (only for simple text CAPTCHAs)

```bash
tesseract captcha.png out -l eng --psm 7 -c tessedit_char_whitelist=abcdefghijklmnopqrstuvwxyz0123456789
```

Preprocess first (grayscale → threshold → deskew) with OpenCV/PIL — raises Tesseract accuracy a lot. Timebox this: if accuracy < ~60% after preprocessing, go to the paid solver. Do not OCR hCaptcha/Arkose — by design it fails.

### 5. Audio CAPTCHA

reCAPTCHA/hCaptcha offer audio challenges (usually weaker than visual). Fetch the audio, transcribe (Whisper or a caption service), submit. On reCAPTCHA this flips between solvable and solved within a couple rounds. Deprecated for reCAPTCHA in places but still present on hCaptcha.

### 6. Paid solving service

For engagement-grade volume on hCaptcha / Arkose / GeeTest / reCAPTCHA:

- 2captcha, anti-captcha, CapSolver — solve-by-sitekey via HTTP API.
- Send `sitekey`, `pageurl`, and the challenge type; poll for the token; inject as `g-recaptcha-response` / `h-captcha-response` / `cf-turnstile-response`.

Cheap ($1–3 per 1000 solves) and engagement-budget-justifiable. **Verify RoE first** — some scopes explicitly forbid CAPTCHA bypass or outsource solving.

`scripts/captcha_ladder.py` orchestrates: probes the widget, tries direct-API → replay → OCR → paid-solver in order, and returns the winning token/cookie with the method used.

## Anti-patterns to avoid

- **Brute-forcing the token** (6-digit puzzle variants): noisy, usually rate-limited, rarely a finding.
- **OCR on image-grid CAPTCHAs**: guaranteed fail, wastes hours.
- **Reusing one token across thousands of requests on a score-based gate**: gets your session downgraded.
- **Skipping validation**: a solved CAPTCHA that still `403`s = no bypass. Always confirm with `validation-and-false-positives.md`.

## Report notes

If CAPTCHA is bypassable via direct API (no server-side token check), that's a distinct, reportable finding (weak CAPTCHA enforcement / missing server-side validation) — separate from "we solved the CAPTCHA", which is not usually a finding by itself. Capture evidence: request to the API with empty captcha field succeeding, vs. the UI enforcing the widget.