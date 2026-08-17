# Validation & False Positives

The single most important discipline in this skill: **a bypass claim is only real if you can prove the origin application answered.** Challenge pages, WAF block pages, and bot-manager error pages routinely return HTTP `200` — never trust the status code alone.

## The false-bypass failure modes

| What you see | What it really is |
|---|---|
| `200` with a tiny body / empty | JS challenge page (Cloudflare `cf_chl`, DataDome, "Checking your browser") |
| `200` with `g-recaptcha`/`cf-turnstile`/`h-captcha` JS | The widget page, not the app |
| `200` but body = generic WAF/bot block text | Block page dressed as 200 |
| `302` to a challenge/error path you didn't request | Gate redirect |
| `403` after "solving" a CAPTCHA | No bypass — token rejected or IP still scored |
| Infinite challenge loop (solve → re-challenge) | Session/token not persisted correctly |

## Minimum validation bar (do this every time)

1. **Status + content-type sanity.** `200` + `text/html` + body > ~1KB, with app-looking markup.
2. **App-specific marker.** Grep for a string that only the real app contains — `<title>`, a known endpoint name, a unique JS bundle path, a meta tag. Not present → not the origin.
3. **Absence of gate markers.** Body must NOT contain `challenge-platform`, `cf-chl`, `_px`, `datadome`, `grecaptcha`, `h-captcha`, `turnstile`, `funcaptcha`, `AWS WAF`, "Verify you are human", "Checking your browser".
4. **Cross-check with the same request *without* your bypass.** If the un-bypassed request is blocked/challenged but the bypassed one returns app content, you've proven the bypass did something.
5. **Cookies actually issued.** If the gate should mint a clearance cookie (`cf_clearance`, `datadome`, `_pxhd`, `_abck`), confirm it exists in the jar and replay a second request with it — the second request should be clean without re-challenging.

## What counts as "reached origin"

- The protected resource returned real application data (not a challenge page).
- A state-changing action (login, form submit, API call) succeeded *because* you passed the gate — and failed without it.
- You can now run your normal tooling (ffuf, sqlmap, burp) against the endpoint using the captured session.

## Distinguishing a WAF block from a bot block (important for reporting)

| Signal | WAF (application-level) | Bot-manager / AI gate (this skill) |
|---|---|---|
| Triggers on specific attack payloads | Yes | Rarely — triggers on automation/IP/behavior |
| Triggers on plain GET/POST with no payload | Rarely | Yes |
| Challenge/JS interstitial | No (usually hard block) | Yes (challenge then allow) |
| Bot cookies minted on success | No | Yes (`cf_clearance`, `_pxhd`, etc.) |
| Fingerprint / behavior sensitive | No | Yes |

If it's a WAF block, use `waf-bypass` + the relevant `hunt-*`/exploitation skill — NOT this one.

## Validating CAPTCHA / LLM-gate results

- **CAPTCHA solved but still blocked?** Not a bypass. Check: IP scoring, cookie lifetime, token-vs-session binding, wrong sitekey/pageurl in solver call.
- **LLM challenge answered correctly but still challenged?** Not a bypass. Confirm the judge actually accepted (look for a `success:true`/`verify` response) and that you're submitting to the right endpoint in the same session.
- **Presence-only token** (empty/forged accepted): that's a *real finding* — weak server-side validation — and worth its own report entry. Document the exact request body showing the missing check.

## Evidence for the report

Per `evidence-hygiene`:

- Capture BOTH requests side-by-side: the blocked one and the bypassed one (headers, status, body length, first N bytes of body).
- Screenshot the challenge/block page before, and the origin content after, with cookies **redacted** (challenge cookies are session tokens).
- Note which layer you bypassed (network → browser → CAPTCHA → LLM-gate) and the exact tooling/config that worked — reproducibility is what makes it a finding.

## Checklist before writing anything up

- [ ] Status is a *real* app response, not a challenge page
- [ ] App-specific marker present; gate markers absent
- [ ] Same request without bypass is blocked (control)
- [ ] Clearance cookie minted & replay works
- [ ] State-changing action succeeded through the gate
- [ ] RoE allows what you did (no CAPTCHA/rate-limit prohibition violated)

## Related

- `vendor-fingerprinting.md` — confirm you even found the right gate.
- `browser-fingerprint-evasion.md` / `captcha-solving-ladder.md` / `llm-judge-gate-bypass.md` — the layer you need to validate.
- `evidence-hygiene` — screenshot + cookie redaction discipline.