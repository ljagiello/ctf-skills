# LLM / AI-Gate Bypass

Sometimes the gate is not a vendor bot-manager or CAPTCHA — it's **an AI/LLM judging whether you're human**. This is the "AI protecting against AI" case: the target uses an LLM (or an AI pipeline) to challenge, score, or gate automated/AI visitors. Distinct from `hunt-llm-ai` / `ai-threat-testing`, which attack LLM **applications**; here the LLM **is the access control**.

## How to recognize an AI gate

Body/page markers:

- "Describe this image", "Select the odd one out", "What's happening in this photo", "Solve the riddle", "Which of these is not a …", "Answer the AI's question"
- "AI-assisted human verification", "prove you are human", "pass the AI test"
- Challenge images with open-ended answers (not fixed grids) → LLM is evaluating the answer semantically
- A text box asking you to *describe* / *explain* something rather than select
- Responses where *any* plausible correct answer works vs only one pixel-exact answer (a giveaway the judge is an LLM with fuzzy acceptance)

Also possible: the gate runs an **LLM scorer** on your inputs/actions to decide bot-vs-human (behavioral AI, anomaly detection, "humanity score"). In that case it overlaps with `browser-fingerprint-evasion.md` + humanized behavior.

## Strategy 1 — Answer the LLM challenge directly (you're also an LLM)

For "describe/solve the AI challenge" gates, drive the challenge with another LLM/vision model:

- Fetch the challenge (image/text) from the endpoint (find it in the page JS / API).
- Send it to a vision-capable model to produce a correct, human-sounding answer.
- Submit as the CAPTCHA response.

Pitfalls:
- The judge may score *answer speed + format*. Don't answer instantly — add human-like latency.
- The judge may re-challenge or rotate images per session; handle retry.
- Some gates bind the challenge to a token/session — fetch + answer + submit in the same session.

## Strategy 2 — Bypass the AI gate structurally

The same "cheapest path first" rule from SKILL.md applies — find where the gate is NOT enforced:

1. **API/mobile path** — the AI gate usually lives in the browser SPA; `api.`/`/api/` endpoints and mobile app versions often skip it.
2. **Cookie/session replay** — pass the challenge once in a real browser, harvest the issued clearance cookie, replay it in curl. Works if the gate is a one-time check.
3. **Challenge endpoint missing on some routes** — same app, some endpoints require the token, others don't (undocumented route, health/static, admin, upload).
4. **Token not server-validated** — submit any plausible value; if the server only checks *presence*, the AI judge never runs (weakest finding: AI gate bypass by missing server-side verification).
5. **Race/weak binding** — challenge token accepted cross-session or with a stale-but-unexpired token.

## Strategy 3 — Prompt-inject the gate if it's a text gate

If the gate accepts free text that an LLM evaluates (e.g., "type a short bio to prove you're human", "answer why you're visiting"), treat the *judge* as an LLM application and prompt-inject it (see `ai-threat-testing`, `hunt-llm-ai`):

- Convince the judge the answer satisfies its rubric even when wrong.
- If the judge exposes reasoning/confidence in an API, probe it.
- Be careful: this only makes sense when the gate is genuinely an LLM judging free text and it's in scope.

## Strategy 4 — Behavioral / anomaly-scored AI gates

If the "AI" is a scorer on your session/behavior rather than a challenge:

- Run the full humanized profile (`browser-fingerprint-evasion.md`, `scripts/stealth_browser.py`).
- Establish a warm session: browse a few pages like a person (dwell, scroll) *before* hitting the gated action.
- Spread requests over realistic intervals; avoid burst patterns that the anomaly model flags.
- Use residential IP; scoring models weight IP reputation heavily.

## Validation (mandatory)

- **Prove the gate is actually an LLM** before treating it as one: send a *deliberately wrong* semantic answer to an image question and check it's rejected; then a correct one. If both are accepted, it's presence-only (finding). If correct-only accepted, it's genuinely evaluated.
- **Prove origin responded** per `validation-and-false-positives.md` — a "passed" challenge must be followed by the real protected resource, not another challenge loop.
- If you bypassed via missing server-side validation / presence-only, document the exact request that succeeded with an empty/forged token.

## What NOT to do

- Don't brute-force open-ended LLM challenges — the answer space is huge and the judge may have rate limits.
- Don't claim "LLM gate bypass" from a cookie replay without confirming the gate ran at all.
- Don't confuse an LLM **gate** (this skill) with an LLM **application behind the gate** (use `hunt-llm-ai` / `ai-threat-testing` after you're in).

## Related

- `hunt-llm-ai` / `ai-threat-testing` — attacking the LLM application *behind* the gate.
- `captcha-solving-ladder.md` — if the AI gate is widgetized, the ladder's token/cookie steps apply.
- `validation-and-false-positives.md` — always confirm the bypass.