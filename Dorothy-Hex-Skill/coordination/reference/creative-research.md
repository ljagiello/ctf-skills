# Creative Research Methodology

Coordinator-only. Produces a RESEARCH_BRIEF (max 10 lines) for executor consumption.

## Triggers

Research when ANY condition met:
- **P4b reset** (mandatory — always research during reset)
- **goal_attempts ≥ 3** on any conceptual goal (Rule 6)
- **New technology** discovered not covered by mounted skill files
- **No hypothesis** at P2 Think phase — nothing obvious to try next
- **No progress for 1 batch** (single dry batch is enough; don't wait for two)
- **Novel error class** — an error message or behavior the chain hasn't seen before
- **Source code unreadable** for a critical surface (binary-only, obfuscated, paywalled)
- **Every executor returned negative** in the previous batch

Skip when: clear next experiment exists with concrete signal from the previous batch.

## Three Sources

### 1. Model Knowledge

Brainstorm from training data. Ask yourself:
- Known CVEs for the exact version/tech in scope?
- Uncommon attack chains? (e.g., SSRF -> cloud metadata -> RCE)
- Edge-case behaviors of this specific framework? (e.g., Spring4Shell, Rails param parsing, PHP type juggling)
- Techniques from CTF writeups, bug bounty disclosures for this tech?
- Protocol-level quirks? (HTTP/2 desync, WebSocket smuggling, DNS rebinding)
- Less obvious vectors? (race conditions, cache poisoning, mass assignment, TOCTOU)

Output: 3-5 bullet hypotheses with reasoning.

### 2. Skill Cross-Reference

Scan `reference/ATTACK_INDEX.md` for untried categories:
- Which attack types haven't been tested against this target?
- Do any skill reference files mention this tech stack specifically?
- Can two different attack types chain? (SSRF + deserialization, LFI + log poisoning, IDOR + mass assignment)
- Any skill recently updated with a technique matching this scenario?

### 3. Online Research 

Pick 2-3 of the most relevant search queries:
- `"{technology} {version}" vulnerability exploit 2025 2026`
- `"{technology}" bypass WAF filter evasion`
- `"{technology}" bug bounty writeup`
- `"{technology}" HackerOne disclosed report`
- `"{technology}" CVE proof of concept`
- `"{specific behavior observed}" exploit technique`
- `"{error message or header}" vulnerability`
- `"{technology}" pentest methodology site:book.hacktricks.xyz`

WebFetch rules:
- Only fetch pages that look like technique writeups, PoC descriptions, or detailed advisories
- Extract: technique name, payload pattern, conditions for exploitation, version affected
- Skip: marketing pages, generic overviews, tool download pages, paywalled content
- Max 2 fetches per research cycle
- If first 2 searches return noise, stop — don't burn the third

## Synthesis -> RESEARCH_BRIEF

Combine all three sources into max 10 lines. **At least one line must be tagged `[wildcard]`** — a hypothesis no mounted skill explicitly prescribes. If only skill-derived ideas surface, run one inverted query (e.g., `"{tech} unusual exploit"`, `"{tech} unexpected behavior"`, `"{tech} non-standard configuration"`) to seed it before finalizing the brief.

```
RESEARCH_BRIEF:
- [model] Hypothesis: <what + why it might work>
- [web] Technique: <name> -- <key payload/pattern> (src: <URL>)
- [skills] Untried: <attack category> -- relevant because <reason>
- [chain] Idea: <A -> B -> C> combining findings from above
- [web] CVE-YYYY-NNNNN: <version affected, exploit type> (src: <URL>)
- [wildcard] <hypothesis no skill prescribes> — <reasoning>
```

### What a wildcard looks like

| Setting | Skill-prescribed | [wildcard] |
|---------|------------------|------------|
| LFI confirmed | Try `php://filter` chain RCE | Inspect `/proc/self/environ` and `/proc/self/cmdline` for ENV-leaked secrets that weren't intended as the LFI target |
| Auth bypass dead-end | JWT alg-confusion, kid-injection | Cookie-name collision with proxy → upstream sees a different session token |
| RCE on box, no privesc | sudo / suid / capabilities | Examine running scheduled jobs that run as another user against attacker-writable paths |

Rules:
- Max 10 lines total.
- Each line actionable (not "maybe look into X").
- Include source tag so executor knows confidence level.
- Prioritize novel combinations over well-known techniques already tried.
- If online research found nothing useful, say so in 1 line and still produce a `[wildcard]` from model knowledge.
- Run `python3 tools/nvd-lookup.py <CVE-ID>` for any CVEs discovered.

## Budget

- Max 3 WebSearch calls per research cycle
- Max 2 WebFetch calls per research cycle
- Total research phase: < 2 minutes wall time
- If search returns noise after 2 queries, stop early and proceed with model knowledge

## Anti-Patterns

- Research only at trigger points — never every batch.
- Distill WebFetch results into the RESEARCH_BRIEF; never pass raw HTML to executors.
- Each hypothesis ≤ 2 lines; if it needs more, it's not a hypothesis yet.
- Skip topics already well-covered by mounted skill files — the brief is for what's missing.
- If no useful results in 2 minutes, finalize with model knowledge only — research must not block execution.
- Don't repeat research on the same technology in consecutive cycles. Log what you searched in the chain so the next P4b doesn't repeat it.
