# Context Injection Rules

Defines what context each agent role receives when spawned. The goal is independent validation — validators must judge from raw evidence alone.

## Executor Context

Executors receive ALL of the following:
1. **Role prompt** — `skills/coordination/reference/executor-role.md`
2. **Chain context** — `{OUTPUT_DIR}/attack-chain.md` (full attack chain with theories, steps, results)
3. **Skill files** — 1-2 most relevant to the objective (e.g., `skills/injection/reference/sql-injection-quickstart.md`)
4. **PATT_URL** — specific payload URL for this mission (not full map)
5. **Objective** — clear description of what to test
6. **MISSION_ID** — unique identifier
7. **OUTPUT_DIR** — where to write results
8. **RESEARCH_BRIEF** (optional) — max 10 lines of synthesized research from coordinator's P2b phase. Only included when creative research was triggered.
9. **EXPERIMENT_ID** — the experiment row ID this executor must update on completion
10. **Experiments table** — `{OUTPUT_DIR}/experiments.md` (read for context, write to update own row)

## Validator Context — BLIND REVIEW

Validators receive ONLY:
1. **Role prompt** — `skills/coordination/reference/validator-role.md`
2. **Finding directory** — `{OUTPUT_DIR}/findings/finding-NNN/` (description.md, poc.py, poc_output.txt, evidence/)
3. **Target URL/IP** — so they can re-run the PoC
4. **OUTPUT_DIR** — `{OUTPUT_DIR}/artifacts/` for writing results

Validators MUST NOT receive:
- `attack-chain.md` (prevents confirmation bias)
- Coordinator reasoning or theories
- Other findings (prevents cross-contamination)
- Executor mission logs or objectives
- Skill files or PATT URLs (irrelevant to validation)
- RESEARCH_BRIEF (prevents confirmation bias, same as chain)

## Skill Mounts by Role

### Executor
Mount skills matching the attack technique:
- SQLi executor → `skills/injection/SKILL.md` + `reference/sql-injection-quickstart.md`
- XSS executor → `skills/client-side/SKILL.md` + `reference/xss-cheat-sheet.md`
- SSRF executor → `skills/server-side/SKILL.md` + `reference/ssrf-quickstart.md`

Pick the 1-2 most relevant. Do not mount everything.

### Validator
Mount ONLY:
- `reference/VALIDATION.md` (the 5-check criteria) — already embedded in validator-role.md
- The specific technique's cheat sheet IF needed to verify evidence format

Do NOT mount the full attack skill — it biases judgment toward finding what the skill describes.

### Research Brief Rules

- RESEARCH_BRIEF is coordinator-synthesized — executors never do their own WebSearch
- Max 10 lines: technique name, why it might work, key payload/pattern, source URL
- Omit when no research was done (most batches)
- Never pass raw WebFetch output to executors — always distill first

## Rationale

The validator performs a blind review. If they cannot independently verify a finding from raw evidence alone, the finding is not trustworthy. Leaking coordinator reasoning into the validator prompt defeats the purpose of independent validation.

This is analogous to double-blind peer review: the reviewer (validator) evaluates the work (finding) without knowing the author's intent (attack chain) or the editor's opinion (coordinator reasoning).
