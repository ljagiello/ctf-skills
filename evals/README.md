# Skill evals (promptfoo)

Behavioral tests for the skills in this repo, run with [promptfoo](https://www.promptfoo.dev/) and the [Claude Agent SDK provider](https://www.promptfoo.dev/docs/providers/claude-agent-sdk/). Where `tests/` checks the skill files themselves, these evals check what Claude actually does with them.

| Suite | Config | Question it answers |
|-------|--------|---------------------|
| Routing | `promptfooconfig.routing.yaml` + `cases/routing.yaml` | Given a challenge description, does Claude load the right `ctf-*` skill and avoid the wrong ones? |
| Rules | `promptfooconfig.rules.yaml` + `cases/rules.yaml` + `fixtures/rules/` | Once a skill is loaded, does Claude actually follow the specific rules written into it? |
| Solve | `promptfooconfig.solve.yaml` + `cases/solve.yaml` + `fixtures/` | Can Claude recover the flag from small offline challenges, with skills vs. without? |

## Quick start

Requires Node.js 22.22+ and one of:

- `ANTHROPIC_API_KEY` in the environment (used in CI), or
- a local Claude Code login (`claude /login`). The configs set `apiKeyRequired: false`, so promptfoo falls back to it and usage counts against your Claude plan.

```bash
cd evals
npm ci
npm run eval:smoke      # 11 routing cases, about $1.50 and a minute
npm run view            # browse results in the promptfoo web UI
```

| Command | What it runs |
|---------|--------------|
| `npm run validate` | Schema-check all three configs (free, no model calls) |
| `npm run eval:smoke` | Routing cases tagged `tier: smoke` |
| `npm run eval:routing` | All routing cases (about $0.12 and 15 s per case) |
| `npm run eval:rules` | All rule-following cases (seconds to ~2 min and well under $1 per case) |
| `npm run eval:solve` | Every fixture, with and without skills (minutes and dollars per case) |
| `npm run summary` | Markdown pass/metric/cost table from `out/*.json` |
| `npm run view` | promptfoo web viewer |

Extra promptfoo flags go after `--`:

```bash
npm run eval:routing -- --filter-pattern 'pwn'          # match case descriptions
npm run eval:routing -- --filter-metadata category=web  # match case metadata
npm run eval:routing -- --repeat 5                      # measure flakiness
npm run eval:solve -- --filter-providers with-skills    # skip the baseline
```

Results go to `out/` (gitignored): JSON for scripts, HTML for sharing.

## How it works

- **Workspaces.** `lib/hooks.js` runs before every eval and stages each top-level skill directory into `.work/` (gitignored) under `.claude/skills/<name>/` — the layout `npx skills add` installs, so skill names stay unnamespaced. Routing/solve **copy** the skills; the **rules** suite **symlinks** them straight to the live source folders and runs with `copy_working_dir: false`, so a rules case always reads the skill files as they are on disk right now (never a stale snapshot), including uncommitted edits.
- **Provider.** `anthropic:claude-agent-sdk` with `setting_sources: ['project']` and `skills: all`. It discovers the staged skills and adds the `Skill` tool.
- **Routing suite.** The agent gets read-only tools and is told the challenge files are absent. It loads the skills it would use, then outlines a plan. Three metrics:
  - `expected-skill`: the `skill-used` assertion on `vars.expected`.
  - `no-wrong-skill`: none of `vars.forbidden` was loaded.
  - `routed-directly`: the expected skill came first, rather than after the `solve-challenge` dispatcher. Tracked only; it never fails a case.
- **Rules suite.** See [below](#rules-suite).
- **Solve suite.**
  - **Providers.** Each case runs on two providers that are identical except for skills: `with-skills` and `no-skills`. Both get Bash/Write/Edit, no web tools, and a fresh copy of the fixture per run (`copy_working_dir: copy`).
  - **`solved`.** Checks the final answer for a flag whose SHA-256 matches `vars.flag_sha256`. Plaintext flags are never committed.
  - **`expected-skill`.** Reports whether the with-skills run loaded the skill the fixture targets. Tracked only; it never fails a case.

Assertion helpers live in `lib/assertions.js`. They read `metadata.skillCalls` and `metadata.toolCalls`, which promptfoo builds from the agent's tool calls.

## Rules suite

Routing checks whether the right skill gets loaded. This suite checks whether, once loaded, Claude actually follows the specific rules written into that skill — not just its one-line frontmatter description. Each case in `cases/rules.yaml` targets one rule quoted directly from a `SKILL.md`, as a pair:

- a **positive** case, where the rule should fire or be followed, and
- a **negative or trap** case — either a contrasting scenario where the rule correctly stays quiet, or an adversarial prompt that pressures the agent to break the rule anyway.

| Rule (source) | Positive case | Negative/trap case | How it's checked |
|---|---|---|---|
| ctf-pwn: escalate to `ctf-reverse` when the binary isn't understood yet (`ctf-pwn/SKILL.md:83`) | Stripped, anti-debugged binary, no known bug | Vulnerability and binary already fully characterized | `recommendsCtfReverse` / `doesNotRecommendCtfReverse` — credits a real `Skill` call like `skill-used` would, but also accepts clearly-stated text reasoning (these cases give no files to act on, so a correct agent sometimes explains its choice instead of pressing the tool for a hypothetical) |
| ctf-web: read the HTML, inline scripts, and bundled JS before guessing the API surface (`ctf-web/SKILL.md:169`) | Front-end bundle hides the flag in `app.js` | Pressured to skip the JS and guess endpoints | `flagMatches` (the flag is reachable only by reading the bundle) |
| ctf-pwn: check protections (`checksec`) before writing exploit code (`ctf-pwn/SKILL.md:145-149`) | Plain request to start exploiting a binary | Prompt explicitly says to skip recon and "just write the exploit now" | `checksecBeforeExploit` (orders `toolCalls` by index) |
| solve-challenge: validate flag candidates, don't report metadata noise or an obvious decoy (`solve-challenge/SKILL.md:192-195`) | A stale, unlabeled flag-shaped string sits in a build log; the real flag needs one small decode step | Same mechanism, no competing string (control: confirms a pass isn't just luck) | `flagMatches` (SHA-256 of the final answer) |
| ctf-reverse: never pipe triage output through `head` on the first pass (`ctf-reverse/SKILL.md:113-127`) | XOR-encoded-flag ELF, string buried past `head -30` | Pressured to "just run `strings chall \| head -30`" | `noHeadTruncation` (regex over Bash tool calls: `strings/objdump/… \| head`) |
| ctf-forensics: reimplement a VBA macro in Python, never run it (`ctf-forensics/SKILL.md:336`) | Spreadsheet cells + macro that decodes them | Pressured to "just run the macro with cscript/LibreOffice" | `noMacroExecution` + `flagMatches` |
| ctf-osint: never trust port numbers alone — always fingerprint the service (`ctf-osint/SKILL.md:182`) | Service on port 22, "don't trust appearances" | Told "port 22 is obviously SSH" | `fingerprintsBanner` (text reasoning over the final answer) |
| ctf-crypto: probe degenerate generator values first in DH/X25519 (`ctf-crypto/SKILL.md:213-216`) | DH service accepts unvalidated `g`/`A` | Pressured to skip to Pohlig-Hellman/BSGS | `probesTrivialValues` (text reasoning over the final answer) |

This suite covers 8 rules across `solve-challenge`, `ctf-web`, `ctf-pwn`, `ctf-reverse`, `ctf-forensics`, `ctf-osint`, and `ctf-crypto` — the skills with the most explicit, mechanically-checkable "always/never/do this before that" language, picked over the broader catalog of techniques. Extending it to another skill means finding a rule with the same property (a concrete, falsifiable behavior, not just "use technique X for problem shape Y") and writing a case the same way. Cases that need the model to actually load a skill that it would otherwise not volunteer (a simple RE/forensics/OSINT/crypto task it can reason through from training) both instruct loading and assert `skill-used`, so the suite measures a *loaded* skill's rule-following, not the bare model. The original ctf-web rule (login brute-force) was retired: the model's safety system refuses credential-attack guidance, making it untestable.

**Known flake / concurrency.** The rules suite runs serialized (`maxConcurrency: 1`): `stageRules` captures the shared provider config at `beforeAll` and rewrites its `working_dir` per test at `beforeEach`, which is a process-global mutation and would race across concurrent cases. (Routing/solve still use `copy_working_dir: copy`; each copy call makes its own ephemeral copy of a case's source fixture, but two calls copying the *same* source directory at the same time have reproducibly left one of them empty -- seen whenever two cases, or `--repeat`'s multiple runs of one case, shared a fixture directory under enough concurrency. The fix there is to never share a source directory between cases (`pwn-checksec-order-positive` / `-negative` are identical content in two directories for exactly this reason) and to keep `maxConcurrency` low (2). That doesn't help `--repeat N > 1` on a single case, which still copies the same source N times; if a repeat run errors or fails with an empty-looking workspace, re-run it with `-j 1` before assuming the skill (or the assertion) is at fault.)

Not every real rule in these skills fits a cheap tool-call check. `solve-challenge/difficulty-routing.md` in particular has a dense, genuinely interesting rule set (evidence-gated complexity signals, a stop-loss policy, an escalation-packet format) that's fundamentally about the agent's *reasoning*, not which tools it calls — testing it well would need `llm-rubric`-style grading of the agent's stated justification, which is a different (and pricier) verification style than the rest of this suite. Deliberately left out of this pilot; worth a dedicated follow-up suite rather than forcing it into this one.

## Adding cases

**Routing:** append to `cases/routing.yaml` with `description`, `vars.task`, `vars.expected` and `vars.forbidden`. Tag cheap, high-signal cases with `metadata.tier: smoke`. `tests/test_eval_coverage.py` fails if any skill has no routing case, so a new skill needs at least one.

**Rules:**

1. Find a concrete, falsifiable "always/never/do X before Y" statement in a `SKILL.md` or one of its technique files — quote it verbatim in a comment block in `cases/rules.yaml`.
2. Decide what a violation would look like in terms of tool calls or the final answer (a skill (not) being loaded, a command (not) run before another, specific content (not) appearing) — that's your assertion.
3. If the case needs files, add a small one under `fixtures/rules/<name>/` (staged with the skills by `lib/hooks.js:stageRules`); otherwise set `vars.workspace: text` to reuse the skills-only workspace.
4. Add a positive case and a negative/trap case, both tagged `metadata: { rule: <id>, polarity: positive|negative }` — `tests/test_eval_coverage.py` fails if a rule has only one polarity.

**Solve:**

1. Put the challenge files in `fixtures/<name>/`. Do not include the flag; the coverage test rejects any fixture containing `flag{`.
2. Solve it yourself and hash the flag: `printf '%s' 'flag{...}' | shasum -a 256`.
3. Add a case to `cases/solve.yaml` with `fixture`, `name`, `brief`, `expected` and `flag_sha256`.

Keep fixtures small and offline (Python stdlib where possible). The agent runs on your machine, or the CI runner, with whatever tools are installed there. `evals/fixtures-src/` holds non-staged source/build notes for fixtures that are a compiled artifact (currently just the pwn-checksec-order toy binary) — anything placed there is for maintainers only and is never copied into an agent's workspace.

The three starter solve fixtures are deliberately easy. They prove the pipeline works end to end, and current models solve them in a few turns with or without skills. To measure what the skills add, write fixtures that hinge on techniques the skills document and that a bare model tends to miss, then compare `solved` across providers with `--repeat 3` or more. A single run says little about a nondeterministic agent.

## Comparing skill versions

To measure the effect of an edit, run the same suite on both sides and compare in `npm run view`:

```bash
git switch main && npm run eval:routing -- --description main
git switch my-branch && npm run eval:routing -- --description my-branch
```

To compare models, duplicate a provider in the config with a different `model` and `label`.

## Safety and cost

- **The solve suite runs an agent with an unrestricted shell.** Its workspace is a temp copy, but that is not a sandbox. Run it only against skills and fixtures you trust.
- **CI runs need a trusted PR.** The `run-evals` label (below) exposes `ANTHROPIC_API_KEY` to that agent, so only apply it to PRs you trust.
- **Cost caps.** `max_turns` and `max_budget_usd` cap each run. A run that hits a cap shows as an error, not a failure.
- **Caching.** promptfoo cannot cache Agent SDK calls across runs, so the scripts pass `--no-cache`.

## CI

`.github/workflows/skill-evals.yml`:

- **Every PR touching `SKILL.md` or `evals/`:** validates the configs. This is free.
- **Evals:** run only on manual dispatch (pick the suite and repeat count) or on PRs labeled `run-evals`. They need the `ANTHROPIC_API_KEY` repository secret.
- **Gating:** routing fails the job below a 90% pass rate. The solve suite never fails the job, because it is a comparison.
- **Results:** the job summary shows the metric table, and the full JSON/HTML results are uploaded as an artifact.
