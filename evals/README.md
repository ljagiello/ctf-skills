# Skill evals (promptfoo)

Behavioral tests for the skills in this repo, run with [promptfoo](https://www.promptfoo.dev/) and the [Claude Agent SDK provider](https://www.promptfoo.dev/docs/providers/claude-agent-sdk/). Where `tests/` checks the skill files themselves, these evals check what Claude actually does with them.

| Suite | Config | Question it answers |
|-------|--------|---------------------|
| Routing | `promptfooconfig.routing.yaml` + `cases/routing.yaml` | Given a challenge description, does Claude load the right `ctf-*` skill and avoid the wrong ones? |
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
| `npm run validate` | Schema-check both configs (free, no model calls) |
| `npm run eval:smoke` | Routing cases tagged `tier: smoke` |
| `npm run eval:routing` | All routing cases (about $0.12 and 15 s per case) |
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

- **Workspaces.** `lib/hooks.js` runs before every eval and copies each top-level skill directory into `.work/` (gitignored) under `.claude/skills/<name>/`. That is the layout `npx skills add` installs, so skill names stay unnamespaced. The copy is made from the working tree, so uncommitted edits are tested too.
- **Provider.** `anthropic:claude-agent-sdk` with `setting_sources: ['project']` and `skills: all`. It discovers the staged skills and adds the `Skill` tool.
- **Routing suite.** The agent gets read-only tools and is told the challenge files are absent. It loads the skills it would use, then outlines a plan. Three metrics:
  - `expected-skill`: the `skill-used` assertion on `vars.expected`.
  - `no-wrong-skill`: none of `vars.forbidden` was loaded.
  - `routed-directly`: the expected skill came first, rather than after the `solve-challenge` dispatcher. Tracked only; it never fails a case.
- **Solve suite.**
  - **Providers.** Each case runs on two providers that are identical except for skills: `with-skills` and `no-skills`. Both get Bash/Write/Edit, no web tools, and a fresh copy of the fixture per run (`copy_working_dir: copy`).
  - **`solved`.** Checks the final answer for a flag whose SHA-256 matches `vars.flag_sha256`. Plaintext flags are never committed.
  - **`expected-skill`.** Reports whether the with-skills run loaded the skill the fixture targets. Tracked only; it never fails a case.

Assertion helpers live in `lib/assertions.js`. They read `metadata.skillCalls`, which promptfoo builds from the agent's `Skill` tool calls.

## Adding cases

**Routing:** append to `cases/routing.yaml` with `description`, `vars.task`, `vars.expected` and `vars.forbidden`. Tag cheap, high-signal cases with `metadata.tier: smoke`. `tests/test_eval_coverage.py` fails if any skill has no routing case, so a new skill needs at least one.

**Solve:**

1. Put the challenge files in `fixtures/<name>/`. Do not include the flag; the coverage test rejects any fixture containing `flag{`.
2. Solve it yourself and hash the flag: `printf '%s' 'flag{...}' | shasum -a 256`.
3. Add a case to `cases/solve.yaml` with `fixture`, `name`, `brief`, `expected` and `flag_sha256`.

Keep fixtures small and offline (Python stdlib where possible). The agent runs on your machine, or the CI runner, with whatever tools are installed there.

The three starter fixtures are deliberately easy. They prove the pipeline works end to end, and current models solve them in a few turns with or without skills. To measure what the skills add, write fixtures that hinge on techniques the skills document and that a bare model tends to miss, then compare `solved` across providers with `--repeat 3` or more. A single run says little about a nondeterministic agent.

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
