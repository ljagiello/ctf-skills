---
name: coordination
description: Pentest coordination — orchestrates executor and validator agents with context-controlled spawning. Entry point for all engagements.
---

# Coordination

Runs as a spawned subagent (one per target). Within its own context, the coordinator holds engagement state inline — it does not delegate its thinking to further sub-subagents. Thinks before every action.

The parent orchestrator (main session) **must not** execute this workflow inline. If you find yourself doing P1-P5 in the main session, you skipped the spawn step in `skills/hackthebox/SKILL.md` (or the relevant platform skill) and the bookkeeping discipline is silently disabled.

## Principle (Rule 0)

**Source code first.** Read all accessible source — application code, config, scripts, share contents — before any executor batch. Every answer is in the data you already have. Guessing without reading is the most common failure mode.

## Workflow

```
P0: Ingest scope
 ↓
P1: Recon + read source code → write attack-chain.md → run preflight-checklist
 ↓
┌→ P2: Think — read chain + experiments.md, write 3 hypotheses (≥1 [wildcard]), pick 1-2 to test
│  P2b: Research (conditional) — see reference/creative-research.md
│  P3: Execute — spawn 1-2 executors with CHAIN_CONTEXT [+ RESEARCH_BRIEF]
│  P4: Integrate — read results, update chain, revise theory
│      No progress 1 batch → consider P2b
│      goal_attempts ≥ 3 on any conceptual goal → P4b
│      Goal → P5
└─ loop (max 30 experiments; mandatory skeptic at experiments 5, 15, 25)

P4b: Reset — re-read all recon + source + chain. Creative Research (mandatory). Fresh theory.
P5: Validate + Report
```

### Steps

1. **Recon + Source Code** — read all accessible code (see `formats/reconnaissance.md`). Run pre-flight checklist (`reference/preflight-checklist.md`).
2. **Think** — write 3 hypotheses to `attack-chain.md`, ≥1 tagged `[wildcard]`. Pick 1-2 to spawn.
3. **Test** — 1-2 executors per batch, integrate before next.
4. **Validate** — finding-validator per finding + engagement-thoroughness validator at P5 (see `reference/validator-role.md`).
5. **Report** — validated findings in `{OUTPUT_DIR}/artifacts/validated/` → Transilience PDF via `formats/transilience-report-style/SKILL.md`.

## attack-chain.md

`{OUTPUT_DIR}/attack-chain.md`. Updated every batch. Sections: services, surface, theory (3 hypotheses + chosen), tested, next. Bullets, max 50 lines, prune old items to one-liners.

## Bookkeeping

experiments.md ledger, tools/ logs, EXPERIMENT_ID injection, conceptual-goal counting — see `reference/bookkeeping.md`.

## Creative Research (P2b)

Triggers: P4b reset (mandatory), goal_attempts ≥ 3 on any goal, novel error class, source code unreadable, every executor returned negative, no hypothesis at P2, no progress for 1 batch. See `reference/creative-research.md`. Most batches skip P2b.

## Spawning

See `reference/spawning-recipes.md` for copy-paste-ready spawn patterns per role. Context contracts in `reference/context-injection.md`. Role boundaries in `reference/role-matrix.md`.

## Roles

| Role | File | Context | When |
|------|------|---------|------|
| Executor (explore) | `reference/executor-role.md` | Full chain + skills | Recon / breadth |
| Executor (exploit) | `reference/executor-role.md` | Full chain + skills + scenarios | Confirmed theory |
| Skeptic | `reference/skeptic-role.md` | experiments.md + recon (no chain) | Mandatory at experiments 5, 15, 25 |
| Validator (finding) | `reference/validator-role.md` | Evidence only (blind) | One per finding |
| Validator (engagement) | `reference/validator-role.md` | OUTPUT_DIR only (blind) | At P5 |

## Rules

1. **Autonomous.** Coordinator MUST NOT call `AskUserQuestion`. If a credential is missing, run `python3 tools/env-reader.py`; if it returns NOT_SET, terminate with `status=BLOCKED` and emit a clear blocker. Asking is the parent orchestrator's job.
2. **Think before acting.** Write 3 hypotheses (≥1 wildcard) to attack-chain.md before every batch. Record rejected ones — they are the search tree.
3. **Max 1-2 executors per batch.** Recon can use more.
4. **Pass chain context + specific PATT_URL** to executors. Not the full PATT map.
5. **30-experiment cap.**
6. **goal_attempts ≥ 3 on a conceptual goal** → P4b reset. Count by *goal*, not literal technique string. Five PKINIT cert variants chasing "use this cert to authenticate" = five strikes against one goal. See `reference/bookkeeping.md` for the goal column.
7. **Mandatory skeptic** at experiments 5, 15, 25 (see `reference/skeptic-role.md`).
8. **All output to OUTPUT_DIR.**
9. **Sequential flag progression** in multi-flag engagements. User-foothold first; root path usually flows from there.
10. **No partial completion as a success state.** A multi-flag engagement is incomplete until every flag submits. `status=FAILED_partial` is a temporary marker, never a final outcome.
11. **Phase 3 (skill-update + Slack + queue) is parent-orchestrator only.** Coordinator emits PHASE3_SUMMARY and exits.
12. **Source for library internals.** Before writing Python against any library API (Impacket, ldap3, pyasn1), read the source. Prefer CLI tools (secretsdump.py, ticketer.py, getST.py).
13. **Background command discipline.** State the specific result a tunnel/relay/listener will produce before spawning.
14. **Report gate.** Validated findings exist → Transilience PDF report required. Read `formats/transilience-report-style/pentest-report.md`.
15. **Validation completeness.** After validators run, every validated finding has `evidence/validation/validation-summary.md`. Flag any without proof.

## Token Discipline

- Internal output (chain, logs, reports): bullets, not prose.
- Executor prompts: 1-2 relevant skill files + the specific PATT_URL.
- attack-chain.md max 50 lines; bookkeeping max 10% of mission tokens.
- User-facing output (reports, summaries): detailed.

## References

`reference/principles.md` · `reference/preflight-checklist.md` · `reference/role-matrix.md` · `reference/bookkeeping.md` · `reference/spawning-recipes.md` · `reference/context-injection.md` · `reference/creative-research.md` · `reference/executor-role.md` · `reference/skeptic-role.md` · `reference/validator-role.md` · `reference/VALIDATION.md` · `reference/ATTACK_INDEX.md` · `reference/OUTPUT_STRUCTURE.md` · `reference/GIT_CONVENTIONS.md` · `formats/INDEX.md`
