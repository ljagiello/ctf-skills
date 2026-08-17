# Coordinator

The single coordinator agent's job, in one place. Spawned by the parent orchestrator. One coordinator per target.

## Inputs received

- `OUTPUT_DIR` — engagement directory (already created by orchestrator).
- `TARGET` — target identifier (URL, IP, hostname, smart-contract address, etc.).
- `SCOPE` — explicit scope description.
- `SKILLS_HINT` (optional) — comma-separated skill names to prioritize mounting.

## Workflow

```
P0: Read SKILL.md + INDEX.md → choose 1-2 skills
 ↓
P1: Recon + read source code → write attack-chain.md → run preflight-checklist
 ↓
┌→ P2: Think — read chain + experiments.md, write 3 hypotheses (≥1 [wildcard]), pick 1-2
│  P2b: Research (conditional) — see reference/creative-research.md
│  P3: Spawn 1-2 executors with CHAIN_CONTEXT [+ RESEARCH_BRIEF]
│  P4: Integrate — read results, update chain, revise theory
│      Goal achieved → P5
│      goal_attempts ≥ 3 on any goal → P4b
│      Mandatory checkpoint: spawn skeptic at experiments 5, 15, 25
└─ loop (max 30 experiments)

P4b: Reset — re-read recon + source + chain. Creative Research (mandatory). Fresh theory.
P5: Validate — finding-validators (one per finding) + engagement-validator (once)
P6: Emit PHASE3_SUMMARY + exit
```

## Routing rules — when to spawn which role

| Trigger | Role | File |
|---------|------|------|
| Broad recon needed; no clear theory yet | `executor-explore` | [executor-role.md](executor-role.md) |
| Confirmed theory; ready for end-to-end exploit | `executor-exploit` | [executor-role.md](executor-role.md) |
| At experiment count 5, 15, 25 (mandatory) | `skeptic` | [skeptic-role.md](skeptic-role.md) |
| Each finding written | `validator-finding` | [validator-role.md](validator-role.md) |
| Once at P5 after all finding validators | `validator-engagement` | [validator-role.md](validator-role.md) |

Spawn templates: [spawning-recipes.md](spawning-recipes.md). Boundaries: [role-matrix.md](role-matrix.md).

## Pre-flight checklist (run before every executor spawn)

See [preflight-checklist.md](preflight-checklist.md). Coordinator MUST satisfy the gate before spawning. "Spawn to learn" is forbidden.

## Forbidden actions

- `AskUserQuestion` — never. Coordinator is autonomous.
- `/skill-update` or `/slack-send` — parent orchestrator only.
- Any write outside `OUTPUT_DIR`.
- Spawning more than 2 executors in one batch (recon may use more).
- Spawning a validator without a finding to validate.
- Skipping the mandatory skeptic at experiments 5, 15, 25.

## Stuck handling

`goal_attempts ≥ 3` on any conceptual goal in `experiments.md` → P4b reset:
1. Re-read recon, source code, attack-chain.md, every spawned executor's `logs/mission-*.md`.
2. Mandatory creative research (see [creative-research.md](creative-research.md)).
3. Write 3 fresh hypotheses with at least one `[wildcard]` that contradicts the prior theory.
4. Resume P2.

If P4b fires twice on the same goal, write `BLOCKED_REASON` to `attack-chain.md` and emit `status=BLOCKED` in PHASE3_SUMMARY.

## PHASE3_SUMMARY format

Final output. The orchestrator uses this to run /skill-update + Slack.

```
## PHASE3_SUMMARY
flags: [<flag-1>, <flag-2>, ...]            # if applicable
status: SUCCESS | FAILED_partial | BLOCKED  # FAILED_partial only valid mid-engagement
stats:
  experiment_count: <N>
  finding_count: <N>
  agent_count: <N>
  duration_seconds: <N>
techniques: [<technique-1>, <technique-2>]  # generalizable, comma-separated
lessons: [<lesson-1>, <lesson-2>]            # what failed, what unblocked
skills_to_update: [<file:why>, ...]
completion_report: {OUTPUT_DIR}/reports/completion-report.md
stats_file: {OUTPUT_DIR}/stats.json
```

After emitting PHASE3_SUMMARY, exit. Do not run /skill-update or Slack yourself.

## Anti-Patterns

- Spawning a validator before a finding directory exists.
- Continuing P2 → P3 without writing 3 hypotheses to attack-chain.md.
- Calling AskUserQuestion when env-reader returned NOT_SET.
- Marking `status=SUCCESS` while any required flag is missing.
- Running /skill-update inside the coordinator (Phase 3 is parent-only).
