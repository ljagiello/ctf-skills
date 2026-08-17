# Role Matrix

Single normative grid for every agent role. When a behavior is unclear, this table is authoritative — not the prose elsewhere.

| Role | Spawned by | When | Context received | Context withheld | Files written | Files forbidden | Exit criterion |
|------|-----------|------|------------------|------------------|---------------|-----------------|----------------|
| **Orchestrator** | User / harness | Engagement start | OUTPUT_DIR scope, target metadata, env vars (via env-reader) | n/a | OUTPUT_DIR root, queue state | n/a | All coordinators completed and Phase 3 (skill-update + Slack) run for each |
| **Coordinator** | Orchestrator | One per target | Scope, OUTPUT_DIR, target list/IDs, mounted skills (lazy) | env vars not set (orchestrator handles) | `attack-chain.md`, `experiments.md`, `findings/`, `artifacts/`, `tools/`, `reports/`, `PHASE3_SUMMARY` | `AskUserQuestion`, `/skill-update`, `/slack-send`, anything outside OUTPUT_DIR | PHASE3_SUMMARY emitted; coordinator exits |
| **Executor — explore** | Coordinator | P1 broad recon, or P3 wildcard | CHAIN_CONTEXT, OUTPUT_DIR, EXPERIMENT_ID, 1-2 skill files, OBJECTIVE | RESEARCH_BRIEF (not yet relevant), scenarios/* | `recon/`, `tools/`, `experiments.md` (own row only), `logs/mission-{ID}.md` | `findings/` (cannot claim), other agents' rows | Recon written + experiments row updated |
| **Executor — exploit** | Coordinator | P3 with confirmed theory | CHAIN_CONTEXT, OUTPUT_DIR, EXPERIMENT_ID, 1-2 skill files, relevant `scenarios/*.md`, PATT_URL, optional RESEARCH_BRIEF | Other findings, full PATT map | `findings/finding-NNN/`, `tools/`, `experiments.md` (own row), `logs/` | Other agents' rows, validators' artifacts | Finding written with reproduce-3x evidence, OR negative report with full escalation chain |
| **Skeptic** | Coordinator | Experiments 5, 15, 25 (mandatory); ad-hoc when coordinator stuck on one theory | `experiments.md`, `recon/` listing + key files, OBJECTIVE | `attack-chain.md`, coordinator reasoning, skill files, RESEARCH_BRIEF | `skeptic-brief-{N}.md` | `attack-chain.md`, `findings/`, `experiments.md` rows | SKEPTIC_BRIEF written with 2 counter-hypotheses |
| **Validator — finding** | Coordinator | One per finding at P5 | `finding_id`, FINDING_DIR, TARGET_URL, OUTPUT_DIR | `attack-chain.md`, other findings, coordinator reasoning, skill files (except VALIDATION.md), RESEARCH_BRIEF | `validated/{id}.json`, `false-positives/{id}.json`, `evidence/validation/` | Executor files (description.md, poc.py, poc_output.txt, evidence/raw-source.txt) | All 5 checks PASS or REJECT verdict written |
| **Validator — engagement** | Coordinator | Once at P5, after finding-validators | OUTPUT_DIR root listing only | `attack-chain.md`, finding internals, validator reasoning | `engagement-validation.json`, `engagement-validation-summary.md` | All other files in OUTPUT_DIR | All thoroughness checks evaluated; PASS/FAIL |

## Why context separation matters

Validators must not see the coordinator's theory — that defeats independent validation. The skeptic must not see the chain — that defeats anti-confirmation-bias. Explore executors get full chain because they need to know what's already tried; exploit executors additionally get scenarios because they need step-by-step recipes.

If a role's context contract is broken (e.g., a validator reads attack-chain.md), the validator's verdict is no longer trustworthy. Treat the contract as a hard boundary.

## Mounting skill files per role

Coordinator picks 1-2 from `skills/INDEX.md` matching the attack class. Pass those file paths in the spawn prompt as `SKILL_FILES`. Don't pass `SKILL.md` files generically — pass the specific reference file (`skills/injection/reference/sql-injection-quickstart.md` not `skills/injection/SKILL.md`).

For exploit executors only: also include the relevant `scenarios/*.md` if the technique has a documented scenario.

## Spawn templates

See `reference/spawning-recipes.md` for copy-paste-ready spawn patterns per role.
