# Spawning Recipes

Copy-paste-ready spawn patterns per role. Context contracts in [role-matrix.md](role-matrix.md). Boundaries (forbidden context per role) enforced by the contract.

## Common preamble (any spawn from coordinator)

```python
output_dir = "<OUTPUT_DIR>"
chain = Read(f"{output_dir}/attack-chain.md")
experiments = Read(f"{output_dir}/experiments.md")
```

## Coordinator (orchestrator → coordinator)

The orchestrator creates the engagement dir tree (no bookkeeping files), then spawns one coordinator subagent per target. The `FIRST_ACTION` block makes the bookkeeping bootstrap a precondition for any other tool call inside the subagent — the gate is in the prompt itself, not in a doc the agent might skim.

```python
coordinator_role = Read("skills/coordination/SKILL.md")
Agent(
    name=f"coordinator-{target_tag}",
    description=f"Coordinator: {target_tag}",
    prompt=f"""{coordinator_role}

OUTPUT_DIR: {output_dir}
TARGET: {target}
SCOPE: {scope}
SKILLS_HINT: {skills_hint or '<none>'}

FIRST_ACTION (before any other tool call):
  1. Write({output_dir}/attack-chain.md, "<skeleton per bookkeeping.md §attack-chain.md>")
  2. Write({output_dir}/experiments.md, "<header row per bookkeeping.md §experiments.md>")
  3. Then run preflight-checklist Phase 1 gate (see reference/preflight-checklist.md).
Bookkeeping files MUST exist before spawning any executor. The coordinator-flow-gate hook
will block downstream Bash/Edit/Write on the engagement dir until attack-chain.md exists.
""",
    run_in_background=True,
)
```

**Anti-pattern: running the coordinator workflow inline in the orchestrator session.** The bookkeeping discipline (goal_attempts counting, mandatory skeptic checkpoints, blind validators) requires the subagent boundary. If the parent session starts doing P1-P5 itself, the `coordinator-flow-gate` PreToolUse hook will block on the first Bash/Edit/Write targeting the engagement dir.

## Executor — explore (recon, no findings)

```python
executor_role = Read("skills/coordination/reference/executor-role.md")
skill_file   = Read("skills/<domain>/reference/<technique>-patterns.md")  # 1-2 max

Agent(description=f"Recon: {objective}", prompt=f"""{executor_role}

role: explore
MISSION_ID: m-{NNN}
EXPERIMENT_ID: E-{NNN}
OBJECTIVE: {objective}
OUTPUT_DIR: {output_dir}

CHAIN_CONTEXT:
{chain}

EXPERIMENTS:
{experiments}

SKILL_FILES:
{skill_file}
""", run_in_background=True)
```

Forbidden: writing to `findings/` (explore agents observe; they do not claim).

## Executor — exploit (confirmed theory → end-to-end)

```python
executor_role = Read("skills/coordination/reference/executor-role.md")
skill_file   = Read("skills/<domain>/reference/<technique>-patterns.md")
scenario     = Read("skills/<domain>/reference/scenarios/<category>/<technique>.md")
patt_url     = "<specific PATT URL>"

# Optional research brief (≤10 lines, ≥1 [wildcard])
research = "RESEARCH_BRIEF:\n- [model] ...\n- [web] ...\n- [wildcard] ..."

Agent(description=f"Exploit: {objective}", prompt=f"""{executor_role}

role: exploit
MISSION_ID: m-{NNN}
EXPERIMENT_ID: E-{NNN}
OBJECTIVE: {objective}
OUTPUT_DIR: {output_dir}

CHAIN_CONTEXT:
{chain}

EXPERIMENTS:
{experiments}

SKILL_FILES:
{skill_file}

SCENARIO:
{scenario}

PATT_URL: {patt_url}

{research if research else ''}
""", run_in_background=True)
```

## Skeptic (mandatory at experiments 5, 15, 25)

Blind to attack-chain. Argues against the dominant theory.

```python
skeptic_role  = Read("skills/coordination/reference/skeptic-role.md")
recon_listing = Bash(f"ls -la {output_dir}/recon/")

Agent(description=f"Skeptic: experiment {N}", prompt=f"""{skeptic_role}

OBJECTIVE: {objective}
OUTPUT_DIR: {output_dir}
EXPERIMENT_COUNT: {N}

EXPERIMENTS:
{experiments}

RECON_LISTING:
{recon_listing}
""", run_in_background=True)
```

Forbidden: reading `attack-chain.md`, skill files, RESEARCH_BRIEF.

## Validator — finding (one per finding, blind)

```python
validator_role = Read("skills/coordination/reference/validator-role.md")
validation_doc = Read("skills/coordination/reference/VALIDATION.md")

Agent(description=f"Validate finding {finding_id}", prompt=f"""{validator_role}

class: finding
finding_id: {finding_id}
FINDING_DIR: {output_dir}/findings/finding-{finding_id}/
TARGET_URL: {target_url}
OUTPUT_DIR: {output_dir}/artifacts

VALIDATION_PROCEDURE:
{validation_doc}
""", run_in_background=True)
```

Forbidden: attack-chain, other findings, executor logs, skill files (except VALIDATION.md), RESEARCH_BRIEF.

## Validator — engagement (once at P5, blind)

```python
validator_role = Read("skills/coordination/reference/validator-role.md")

Agent(description=f"Validate engagement thoroughness", prompt=f"""{validator_role}

class: engagement
OUTPUT_DIR: {output_dir}
""", run_in_background=True)
```

Forbidden: attack-chain, finding internals, validator-finding artifacts.

## Patterns

### Batch of 1-2 executors (depth-first cadence)

```python
ids = []
for mission in missions[:2]:
    a = Agent(prompt=..., run_in_background=True)
    ids.append(a)
# Wait for all → integrate → update chain → next batch.
```

### Validators in parallel (one per finding)

```python
finding_ids = [f for f in os.listdir(f"{output_dir}/findings/") if f.startswith("finding-")]
for fid in finding_ids:
    Agent(prompt=..., run_in_background=True)  # all parallel
# Wait → read artifacts/validated/ + artifacts/false-positives/.
```

### Engagement validator (sequential after finding-validators)

```python
# After all finding-validators returned:
Agent(prompt=engagement_validator_prompt, run_in_background=True)
```

## Anti-Patterns

- Mounting `SKILL.md` files into executor prompts. Pass the specific reference / scenario file, not the navigation file.
- Mounting > 2 skill files into one executor.
- Letting a validator see `attack-chain.md` (breaks blind contract).
- Letting a skeptic see `attack-chain.md` (breaks anti-bias contract).
- Spawning > 2 executors in one batch (recon excepted).
- Spawning a `validator-finding` without a corresponding `findings/finding-{id}/`.
