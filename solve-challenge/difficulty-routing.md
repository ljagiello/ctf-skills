# Adaptive Difficulty and Model Routing

Use this reference when the `solve-challenge` skill needs to select, downgrade,
escalate, park, or stop a solver.

> **Note:** The `ctf_router.py` helper referenced below is a deterministic
> reference implementation of these rules. If it is not present, apply the
> scoring, stop-loss, and tier-gate rules manually — the methodology is the
> source of truth, not the script.

## Why routing is evidence-based

Organizer labels and points are weak priors. They can be misleading, calibrated
for a different audience, or attached to a challenge with an unintended
shortcut. Conversely, an easy label may hide a difficult implementation detail.

The router follows three rules:

1. Verified simplicity overrides labels immediately.
2. Hard tiers require observed structural complexity.
3. Failure, elapsed time, and repeated guesses never raise difficulty.

## State schema

Keep one small JSON file per active challenge:

```json
{
  "declared_difficulty": "hard",
  "triage_complete": true,
  "signals": ["common_encoding", "direct_flag_path", "single_artifact"],
  "current_tier": "triage",
  "missing_required_input": false,
  "exact_blocker": false,
  "new_evidence_since_escalation": false,
  "solved": false,
  "metrics": {
    "substantive_actions": 3,
    "elapsed_minutes": 2,
    "consecutive_no_progress": 0,
    "independent_attack_families": 1,
    "remaining_unknowns": 1
  }
}
```

Run the router from the repository root:

```bash
python3 solve-challenge/scripts/ctf_router.py challenge-state.json
```

The output contains:

- `difficulty`: working evidence-based class;
- `selected_tier`: tier the next solver is actually allowed to use;
- `model` and `reasoning`: exact Codex route;
- `action`: `triage`, `route`, `continue`, `downgrade`, `pivot`, `escalate`,
  `need_input`, `park`, `stop`, or `solved`;
- `budget`: limits for the selected tier;
- `reasons`: auditable signals behind the decision.

## Verified signal vocabulary

Add a signal only after an artifact, source path, command result, or service
response confirms it. Do not encode a hunch as a signal.

### Simplicity signals

| Signal | Use when verified |
| --- | --- |
| `common_encoding` | A standard reversible encoding is identified |
| `default_credential` | A challenge-provided/default credential works |
| `direct_flag_path` | The remaining steps to the flag are deterministic and short |
| `known_pattern` | A standard challenge pattern matches observed behavior |
| `metadata_leak` | Metadata directly exposes the needed value or next step |
| `single_artifact` | One small artifact contains the complete problem |
| `small_input` | The relevant input/search space is measured and small |
| `source_available` | Relevant implementation source is available |
| `verified_primitive` | A leak, oracle, read, write, key, or control primitive works |

`direct_flag_path` always routes to easy. A verified primitive combined with a
known cheap path also routes to easy, regardless of the organizer label.

### Complexity signals

| Signal | Use when verified |
| --- | --- |
| `anti_debug` | Anti-debugging changes the observed execution path |
| `custom_protocol` | A nonstandard protocol must be reconstructed |
| `exploit_development` | A real memory/control primitive must be weaponized |
| `full_mitigations` | Relevant binary protections are confirmed enabled |
| `large_artifact` | Measured size/structure materially increases analysis |
| `multiple_categories` | The solution demonstrably requires interacting domains |
| `multi_stage` | Several dependent unknown stages are confirmed |
| `obfuscation` | Obfuscation blocks the relevant logic path |
| `race_condition` | Success depends on a real timing/concurrency condition |
| `requires_external_correlation` | Several external facts must be triangulated |
| `custom_crypto` | A nonstandard construction requires analysis |
| `lattice_required` | A lattice formulation is justified and necessary |
| `kernel` | The challenge requires kernel-level reasoning/exploitation |
| `novel_primitive` | Known attack families do not cover the verified mechanism |

Do not add `multi_stage`, `custom_crypto`, or `novel_primitive` merely because
the story text sounds complex.

## Model ladder and budgets

| Tier | Model | Effort | Time | Actions |
| --- | --- | --- | --- | --- |
| Fast probe | `gpt-5.5` | medium | 4 min | 6 |
| Easy | `gpt-5.5` | medium | 6 min | 10 |
| Medium | `gpt-5.6-luna` | medium | 12 min | 20 |
| Hard | `gpt-5.6-luna` | high | 20 min | 30 |
| Very hard | `gpt-5.6-luna` | xhigh | 20 min | 25 |
| Extreme | `gpt-5.6-sol` | high | 30 min | 35 |

Stop at the first limit reached. A deterministic local job with a known bound
may finish, but do not start unrelated work while it runs.

Sol high is locked until a productive Luna xhigh pass has:

- tested at least two independent evidence-backed families;
- produced new verified evidence since the previous escalation; and
- reduced the problem to an exact blocker.

## Codex execution

When Codex supports model-specific subagents:

1. Keep the root agent as the lightweight orchestrator.
2. Spawn exactly one solver using the router's exact model and effort.
3. Give it the category skill, relevant files, case file, budget, and one
   precise objective.
4. Wait for it to finish or hit a stop condition.
5. Close or leave that solver idle before routing another tier.

Do not run several model tiers concurrently. A higher model is a deliberate
escalation on a precise blocker, not a second opinion on the entire challenge.

## Progress and stop-loss

Progress is one of:

- new verified fact;
- meaningful elimination of a plausible hypothesis;
- working exploit/crypto/forensic primitive;
- measured search-space reduction;
- reproducible flag candidate;
- exact blocker replacing a broad unknown.

The following are not progress:

- another explanation of the same output;
- changing payload punctuation without a mechanism;
- rerunning an unchanged command;
- trying an attack family unsupported by evidence;
- generating more possible flags from story themes.

After three consecutive no-progress actions:

- first family: perform one evidence-backed pivot;
- two families without new hard evidence: park;
- exact blocker plus new verified hard evidence: escalate one tier only;
- Sol after three families: stop and return `DEAD_END` with the exact blocker.

## Escalation packet

Before a model change, compress state to about 1,000 tokens, excluding paths
and tiny code snippets:

```text
CTF CASE FILE
Challenge/category:
Goal and exact flag format:
Attempts remaining:
Artifacts/targets:

VERIFIED FACTS
- fact -> evidence

ATTACKS TESTED
- hypothesis -> test -> result -> conclusion

WORKING PRIMITIVES
- primitive -> reproduction

REJECTED IDEAS
- idea -> why it must not be retried without new evidence

CURRENT HYPOTHESES
1. evidence, confidence, cheapest next test
2. evidence, confidence, cheapest next test

EXACT BLOCKER
- one precise statement

FILES AND SCRIPTS
- path -> purpose

NEXT SOLVER TASK
- one bounded objective
```

Never hand the next solver a raw repetitive conversation when this packet is
available.

## Submission governor

Represent a candidate as JSON:

```json
{
  "attempts_remaining": 8,
  "reproducible": true,
  "format_valid": true,
  "independent_checks": 1,
  "user_approved": false
}
```

Evaluate it with:

```bash
python3 solve-challenge/scripts/ctf_router.py --submission candidate.json
```

Rules:

- every candidate must be reproducible and format-valid;
- ten or fewer attempts require an independent consistency check;
- three or fewer attempts also require explicit user approval;
- a rejected flag becomes evidence and must be recorded exactly;
- never submit cosmetic permutations without format or derivation evidence.
