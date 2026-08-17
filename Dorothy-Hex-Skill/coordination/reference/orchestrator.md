# Orchestrator

The parent-orchestrator's job. Runs in the main conversation context. Owns the queue, credentials, OUTPUT_DIR creation, and Phase 3 (skill-update + Slack) for every coordinator that completes.

## Inputs

- Target list / scope CSV.
- User intent (HackerOne program, single target, lab track, …).
- Environment variables (loaded once via `tools/env-reader.py`).

## Pre-flight

1. **Credentials.** Run `python3 tools/env-reader.py <required-vars>`. If a required variable returns `NOT_SET`, this is the **only** layer that may `AskUserQuestion`. Coordinators must not.
2. **Platform-specific protocol** (when applicable). For HackTheBox: read `skills/hackthebox/SKILL.md` and follow its API + VPN setup steps. For HackerOne: read `skills/hackerone/SKILL.md` for scope-CSV parsing.
3. **OUTPUT_DIR.** Create the engagement directory tree per [output-discipline.md](output-discipline.md). One per target.

## Coordinator pool

- Default cap: **3 concurrent coordinators**.
- Strict 1:1 — one coordinator per target. Never share.
- Queue-based: spawn min(cap, total) at T0; each coordinator solves one target then exits; spawn the next from the queue when one completes.
- Each coordinator gets its own `OUTPUT_DIR`.

Spawn template:

```python
coordinator_role = Read("skills/coordination/SKILL.md")
Agent(
    name=f"coordinator-{target_tag}",
    description=f"Coordinator: {target_tag}",
    prompt=f"{coordinator_role}\n\nOUTPUT_DIR: {output_dir}\nTARGET: {target}\nSCOPE: {scope}\n",
    run_in_background=True,
)
```

## Phase 3 — runs after every coordinator completes

The coordinator does NOT run /skill-update or Slack. The orchestrator does, every time.

For each completed coordinator:

1. **Read** the coordinator's PHASE3_SUMMARY block from its return.
2. **Verify outputs** — `{OUTPUT_DIR}/reports/completion-report.md` and `{OUTPUT_DIR}/stats.json` exist.
3. **Run `/skill-update`** with the techniques + lessons from PHASE3_SUMMARY. The skill-update will reject any addition that re-introduces challenge-specific lore.
4. **Send Slack notification** if `SLACK_BOT_TOKEN` and the channel ID are both set:
   - Compose per platform-specific notification format if one applies.
   - Send via `python3 tools/slack-send.py`.
   - If either env var is `NOT_SET`, skip silently.
5. **Spawn next** target from queue (if any remain).

If a coordinator returns `status=BLOCKED` with no findings, still run Phase 3 — the lessons-learned have value.

If a coordinator crashes without emitting PHASE3_SUMMARY:
- Read whatever files it wrote (`recon/`, `attack-chain.md`, `experiments.md`, partial findings).
- If enough evidence exists to drive completion inline, do so from the orchestrator (the orchestrator's main context is governed by user-level instructions and authorization, separately from the agent's policy layer).
- Otherwise log a warning, skip skill-update / Slack for that target, do not block the queue.

## Resubmission protocol (platform-specific)

If the coordinator reports "submission blocked" but captured the flags: this is a transport failure, not engagement failure. Verify ownership via the platform's profile API; if the flag is unsubmitted, resubmit from the orchestrator with the appropriate retry headers (typical: HTTP/1.1 instead of HTTP/2, default User-Agent rather than custom). See [skills/hackthebox/SKILL.md](../../hackthebox/SKILL.md) for HTB-specific retry rules.

## Forbidden in the orchestrator

- Touching target tools directly during a coordinator's run (the coordinator owns that engagement's OUTPUT_DIR).
- Spawning a coordinator without a populated `OUTPUT_DIR`.
- Skipping Phase 3 because the coordinator "looked successful."
- Running coordinators sequentially when the cap permits parallel.

## Anti-Patterns

- Letting the coordinator call `/skill-update` to "save the orchestrator a step."
- Asking the user before trying `env-reader.py`.
- Running multiple coordinators against the same target.
- Skipping the queue and spawning all coordinators at once for "speed."
