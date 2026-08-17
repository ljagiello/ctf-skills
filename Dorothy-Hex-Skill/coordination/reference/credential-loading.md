# Credential Loading

Single canonical procedure for reading environment variables, credentials, API keys, tokens, and configuration values during an engagement.

## Rule

Always use `python3 tools/env-reader.py` to read any env var or credential. This is the only approved method.

```bash
python3 tools/env-reader.py VAR1 VAR2 VAR3
```

## Why

- `source .env` / `cat .env` / `echo $VAR` / `os.environ.get` / `dotenv.load()` from inside Bash all fail. Each `Bash` invocation is a fresh shell with no `.env` loaded.
- `env-reader.py` parses `.env` reliably via Python and exposes only the requested keys.
- Centralization makes it easy to audit what credentials a run needs.

## When

Before any tool invocation, scan, or API call that requires a credential. The SessionStart hook runs env-reader for the canonical credential set automatically; this rule covers ad-hoc reads inside a running engagement.

## Coordinator responsibility

The coordinator MUST NOT call `AskUserQuestion` for missing credentials. Workflow:

1. Run `python3 tools/env-reader.py <vars>`.
2. If a returned value is `NOT_SET`, terminate with `status=BLOCKED` and a clear `BLOCKED_REASON` naming the missing variable.
3. The parent orchestrator decides whether to ask the user. Coordinator does not.

## Executor responsibility

Same rule — when an executor needs a credential it doesn't have in its prompt, run env-reader. Don't `AskUserQuestion`. If env-reader returns `NOT_SET`, write the failure to the executor's `logs/mission-{ID}.md` and terminate the mission.

## Common variables

- Platform: `HTB_USER`, `HTB_PASS`, `HTB_TOKEN`, `HACKERONE_TOKEN`
- Notification: `SLACK_BOT_TOKEN`, `<SLACK_CHANNEL_ID>`
- AI: `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`
- Engagement: `FLAG` (when running benchmark suites that pass a flag via env)

## Anti-patterns

- Sourcing `.env` from inside a Bash command.
- Using `AskUserQuestion` from the coordinator before trying env-reader.
- Hard-coding credentials in skill files or prompts.
- Logging credential values to `tools/`, `experiments.md`, or `attack-chain.md`. Reference variables by name only.
