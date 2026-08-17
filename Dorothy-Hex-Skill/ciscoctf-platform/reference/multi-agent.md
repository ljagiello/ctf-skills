# Multi-agent Parallel Submission

Spawning multiple sub-agents to handle different flags simultaneously.

## When to use

- **Independent flags** — flags that don't depend on each other (common in practice tests)
- **Whois/DNS questions** — can be auto-answered via `auto` command
- **Batch == different machines** — each sub-agent has its own session/VM

## When NOT to use

- **Sequential flags** — where Q2 requires Q1 completion
- **Shared 5-attempt limit** — parallel submissions to the same flag waste attempts
- **Same session** — CiscoCTF uses per-account sessions; parallel curl with the same session causes race conditions

## Architecture

```
Orchestrator (this session)
├── agent-A: Q1 whois answer  (task: check + submit flag 1)
├── agent-B: Q3 whois answer  (task: check + submit flag 3)  
├── agent-C: Q4 DNS answer    (task: check + submit flag 4)
└── agent-D: Q5 whois answer  (task: check + submit flag 5)
```

## Recommended approach: sub-agent per account

Each sub-agent should have its OWN account (different session_id) to avoid session conflicts:

```bash
# Agent 1: account A
python3 session_manager.py save   # paste account A session
python3 session_manager.py auto <flag_uuid_1> <mission_uuid>

# Agent 2: account B (different terminal / machine)
python3 session_manager.py save   # paste account B session
python3 session_manager.py auto <flag_uuid_3> <mission_uuid>
```

## Single-account approach (careful!)

If using one account, serialize submissions with 3s gaps:

```python
# pseudo-code: sequential batch within one agent
for fuuid, answer in flags:
    subprocess.run(["python3", "session_manager.py", "submit", fuuid, answer, muid])
    time.sleep(3)  # avoid race + rate limit
```

## Sub-agent prompt template (for AI usage)

```
You are a CTF sub-agent working on CiscoCTF.
Session ID: <session_id_value>
Mission UUID: <mission_uuid>
Your flag UUID: <flag_uuid>
Question: <question text>

Steps:
1. If whois/DNS question, use `auto` command
2. Otherwise ask user for answer
3. Submit with `submit` command
4. Report result back
```

## Telegram coordination

When using multiple agents, all can log to the same Telegram chat:

```bash
# Each agent loads same session with Telegram configured
python3 session_manager.py tg-send "[Agent-A] Q1: SUCCESS +20pts"
python3 session_manager.py tg-send "[Agent-B] Q3: SUCCESS +20pts"
```
