---
name: hackthebox
description: HackTheBox platform operations and automations to solve challenges, machines and capture the flags hacking competitions
context: fork
---

## Workflow
- [workflow.md](reference/workflow.md) — Complete workflow with commands. Read this for each step

### Steps
1. Get Credentials — `python3 .claude/tools/env-reader.py HTB_USER HTB_PASS HTB_TOKEN ANTHROPIC_API_KEY SLACK_BOT_TOKEN HTB_SLACK_CHANNEL_ID`
2. Only for "Machine" kind of competition -> Verify vpn is running, otherwise download the vpn file from the platform and instruct the user on how to enable it
3. Generate output dirs — `mkdir -p YYMMDD_<name>/{recon,findings,logs,artifacts,tools,reports}` for each challenge. **Do not seed `attack-chain.md` or `experiments.md` from the orchestrator** — those are the coordinator subagent's first action (see `skills/coordination/reference/spawning-recipes.md`).
4. To achieve the tasks given by the user, when possible use the HTB_TOKEN, otherwise login to the platform using playwright at https://account.hackthebox.com/login and fill the login form with the HTB_USER and HTB_PASS
5. If necessary, start the machines
6. If necessary, check network connectivity to the machines
7. Spawn coordinator subagent per target — `Agent(name="coordinator-{tag}", run_in_background=True, ...)` per `spawning-recipes.md`. **Never run the P0-P6 coordinator workflow inline in the orchestrator session** — the bookkeeping discipline (attack-chain.md, experiments.md, goal_attempts counting, mandatory skeptic at experiments 5/15/25) requires the subagent boundary. Max N concurrent agents, queue-based spawning.
8. Post-solve Phase 3 — parent orchestrator (not coordinator) always runs `/skill-update` + Slack after each coordinator returns its PHASE3_SUMMARY (see workflow.md step 8)

## References
- [workflow.md](reference/workflow.md) — Workflow overview with credentials, VPN, setup, and coordinator spawn
- [spawning-recipes.md](../coordination/reference/spawning-recipes.md) — Coordinator agent spawn prompt templates (exploitation, flag submission, completion report, stats)
- [completion-report-schema.md](../../formats/htb-completion-report.md) — Challenge completion report structure & template
- [slack-notifications.md](reference/slack-notifications.md) — Slack completion notification format & examples
- [platform-navigation.md](reference/platform-navigation.md) — Platform site navigation guide
- [vpn-pool-routing.md](reference/vpn-pool-routing.md) — VPN pool isolation. Pre-flight check before spawning any machine (release_arena vs dedivip_lab vs others)
- [vpn-setup.md](reference/vpn-setup.md) — VPN connectivity troubleshooting
- [anti-bot-bypass.md](../reconnaissance/reference/anti-bot-bypass.md) — Cloudflare/Turnstile detection evasion
