# Slack Notifications Reference

Slack messages notify the team when a challenge starts or when it's solved. Both messages are sent to the configured Slack channel via `python3 .claude/tools/slack-send.py`.

## Challenge Started Notification

**When**: Immediately after machine/challenge is started on the platform.

**Format**:
```bash
printf ':crossed_swords: *Starting: %s*\n*Difficulty:* %s | *OS:* %s | *Target:* `%s`\n_Started at %s_' \
  "{name}" "{difficulty}" "{os}" "{ip}" "$(date -u '+%Y-%m-%d %H:%M UTC')" \
  | python3 tools/slack-send.py --token "{SLACK_BOT_TOKEN}" --channel "{HTB_SLACK_CHANNEL_ID}" -
```

**Example Output**:
```
⚔️ Starting: <ChallengeName>
Difficulty: Insane | OS: Windows | Target: `<TARGET_IP>`
Started at 2026-04-02 14:30 UTC
```

**Fields**:
- `{name}` — Challenge/machine name (from platform metadata)
- `{difficulty}` — Easy/Medium/Hard/Insane
- `{os}` — Linux/Windows/FreeBSD
- `{ip}` — Target IP address
- Timestamp — UTC timestamp in ISO format

---

## Challenge Completed Notification

**When**: After skill-update and stats collection.

**Format Structure**:
```
:trophy: PWNED — {name}
Difficulty/OS/Duration | Flag Status | Stats | How It Was Hacked | Key Techniques | Skills Updated
```

**Required Sections** (ALL must be present):

1. **Header**: `:trophy: PWNED — {challenge_name}` (use the challenge name from platform metadata; do not hardcode)
2. **Metadata**: `*Difficulty:* {level} | *OS:* {os} | *Time:* {duration}`
3. **Flag Status**: `:white_check_mark:` (user flag) `:white_check_mark:` (root flag) or `:x:` (failed)
4. **Stats** (from `stats.json`): experiments count, findings count, agents spawned
5. **How It Was Hacked** (narrative, 3-6 sentences, not bullet-pointed):
   - Connected story, explain the attack chain flow
   - Emphasize key turning points and techniques
   - NOT just a list of techniques
6. **Key Techniques** (bulleted list):
   - Primary techniques used (e.g., "SQL injection in login form")
   - Format: `- Technique name + brief context`
7. **Skills Updated** (from skill-update output):
   - Which skills were modified and why

**Example Output**:
```
:trophy: PWNED — <ChallengeName>
Difficulty: Insane | OS: Windows | Time: 4h 22m
Flags: :white_check_mark: :white_check_mark:

Experiments: 18 | Findings: 5 | Agents: 3

The attack started with NFS enumeration revealing a writable share. By spoofing GID, we mounted the share and discovered a Docker CA certificate. The CA was used to create a signing cert for malicious Docker daemon. Inside the container, we exploited gMSA to obtain credentials for a service account. Those credentials enabled LDAP poisoning through PWM, leading to domain admin privilege escalation.

Key Techniques:
- NFS GID spoofing to mount restricted shares
- Docker CA takeover via certificate manipulation
- gMSA LDAP querying for credential extraction
- PWM LDAP injection for privilege escalation

Skills Updated:
- authentication: Added gMSA extraction technique
- system: Added Docker CA exploitation pattern
- infrastructure: NFS GID spoofing documented
```

---

## Implementation Guidelines

### Slack Message Sending
```bash
# Send to Slack
python3 tools/slack-send.py \
  --token "{SLACK_BOT_TOKEN}" \
  --channel "{HTB_SLACK_CHANNEL_ID}" \
  "{message_text}"
```

### Error Handling
- If Slack send fails: **log error but continue** (do not block completion)
- Check `SLACK_BOT_TOKEN` and `HTB_SLACK_CHANNEL_ID` from `.env` via `env-reader.py`
- If either is `NOT_SET`, skip Slack notifications silently

### Completion Report Source
The **coordinator** sends this notification as Phase 3 of its mission (see `skills/coordination/reference/spawning-recipes.md`), after running `/skill-update`.
- Build notifications from `{OUTPUT_DIR}/reports/completion-report.md`
- Extract stats from `{OUTPUT_DIR}/stats.json`
- Include skill updates from the `/skill-update` output just completed

### Narrative Guidelines
- Write as **connected story**, not disconnected steps
- Emphasize **why** each technique worked in sequence
- Include **discoveries** that led to next phase
- Highlight **failures** that changed approach (if relevant)
- 3-6 sentences ideal length
