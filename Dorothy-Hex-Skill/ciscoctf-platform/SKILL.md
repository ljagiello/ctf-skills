---
name: ciscoctf-platform
description: CiscoCTF (netacad.ciscoctf.io) platform automation — session-based auth, mission/flag fetching, answer submission, leaderboard, user data. Use when the target platform is netacad.ciscoctf.io or any CiscoCTF instance. The user provides a session_id; all operations use curl with that session.
---

# CiscoCTF Platform

Cookie-based automation for netacad.ciscoctf.io. No password/login needed — user provides `session_id` cookie value.

## Quickstart

User gives you `session_id` from their browser (F12 → Application → Cookies → netacad.ciscoctf.io → session_id). Store it:

```bash
SID='session_id="<value>"'
COOKIE="csessxptim=<ts>; _xsrf=<token>; ${SID}"
```

Get a fresh `_xsrf` from any page:

```bash
curl -s -H "Cookie: ${COOKIE}" 'https://netacad.ciscoctf.io/%F0%9F%8F%86%E2%9A%A1%F0%9F%9A%A9/user/event/select' | grep -oP 'name="_xsrf" value="\K[^"]+'
```

## Generic workflow (works with ANY event)

```bash
# Save session ONCE — paste session_id from F12 → Cookies
python3 reference/session_manager.py save

# 1. List available events
python3 reference/session_manager.py events

# 2. Select your event
python3 reference/session_manager.py select <EVENT_CODE>

# 3. See what missions exist
python3 reference/session_manager.py missions

# 4. Check flag status
python3 reference/session_manager.py status <MISSION_UUID>

# 5. Submit flag answer
python3 reference/session_manager.py submit <FLAG_UUID> <ANSWER> <MISSION_UUID>

# 6. Check your own score + rank + per-flag status
python3 reference/session_manager.py myscore <EVENT_CODE>

# 7. Report card (per-flag capture status)
python3 reference/session_manager.py myreport <EVENT_CODE> <MISSION_UUID>

# 8. Leaderboard
python3 reference/session_manager.py lb <EVENT_CODE>
```

Session saved to `~/.ciscoctf_config.json` — reuse across terminals, machines, any event.

## Base URL

Always encode emoji path: `%F0%9F%8F%86%E2%9A%A1%F0%9F%9A%A9`

Base: `https://netacad.ciscoctf.io/%F0%9F%8F%86%E2%9A%A1%F0%9F%9A%A9`

## Smart submission — auto vs manual

`session_manager.py submit` uses attempt-based logic:

| Remaining attempts | Behavior |
|-|-|
| **≥ 3** (used 0-2) | Auto-submit — shows question + answer, then submits with 2s cooldown |
| **≤ 2** (used 3-4) | Ask confirmation — shows question, warns "only X left", requires `y` to proceed |
| **0** (used 5) | Blocked — cannot submit, exits with error |

Plus: **2-second cooldown** between submissions to avoid spam detection.

## Key rules

- **Session_id is HttpOnly** — user must paste from DevTools Application tab, not `document.cookie`
- **_xsrf cookie + form field must match** — always extract fresh _xsrf from page, use it as cookie AND in POST body
- **Emoji path must be URL-encoded** in curl (above encoding works)
- **One session per account** — curl and browser can't be logged into the same account simultaneously
- **5 attempts max per flag** — verify answer before submitting
- **Referer header** required for POST submissions: set to the missions page URL

## Reference files

- [authentication.md](reference/authentication.md) — Session cookie extraction, _xsrf management, cookie file creation
- [missions.md](reference/missions.md) — Event listing, joining events, viewing mission flags
- [submission.md](reference/submission.md) — Flag submission, answer verification, attempt tracking
- [scoreboard.md](reference/scoreboard.md) — Leaderboard, team view, report card, user data
- [commands.md](reference/commands.md) — All curl commands in one reference sheet
- [session_manager.py](reference/session_manager.py) — Python helper: paste session once, use forever
