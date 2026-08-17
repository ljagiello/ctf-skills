# Flag Submission

## Endpoint

```
POST /%F0%9F%8F%86%E2%9A%A1%F0%9F%9A%A9/user/missions/capture
Content-Type: application/x-www-form-urlencoded
```

Fields:
- `_xsrf` — from the page (must match cookie)
- `uuid` — flag UUID (NOT mission UUID)
- `token` — the flag/answer (max 256 chars)

## Single flag submission

```bash
curl -s -H "Cookie: ${COOKIE}" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -H "Referer: ${REFERER}" \
  -d "_xsrf=${XSRF}" \
  -d 'uuid=<FLAG_UUID>' \
  -d 'token=<ANSWER>' \
  "${BASE}/user/missions/capture" -o /tmp/submit_result.html
```

## Reading the response

Server returns HTML with an alert div. Check result:

```bash
# Quick check
grep -oP '(SUCCESS|INCORRECT)[^<]*' /tmp/submit_result.html

# Full alert text
grep -A 5 'alert-success\|alert-danger' /tmp/submit_result.html

# Green = SUCCESS (points added)
# Red = INCORRECT (attempt consumed)
```

## Attempt tracking

The page shows `N/5` attempts per flag. After each submission, refetch the mission page to see updated count:

```bash
curl -s -H "Cookie: ${COOKIE}" \
  "${BASE}/user/missions/missions?uuid=<MISSION_UUID>" | \
  grep -oP 'Attempts</span>\s*\d+/\d+' | head -1
```

## Common issues

- **500 error on submit** — _xsrf mismatch (cookie != form value). Refetch page for fresh token
- **"Incorrect Response"** — wrong answer format. Check hint/format description in the question
- **Already used all 5 attempts** — cannot retry
