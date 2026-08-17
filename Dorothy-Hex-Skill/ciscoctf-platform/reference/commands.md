# Quick Command Reference

All commands assume these exports (set once at top):

```bash
export SID='session_id="..."'
export XSRF="2|...|..."
export CSESS="<csessxptim>"
export COOKIE="csessxptim=${CSESS}; _xsrf=${XSRF}; ${SID}"
export BASE="https://netacad.ciscoctf.io/%F0%9F%8F%86%E2%9A%A1%F0%9F%9A%A9"
```

## Core Commands

### Refresh XSRF
```bash
PAGE=$(curl -s -D /tmp/h.txt -H "Cookie: ${COOKIE}" "${BASE}/user/event/select")
XSRF=$(echo "$PAGE" | grep -oP 'name="_xsrf" value="\K[^"]+')
COOKIE="csessxptim=${CSESS}; _xsrf=${XSRF}; ${SID}"
```

### List events
```bash
curl -s -H "Cookie: ${COOKIE}" "${BASE}/user/event/select" | \
  grep -oP 'data-(current|unjoined|upcoming)_events_codes_list="[^"]*"'
```

### Select/join event
```bash
curl -s -D /tmp/h.txt -H "Cookie: ${COOKIE}" \
  -H "Referer: ${BASE}/user/event/select" \
  -d "_xsrf=${XSRF}" -d 'event_code=XFNDF0' \
  "${BASE}/user/event/select"
# Expect 302 to /user/event/home
```

### Get mission UUIDs
```bash
curl -s -H "Cookie: ${COOKIE}" "${BASE}/user/event/home" | \
  grep -oP '[0-9a-f-]{36}' | sort -u
```

### View mission flags
```bash
curl -s -H "Cookie: ${COOKIE}" \
  "${BASE}/user/missions/missions?uuid=<MISSION_UUID>" -o /tmp/m.html
```

### Submit flag
```bash
curl -s -H "Cookie: ${COOKIE}" \
  -H "Referer: ${BASE}/user/missions/missions?uuid=<MISSION_UUID>" \
  -d "_xsrf=${XSRF}" -d 'uuid=<FLAG_UUID>' -d 'token=<ANSWER>' \
  "${BASE}/user/missions/capture" | grep -oP '(SUCCESS|INCORRECT)[^<]*'
```

### Leaderboard
```bash
curl -s -H "Cookie: ${COOKIE}" "${BASE}/scoreboard?e=XFNDF0"
```

## Parsing help

```bash
# Extract all flag UUIDs + question text from mission page
python3 << 'EOF'
import re
with open('/tmp/m.html') as f:
    h = f.read()
sections = re.split(r'<div class="row border-flag-separator', h)
for s in sections:
    uuid = re.search(r'id="([a-f0-9-]+)"', s)
    q = re.search(r'Question (\d+)', s)
    md = re.search(r'<div class="markdown">(.*?)</div>', s, re.DOTALL)
    if uuid and q:
        txt = re.sub(r'<[^>]+>', '', md.group(1)).strip()[:150] if md else '?'
        print(f"Q{q.group(1)}: uuid={uuid.group(1)} | {txt}")
EOF
```

## Notes

- Always encode emoji path as `%F0%9F%8F%86%E2%9A%A1%F0%9F%9A%A9`
- Always include Referer header on POST submissions
- Fresh XSRF for each batch of operations
- `session_id` requires quotes in cookie value: `'session_id="..."'`
