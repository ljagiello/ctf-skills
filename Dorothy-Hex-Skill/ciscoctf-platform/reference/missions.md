# Missions — Event & Flag Management

## Listing events

```bash
curl -s -H "Cookie: ${COOKIE}" "${BASE}/user/event/select" -o /tmp/events.html

# Extract event codes
grep -oP 'data-event_code="[^"]*"' /tmp/events.html

# Check which events are ongoing
grep -oP 'data-current_events_codes_list="[^"]*"' /tmp/events.html
grep -oP 'data-unjoined_events_codes_list="[^"]*"' /tmp/events.html
```

## Joining / selecting an event

If the event is already joined (appears under "Your Ongoing CTF Events"), selecting it as active:

```bash
XSRF=$(grep -oP 'name="_xsrf" value="\K[^"]+' /tmp/events.html)
COOKIE="csessxptim=${CSESS}; _xsrf=${XSRF}; ${SID}"

curl -s -D /tmp/select_h.txt -H "Cookie: ${COOKIE}" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -H "Referer: ${BASE}/user/event/select" \
  -d "_xsrf=${XSRF}" -d 'event_code=<EVENT_CODE>' \
  "${BASE}/user/event/select"
```

If response is `302 /user/event/home` → success. If `302 /500` → check _xsrf cookie matches form value.

For unjoined events, same endpoint joins AND selects.

## Viewing mission flags

Get mission UUIDs from the event home page:

```bash
curl -s -H "Cookie: ${COOKIE}" "${BASE}/user/event/home" -o /tmp/home.html
grep -oP '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}' /tmp/home.html | sort -u
```

View specific mission:

```bash
curl -s -H "Cookie: ${COOKIE}" \
  "${BASE}/user/missions/missions?uuid=<MISSION_UUID>" -o /tmp/mission.html
```

## Extracting flag details

Each mission page contains all flags with UUIDs, questions, and attempt counts:

```bash
# Extract flag UUIDs
grep -oP 'data-flag_uuid="[^"]*"' /tmp/mission.html | sort -u

# Extract question text and answer format
python3 -c "
import re
with open('/tmp/mission.html') as f:
    html = f.read()
# Find each flag section
flags = re.findall(r'Question \d+.*?(?=Question \d|\$)', html, re.DOTALL)
for i, flag in enumerate(flags):
    q = re.search(r'Question \d+', flag)
    text = re.search(r'<div class=\"markdown\">(.*?)</div>', flag, re.DOTALL)
    uuid = re.search(r'id=\"([a-f0-9-]+)\"', flag)
    print(f'Q{i+1}: {q.group(0) if q else \"?\"} | UUID: {uuid.group(1) if uuid else \"?\"} | Text: {(text.group(1).strip()[:200] if text else \"?\")}')
"

# Extract current attempt count
grep -oP 'Attempts">\\s*\\d+/\\d+' /tmp/mission.html
```

## Important notes

- Each flag has a **unique UUID** required for submission
- Attempt count shown as `N/5` on the page
- Use the **flag UUID** (from `data-flag_uuid` or `id=""` attribute), not the mission UUID
- XSRF token in the capture form is per-page-load — always use the one from the current page
