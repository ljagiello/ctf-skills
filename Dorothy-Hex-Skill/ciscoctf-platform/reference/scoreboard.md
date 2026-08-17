# Scoreboard & User Data

## Leaderboard

Simple leaderboard for an event:

```bash
curl -s -H "Cookie: ${COOKIE}" \
  "${BASE}/scoreboard?e=<EVENT_CODE>" -o /tmp/scoreboard.html

# Extract player rows
python3 -c "
import re
with open('/tmp/scoreboard.html') as f:
    html = f.read()
# Find ranked players
rows = re.findall(r'<tr[^>]*>.*?</tr>', html, re.DOTALL)
for row in rows:
    cells = re.findall(r'<td[^>]*>(.*?)</td>', row, re.DOTALL)
    if len(cells) >= 3:
        rank = re.sub(r'<[^>]+>', '', cells[0]).strip()
        name = re.sub(r'<[^>]+>', '', cells[1]).strip()
        score = re.sub(r'<[^>]+>', '', cells[2]).strip()
        print(f'{rank}. {name} - {score}')
"
```

## Detailed leaderboard (team/player view)

```bash
curl -s -H "Cookie: ${COOKIE}" \
  "${BASE}/teams?e=<EVENT_CODE>" -o /tmp/teams.html
```

## My Report Card

Shows your flag capture status per mission:

```bash
curl -s -H "Cookie: ${COOKIE}" \
  "${BASE}/myreport?e=<EVENT_CODE>&uuid=<MISSION_UUID>" -o /tmp/report.html

# Extract captured flags
grep -oP '(Captured|Not Captured|Flag \d+)' /tmp/report.html | head -10
```

## User settings / profile

```bash
curl -s -H "Cookie: ${COOKIE}" \
  "${BASE}/user/settings" -o /tmp/settings.html

curl -s -H "Cookie: ${COOKIE}" \
  "${BASE}/user/accountmgmt" -o /tmp/account.html
```

## Active event info

Fetch event home to see current active event and stats:

```bash
curl -s -H "Cookie: ${COOKIE}" \
  "${BASE}/user/event/home" -o /tmp/event_home.html

# Mission UUIDs
grep -oP '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}' /tmp/event_home.html | sort -u

# Total captured
grep -oP '(flags captured|Flags Captured|score|Score)[^<]*' /tmp/event_home.html | head -5
```
