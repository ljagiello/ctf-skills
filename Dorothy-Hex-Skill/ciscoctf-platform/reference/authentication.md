# Authentication

CiscoCTF uses cookie-based sessions (Tornado/ASP.NET). No API tokens.

## Getting the session_id from user

User opens F12 → Application (Chrome/Edge) or Storage (Firefox) → Cookies → `netacad.ciscoctf.io` → copy `session_id` Value.

**Do NOT ask user to run `document.cookie`** — session_id is HttpOnly and won't appear.

The user should also provide three cookie values:
- `session_id` (from Application tab)
- `csessxptim` (from Application tab or `document.cookie`)
- `_xsrf` (from Application tab or `document.cookie`)

## Cookie string setup

```bash
SID='session_id="2|1:0|10:...|..."'
COOKIE="csessxptim=<value>; _xsrf=<value>; ${SID}"
```

## Getting fresh _xsrf

The `_xsrf` cookie expires. Get a fresh one from any page:

```bash
# Fetch event select page — server sets new _xsrf cookie
PAGE=$(curl -s -D /tmp/head.txt -H "Cookie: ${COOKIE}" \
  'https://netacad.ciscoctf.io/%F0%9F%8F%86%E2%9A%A1%F0%9F%9A%A9/user/event/select')

# Extract _xsrf from hidden input in form
XSRF=$(echo "$PAGE" | grep -oP 'name="_xsrf" value="\K[^"]+')

# Also extract from Set-Cookie header (for cookie jar)
XSRF_COOKIE=$(grep -i 'set-cookie.*_xsrf' /tmp/head.txt | sed 's/.*_xsrf=//' | cut -d';' -f1)

# Update COOKIE with fresh _xsrf
COOKIE="csessxptim=<value>; _xsrf=${XSRF}; ${SID}"
```

## Cookie file approach (for curl -b/-c)

```bash
cat > /tmp/cookies.txt << EOF
# Netscape HTTP Cookie File
netacad.ciscoctf.io	FALSE	/	TRUE	<expiry>	_xsrf	${XSRF}
netacad.ciscoctf.io	FALSE	/	TRUE	<expiry>	csessxptim	<timestamp>
#HttpOnly_netacad.ciscoctf.io	FALSE	/	TRUE	<expiry>	session_id	"<value>"
EOF
# Use: curl -b /tmp/cookies.txt -c /tmp/cookies.txt
```

## Reusing across commands

Always export these environment variables at the start:

```bash
export SID='session_id="..."'
export XSRF="2|...|...|..."
export CSESS="<csessxptim_value>"
export COOKIE="csessxptim=${CSESS}; _xsrf=${XSRF}; ${SID}"
export BASE="https://netacad.ciscoctf.io/%F0%9F%8F%86%E2%9A%A1%F0%9F%9A%A9"
export REFERER="${BASE}/user/missions/missions?uuid=<mission_uuid>"
```

## SSO login (for reference, not needed if session_id provided)

Login flow (id.cisco.com Okta):
1. GET `/login/usingciscosso` → 302 to id.cisco.com authorize URL
2. POST `id.cisco.com/api/v1/authn` with `{username, password}` → get sessionToken
3. GET authorize URL with `&sessionToken=...` → 302 to callback URL
4. GET callback URL twice (first sets `r` cookie, second triggers redirect)
5. Follow redirect to `/authenticated?state=...` → gets `session_id` cookie

This flow is only needed when the user cannot provide a session_id. It kicks the browser session out.
