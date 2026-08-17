# Second-Order SQL Injection

## When this applies

- Input is safely parameterized at insertion (e.g. registration), but later read back and concatenated unsafely.
- Common in: profile updates, password resets, search history, audit logs, "recent activity" features.
- The first request looks completely benign — no injection observable until a later, separate request triggers the stored value's unsafe use.

## Technique

Persist a payload via a safe insertion path. Wait for (or trigger) a second code path that retrieves the stored value and concatenates it into a new query without re-parameterizing.

## Steps

### 1. Register / store payload

```python
# Registration uses parameterized query — payload stored verbatim
username = "admin'--"
password = "anything"
cursor.execute(
    "INSERT INTO users (username, password) VALUES (?, ?)",
    (username, password)
)
```

Other entry points to consider for stored payloads:
- Display name / nickname
- Email address (subject to validation)
- Address fields
- Search saved-query feature
- Comments / posts
- Tags

### 2. Trigger the unsafe second path

Visit any feature that takes the stored value and embeds it in a new query:

```python
# Profile update — UNSAFE retrieval and reuse
cursor.execute("SELECT username FROM users WHERE id=?", (user_id,))
username = cursor.fetchone()[0]   # 'admin'--

query = f"UPDATE profiles SET bio='New bio' WHERE username='{username}'"
cursor.execute(query)
# Resulting SQL:
# UPDATE profiles SET bio='New bio' WHERE username='admin'--'
```

Common second-stage triggers:
- Saving profile / preferences
- Changing password (uses stored username in WHERE)
- Sending a notification
- Generating a report
- Audit log writes

### 3. Detection workflow

1. Register/store with a sentinel: `test'--`, `test"--`, `test')--`.
2. Visit every authenticated feature you can reach.
3. Watch for:
   - 500 errors on otherwise-working pages.
   - Different rendering of the stored value (escaping changes between contexts).
   - Behavior changes (e.g. password change "succeeds" but password didn't change → query was malformed).

### 4. Exfiltration once confirmed

Once the unsafe second path is identified, switch the stored value to a destructive/extractive payload:

```sql
test'; UPDATE users SET role='admin' WHERE username='attacker'--
test' UNION SELECT credit_card FROM orders WHERE id=1--
```

The exact payload depends on the second-path query; you may need source code or trial-and-error to learn the surrounding query structure.

### 5. Boolean second-order

When the second path doesn't render output, fall back to boolean blind via the stored value:

```
Stored: test' AND (SELECT 'a' FROM users WHERE username='admin' AND SUBSTRING(password,1,1)='a')='a'--
```

Trigger the second path; observe if it succeeded or errored. Iterate stored payload + retrigger.

## Verifying success

- A request that previously worked now returns 500 / error after registering a `'`-containing username.
- Payload that includes UNION SELECT pulls data into a context that renders it.
- Destructive payload (in authorized labs) demonstrably modifies database state in a way the second path shouldn't allow.

## Common pitfalls

- Many storage paths sanitize/escape on insert (good!) but the issue is on RETRIEVAL — focus testing on what happens to stored values.
- Account lockout / cooldowns may prevent rapid registration with new payloads — register with a long-lived account and test other entry points (display name, etc.).
- Some second paths are async (job queues) — wait several seconds before checking for effects.
- Stored payload may be truncated by column length; test column width before crafting longer payloads.
- Some apps re-encode on store (e.g. HTML-encode `'` to `&#x27;`) — that breaks SQLi but breaks XSS too. Test with multiple encodings.

## Tools

- Burp Suite session management (register → set session → trigger workflow).
- Manual workflow walkthroughs (register, then poke every feature).
- sqlmap `--second-order <url>` (for known stored→retrieved patterns).
