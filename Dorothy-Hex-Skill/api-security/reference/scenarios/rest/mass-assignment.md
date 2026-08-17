# REST Mass Assignment (Hidden Property Injection)

## When this applies

- API endpoint accepts a JSON/form body for create/update operations.
- Server uses bulk-bind / auto-binding (`Object.assign`, Rails `permit!`, Spring auto-bind).
- A field present in GET response (or guessable) is NOT in the form but IS bound on the server.

## Technique

Compare GET response fields with POST submission fields. Inject any field the GET response contains but POST omits — and any guessable privilege/discount/credit field. The server blindly binds them.

## Steps

### Lab — Apply 100% discount

```http
GET /api/checkout HTTP/1.1
Response:
{
  "chosen_discount": {"percentage": 0},
  "chosen_products": [...]
}

POST /api/checkout HTTP/1.1
Content-Type: application/json

{
  "chosen_discount": {"percentage": 100},
  "chosen_products": [{"product_id": "1", "quantity": 1}]
}
→ Success
```

### Workflow

1. Login and add jacket to basket
2. Attempt purchase → insufficient credit
3. In Proxy history, compare `GET /api/checkout` and `POST /api/checkout`
   - GET response contains `chosen_discount` parameter
   - POST request omits this parameter
4. Send POST request to Repeater
5. Inject discovered parameter:
```json
{
  "chosen_discount": {
    "percentage": 100
  },
  "chosen_products": [
    {
      "product_id": "1",
      "quantity": 1
    }
  ]
}
```
6. Submit → purchase succeeds with 100% discount

### Mass assignment detection

1. GET request to retrieve object
2. Identify all returned fields
3. Compare with UPDATE/POST submitted fields
4. Test adding undocumented fields from GET
5. Observe behavioral changes

Example:
```json
GET /api/user/profile
{
  "username": "user123",
  "email": "user@example.com",
  "role": "user",
  "credit": 100
}

POST /api/user/profile (test injection)
{
  "email": "new@example.com",
  "role": "admin",
  "credit": 999999
}
```

### Common parameter names

```
id, user_id, userid, username, email
token, access_token, api_key, key
role, admin, isAdmin, is_admin
price, discount, amount, total
password, new_password, current_password
page, limit, offset, count, size
format, type, content_type
callback, redirect, url, next
debug, verbose, trace
```

### Connector / integration URL fields (SSRF sink)

Create/update bodies for connectors, integrations, and webhooks often carry server-fetched URL fields — `base_url`, `api_url`, `auth_url`, `instance_url`, `endpoint`, `webhook_url`. The server dereferences these on save or on first sync, so a mass-assigned/attacker-controlled value is also an SSRF sink (cloud metadata, internal services). When you spot one of these fields, pivot: `skills/server-side/reference/scenarios/ssrf/stored-connector-url-ssrf.md`.

### Attack variations

- Negative percentages for credit gains
- Values >100 (150% discount)
- Multiple discount objects
- Other hidden fields: `shipping_cost`, `tax_rate`

### Bypass techniques

- Decimal values: `99.999999`
- Alternative field names: `discount_percent`, `discountPercentage`
- Case variations: `Percentage`, `PERCENTAGE`
- Nested structures: `{"discount": {"discount": {"percentage": 100}}}`

### Real-world examples

- **GitHub 2012:** Mass assignment allowed uploading public keys to any organization
- **E-commerce:** Manipulation of loyalty points, referral credits
- **SaaS:** Users upgrade features by injecting premium flags

## Verifying success

- The injected field's value is reflected on the next GET (`chosen_discount.percentage = 100`).
- Privileged action succeeds (purchase completes despite insufficient credit).
- Re-fetching the object shows the persisted modified value.

## Common pitfalls

- Some frameworks silently strip unknown fields — try the exact field name from the GET response first.
- Nested object injection requires correct nesting level (`user[role]` vs top-level `role`).
- Prefer the field name AND structure observed in GET — server-side validators often deserialize using the schema you see.

## Tools

- Burp Suite Repeater (compare GET vs POST)
- Burp Param Miner (Guess parameters)
- Arjun
- curl
