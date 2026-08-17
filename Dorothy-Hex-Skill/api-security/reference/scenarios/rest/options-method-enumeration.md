# OPTIONS Method Enumeration (Hidden HTTP Verbs)

## When this applies

- Endpoint exposed via UI uses one HTTP method (GET) but supports others (PATCH, PUT, DELETE).
- Authorization is verb-bound — POST is gated but PATCH is not.
- Goal: discover and exploit the unrestricted verb (mass-assign, modify price, delete data).

## Technique

Send `OPTIONS` to the endpoint. Read the `Allow:` header for supported methods. Test each verb with the existing session. Hidden verbs are the typical privilege-escalation path.

## Steps

### Lab — Lightweight l33t Leather Jacket price = 0

```http
OPTIONS /api/products/1/price HTTP/1.1
→ Allow: GET, PATCH

PATCH /api/products/1/price HTTP/1.1
Content-Type: application/json
Cookie: session=[token]

{"price":0}
→ 200 OK
```

### Workflow

1. Browse to product page and capture `/api/products/1/price` request
2. Send to Repeater and change method from `GET` to `OPTIONS`
   - Response reveals: `Allow: GET, PATCH`
3. Try `PATCH` without auth → 401 Unauthorized
4. Login
5. Send `PATCH` request → Error: missing Content-Type header
6. Add `Content-Type: application/json` with empty body `{}`
   - Error: missing price parameter
7. Send `PATCH` with `{"price":0}`
8. Reload product page → price changed to $0.00
9. Add to cart and complete purchase

### HTTP method testing

**Methods to test:** GET, POST, PUT, PATCH, DELETE, OPTIONS, HEAD, CONNECT, TRACE

**Workflow:**
1. Identify endpoint: `/api/products/123`
2. Send OPTIONS to discover methods
3. Test each discovered method
4. Test undisclosed methods (even if not in OPTIONS)
5. Analyze responses

**Burp Intruder method fuzzing:**
```
§METHOD§ /api/products/123 HTTP/1.1
Host: target.com
Content-Type: application/json

{"id": 123, "price": 0}

Payloads: GET, POST, PUT, PATCH, DELETE, OPTIONS, HEAD
```

### Attack variations

- Negative price values
- Extremely small decimals (0.01)
- Modify other attributes (stock, name, description)
- Batch modifications for multiple products

### Bypass techniques

- Alternative encodings: `application/x-www-form-urlencoded`
- Unicode in numeric fields
- Array payloads: `{"price":[0]}`

## Verifying success

- `OPTIONS` returns `Allow:` header listing extra verbs.
- The hidden verb succeeds on the endpoint with your existing session.
- The target resource state changes (price modified, item deleted).

## Common pitfalls

- Some servers refuse `OPTIONS` from authenticated users — try unauthenticated.
- `Allow:` may list verbs the server rejects in practice — test each.
- Some frameworks (Spring) auto-allow `HEAD` for any GET handler — useful for confirming existence without body.

## Tools

- Burp Suite Repeater (Change request method)
- Burp Intruder (method fuzzing)
- curl `-X <METHOD>`
- Burp Active Scan++
