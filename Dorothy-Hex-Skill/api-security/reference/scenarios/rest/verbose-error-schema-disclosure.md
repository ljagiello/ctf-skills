# Verbose Error & Schema Disclosure

## When this applies

- Any endpoint that parses a structured body (JSON/XML/form) and runs server-side validation.
- The target leaks internals through error responses: framework validation arrays, ORM errors, stack traces, or auth-provider token-lifecycle messages. This is a proactive `XC-VERBOSE-ERRORS` coverage class — it surfaces only when you deliberately send malformed or wrong-typed input.

## Technique

Well-built APIs return a generic, opaque error (`400 Bad Request`, no detail). Many frameworks default to **verbose** errors that echo the internal model: field names you didn't know existed, expected types, parser state, ORM SQL fragments, file paths, and library versions. Send malformed bodies, wrong types, and missing/extra fields and harvest the structure from the errors. The leaked schema then **accelerates** mass-assignment, BOLA, and injection — you fuzz against the real field list instead of guessing.

## Steps

### 1. Type-confusion — send the wrong type for each field

Submit a value whose type contradicts the expected one (string where int expected, object where string expected, array where scalar expected):

```bash
curl -s -X POST https://api.target.tld/v1/widgets \
  -H 'Content-Type: application/json' \
  -d '{"count":"not-a-number","owner_id":[],"config":"should-be-object"}'
```

A Pydantic/FastAPI app leaks the field map in its `422 detail` array:

```json
{"detail":[
  {"loc":["body","count"],"msg":"value is not a valid integer","type":"type_error.integer"},
  {"loc":["body","owner_id"],"msg":"value is not a valid uuid","type":"type_error.uuid"},
  {"loc":["body","config","region"],"msg":"field required","type":"value_error.missing"}
]}
```

`loc`/`type` reveal exact internal field names, types, and the nested shape (`config.region`) — including fields not in the public form.

### 2. Malformed / truncated body — leak parser state

```bash
curl -s -X POST https://api.target.tld/v1/widgets \
  -H 'Content-Type: application/json' -d '{"count":'
```

JSON parsers report the byte/line offset and parser state (`Expecting value: line 1 column 11`), confirming the framework and sometimes the deserializer. An XML body to a JSON endpoint (or vice-versa) often dumps a content-negotiation stack trace.

### 3. Provoke ORM / DB-layer errors

A value that breaks a constraint, a duplicate unique key, or a type the DB driver rejects can surface an ORM error quoting the **table/column names** and a SQL fragment:

```
IntegrityError: duplicate key value violates unique constraint "widgets_slug_key"
DETAIL: Key (slug)=(demo) already exists.
```

This names columns and constraints directly — high-value schema intel (and a hint that injection error-based extraction may work; cross to the injection skill).

### 4. Stack traces / debug mode

A `500` with `debug=true` (Flask/Django/Rails/Express dev mode) returns a full traceback: file paths, line numbers, framework + version, sometimes config/secret fragments. Trigger it with an input that escapes the validation layer (oversized value, unexpected encoding) and capture the trace.

### 5. Auth-provider verbose token errors

OAuth/JWT/SSO layers leak **token lifecycle** detail that distinguishes failure modes — `token expired` vs `invalid signature` vs `audience mismatch` vs `unknown key id`. These reveal the token type, accepted issuers/audiences, key-rotation state, and clock behavior:

```bash
curl -s https://api.target.tld/v1/me -H 'Authorization: Bearer eyJ...tampered'
# {"error":"invalid_token","error_description":"signature verification failed: kid \"k1\" not found"}
```

Capture the exact `error_description` strings — they map the auth provider's validation order and accepted parameters.

## Verifying success

- An error response names internal fields/types/columns NOT present in the public API surface or docs.
- The leaked schema lets you target a follow-up probe (mass-assign a newly-revealed field, inject into a named column) that you could not have guessed blind.
- Auth errors discriminate failure modes (expired vs bad-signature vs wrong-audience) rather than returning one opaque `401`.

## Common pitfalls

- A generic opaque `400`/`401` for every malformed input means errors are sanitized — record the N/A.
- Don't conflate the framework's default verbosity with a *deployed* leak — confirm the verbose body is returned by the live target, not a local repro.
- Some gateways rewrite app errors into generic ones at the edge; the verbose body may only appear on a direct/origin path — note where you observed it.
- Verbose validation that leaks field names overlaps with the existence oracle — keep findings distinct (`XC-VERBOSE-ERRORS` = schema/stack; `XC-EXISTENCE-ORACLE` = id existence).
- Stay non-destructive: provoke errors with malformed *read-shaped* requests; avoid duplicate-key probes on production data that could corrupt state.

## Tools

- curl (wrong-typed / truncated / cross-content-type bodies)
- Burp Repeater (mutate one field at a time, diff error bodies)
- Feeds: `scenarios/rest/mass-assignment.md`, `scenarios/rest/owasp-bola-bopla.md`, `injection/SKILL.md`
