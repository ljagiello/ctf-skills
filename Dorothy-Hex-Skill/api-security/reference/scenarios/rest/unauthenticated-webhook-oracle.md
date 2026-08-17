# Unauthenticated Webhook / Ingress State Oracle

## When this applies

- The surface exposes an inbound ingestion endpoint: `/webhooks`, `/ingress`, `/callback`, `/events`, `/hooks`, `/notify`, `/inbound`.
- The endpoint accepts an unauthenticated (or weakly pre-auth) POST — it is designed to receive third-party callbacks, so it must answer before any caller-side credential exists.
- The handler resolves the referenced object id via a **global** lookup before validating the payload signature. This is a proactive `XC-WEBHOOK-ORACLE` coverage class — it emits no fingerprint until you POST to it.

## Technique

A correctly built webhook receiver validates the request signature/HMAC **first** and returns a single opaque response (`202 Accepted` / generic `400`) regardless of whether the referenced object exists. A vulnerable one resolves the object id against a global (cross-tenant) table *before* signature validation, so its error branch differs by object state:

- unknown id → `404 not found`
- known id, wrong state → `400 "object not in active state: pending"`
- known id, right state → proceeds (queues work, `202`)

Those three distinct response shapes turn an unauthenticated endpoint into a **cross-tenant existence + state oracle**: an attacker who knows no credentials can confirm which object ids exist and what lifecycle state they are in.

## Steps

### 1. Discover the ingestion endpoint

Enumerate the common ingress paths and note which accept POST without auth:

```bash
for p in webhooks ingress callback events hooks notify inbound; do
  printf '%s -> ' "$p"
  curl -s -o /dev/null -w '%{http_code}\n' -X POST "https://api.target.tld/$p" \
    -H 'Content-Type: application/json' -d '{}'
done
```

A `400`/`422` (rather than `401`/`403`) means the handler ran without rejecting on auth — it is parsing your body.

### 2. Probe a random id vs a known id

Send the same well-formed body twice — once with a random/non-existent id, once with an id you legitimately know (your own object, or one leaked elsewhere):

```bash
# Random / non-existent object id
curl -s -w '\n%{http_code} %{time_total}\n' -X POST https://api.target.tld/webhooks \
  -H 'Content-Type: application/json' \
  -d '{"object_id":"00000000-0000-0000-0000-000000000000","event":"update"}'

# Known-good object id
curl -s -w '\n%{http_code} %{time_total}\n' -X POST https://api.target.tld/webhooks \
  -H 'Content-Type: application/json' \
  -d '{"object_id":"<KNOWN_ID>","event":"update"}'
```

### 3. Compare status, body, and timing

Tabulate the three discriminators across responses:

| Signal | not-found | exists, wrong state | exists, right state |
|--------|-----------|---------------------|---------------------|
| status | 404 | 400 / 409 | 202 |
| body   | `"not found"` | `"not in active state: X"` | queued/accepted |
| timing | fast (no DB row) | medium (row fetched) | slow (work queued) |

Any axis that reliably separates the cases is the oracle. The body message often **leaks the exact lifecycle state name** (`pending`, `active`, `suspended`) — capture it.

### 4. Map the inventory

Walk an id space (sequential ints, or ids harvested from CORS/JS/docs leaks) and bucket each by oracle signal. Keep request volume low and well below any rate limit — this is mapping, not flooding:

```bash
while read id; do
  code=$(curl -s -o /dev/null -w '%{http_code}' -X POST https://api.target.tld/webhooks \
    -H 'Content-Type: application/json' -d "{\"object_id\":\"$id\",\"event\":\"update\"}")
  echo "$id $code"
done < ids.txt | sort -k2
```

Result: a cross-tenant inventory of which object ids exist and their states — built with zero credentials.

## Verifying success

- The same payload yields **distinguishable** responses (status / body / timing) for a known id vs a random id.
- A response body discloses an internal lifecycle state value tied to an object you do not own.
- The discrimination happens **before** any signature/HMAC check (a deliberately wrong/absent signature still produces the existence-dependent branch).

## Common pitfalls

- A uniform `202` for everything means the handler validates the signature first — not vulnerable; record the N/A.
- Timing alone is noisy — corroborate with status/body before claiming a timing oracle; average several requests.
- Some receivers return `404` only after a valid signature — confirm the discriminator survives with a garbage signature.
- Stay non-destructive: many ingestion events *mutate* state. Use read-style `event` values and never replay a real payload that triggers side effects.
- The id format matters — match the observed scheme (UUID vs int vs slug) or every probe collapses to one error branch.

## Tools

- curl (status / `%{time_total}` timing differential)
- ffuf / Burp Intruder for id-space walking (low rate)
- Cross-reference object enumeration: `scenarios/rest/unauth-existence-oracle.md`
