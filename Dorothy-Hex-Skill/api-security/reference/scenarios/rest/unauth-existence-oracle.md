# Unauthenticated Existence Oracle (Error-Ordering Side Channel)

## When this applies

- Any id-keyed endpoint that answers before full authentication — login, password-reset, org/tenant resolution, invite acceptance, an API-key-scoped resource lookup.
- The server checks **object / org / tenant existence BEFORE validating the supplied auth key**. This is a proactive `XC-EXISTENCE-ORACLE` coverage class: it emits no fingerprint until you deliberately diff a "bad key on a real id" vs a "bad key on a fake id".

## Technique

Secure endpoints return one indistinguishable error for "no such object" and "object exists but auth failed" — they validate the key first, or normalize both branches. A vulnerable one evaluates existence first:

```
1. row = lookup(org_id)          # existence check runs FIRST
2. if row is None: return 404    #   ← leaks "does not exist"
3. if not valid(key, row): 401   #   ← only reached when it DOES exist
```

So a deliberately garbage key still **discriminates** "exists, auth failed" (`401`) from "not found" (`404`). With a key you know is wrong, you enumerate which ids are real — no valid credential required. The same ordering flaw appears as username/email enumeration on login and reset flows.

## Steps

### 1. Establish the two reference responses

Pick an id you *know* exists (your own org/account) and one you *know* does not. Send the **same wrong key** to both:

```bash
KEY='definitely-invalid-key'

# Known-good id, wrong key
curl -s -w '\n%{http_code} %{time_total}\n' \
  -H "Authorization: Bearer $KEY" https://api.target.tld/v1/orgs/<KNOWN_ID>/info

# Known-bad id, wrong key
curl -s -w '\n%{http_code} %{time_total}\n' \
  -H "Authorization: Bearer $KEY" https://api.target.tld/v1/orgs/00000000/info
```

### 2. Diff status, message, and timing

Capture all three discriminators:

| Signal | exists (auth failed) | does not exist |
|--------|----------------------|----------------|
| status | `401 Unauthorized` | `404 Not Found` |
| message | `invalid credentials` | `organization not found` |
| timing | slower (row fetched, key compared) | faster (short-circuit) |

If any axis cleanly separates the two reference cases, you have an existence oracle. Body text often names the entity (`organization`, `account`, `tenant`) and confirms the leak directly.

### 3. Enumerate the id space

Walk candidate ids (sequential ints, slugs, or ids harvested from JS/docs/CORS leaks) with the constant wrong key, bucketing by the discriminating signal. Keep the rate well under any limit — this is enumeration, not brute force, and never guesses the *key*:

```bash
while read id; do
  code=$(curl -s -o /dev/null -w '%{http_code}' \
    -H "Authorization: Bearer $KEY" "https://api.target.tld/v1/orgs/$id/info")
  echo "$id $code"
done < candidates.txt | awk '$2==401{print $1" EXISTS"}'
```

### 4. Cross-check on auth flows

The same flaw surfaces on `/login`, `/password-reset`, and `/invite` — a distinct "user not found" vs "wrong password" response enumerates valid accounts. Diff the responses for a known-good vs known-bad principal the same way.

## Verifying success

- The same invalid key produces **different** status / message / timing for a real id vs a fake id.
- The discriminating branch is reached **before** key validation (a syntactically valid but unauthorized key reproduces the split).
- You can convert the oracle into a list of confirmed-existing ids that you had no credential to see.

## Common pitfalls

- A uniform `401`/`404` for both reference cases means the endpoint normalizes — record the N/A, don't force it.
- Timing differentials are noisy across the internet — average several samples and corroborate with status/body before claiming a timing-only oracle.
- WAFs/rate limiters can inject their own `403`/`429`, masking the real branch — confirm you're seeing the app's response, not the edge's.
- Match the id format exactly; a malformed id can trip a `400` validation branch that hides the real existence split.
- Some APIs return `403` (not `404`) for non-existent objects to *avoid* this leak — that's the secure pattern; note it as covered-N/A.

## Tools

- curl (`%{http_code}` + `%{time_total}` differential)
- ffuf / Burp Intruder for id-space walking (low rate)
- Companion oracles: `scenarios/rest/unauthenticated-webhook-oracle.md`, `scenarios/rest/verbose-error-schema-disclosure.md`
