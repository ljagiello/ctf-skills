# OWASP API Security Top 10 (2023) — Coverage Map

This file maps every OWASP API Security Top 10 (2023) item to the scenario file and the **explicit probe** that covers it, then adds rows for the no-fingerprint cross-cut classes (CORS, webhook oracle, transport downgrade, existence oracle, verbose errors, public docs) so they cannot be silently skipped. The fingerprint decision tree in `api-security-principles.md` tells you where to START once a symptom appears; this map plus `coverage-matrix.md` define DONE.

## Contents

- [API1–API10 map](#api1api10-map)
- [No-fingerprint cross-cut classes](#no-fingerprint-cross-cut-classes)
- [Recommended probe order](#recommended-probe-order)
- [N/A justification cheat sheet](#na-justification-cheat-sheet)
- [How to use](#how-to-use)

## API1–API10 map

| OWASP item | class_id | Scenario file | Explicit probe |
|------------|----------|---------------|----------------|
| API1 — Broken Object Level Auth | `API1-BOLA` | `scenarios/rest/owasp-bola-bopla.md` | Swap object id to another tenant's; diff status/size |
| API2 — Broken Authentication | `API2-BROKEN-AUTH` | `authentication/SKILL.md` | Weak/forgeable tokens, credential stuffing surface, reset flow |
| API3 — Broken Object Property Level Auth | `API3-BOPLA` | `scenarios/rest/mass-assignment.md` | Inject privileged/hidden fields into create/update bodies |
| API4 — Unrestricted Resource Consumption | `API4-RESOURCE` | `scenarios/rest/api-recon-and-discovery.md` | Characterize rate/size limits (measure only, no flooding) |
| API5 — Broken Function Level Auth | `API5-BFLA` | `scenarios/rest/owasp-bola-bopla.md` | Low-priv token on admin route / hidden verb (OPTIONS) |
| API6 — Unrestricted Access to Business Flows | `API6-BUSINESS` | `web-app-logic/SKILL.md` | Replay/automate a sensitive workflow past intended limits |
| API7 — Server-Side Request Forgery | `API7-SSRF` | `server-side/.../ssrf/` + `scenarios/ssrf/stored-connector-url-ssrf.md` | Server-fetched URL field → collaborator/metadata callback |
| API8 — Security Misconfiguration | `API8-MISCONFIG` | `scenarios/rest/https-downgrade-redirect-hsts.md` | Headers, verbose errors, default config, CORS posture |
| API9 — Improper Inventory Management | `API9-INVENTORY` | `scenarios/rest/exposed-documentation.md` | Swagger/OpenAPI without auth; shadow/old API versions |
| API10 — Unsafe Consumption of 3rd-party APIs | `API10-CONSUMPTION` | `scenarios/rest/api-recon-and-discovery.md` | Trust boundaries on upstream data the API ingests |

Probe depth notes (what a shallow pass under-tests on each item):

- **API1** — test write/action endpoints (`PATCH`/`DELETE`/archive), not just `GET`; UUIDs need a leak source (search, public profile) before enumeration.
- **API2** — cover the *full* auth lifecycle: login, refresh, reset, logout/revocation, and token forgery — not just the login form.
- **API3** — drive field discovery from `verbose-error-schema-disclosure.md`; inject server-fetched URL fields (`base_url`, `webhook_url`) that double as SSRF sinks → `API7-SSRF`.
- **API4** — characterize limits passively (response headers, observed throttling); do NOT flood. A missing limit is a finding on its own.
- **API5** — combine role axis (low-priv token) with verb axis (`OPTIONS`-revealed `PATCH`/`PUT`) — function-level gaps hide on unlisted verbs.
- **API6** — model the intended sequence/quantity of a business flow, then break it (replay, skip a step, exceed a per-account cap).
- **API7** — every connector/integration create-body URL field is a sink; confirm with an out-of-band collaborator callback, then try metadata/internal targets.
- **API8** — this is the umbrella for the cross-cut classes below; do not treat one missing header as the whole of API8.
- **API9** — walk back from any `/api/v2/...` to `/api/v1/...` and `/openapi.json`/`swagger`; shadow/old versions often skip the auth the current one enforces.
- **API10** — where the API ingests upstream JSON/redirects, test whether it trusts upstream-controlled fields (open-redirect, SSRF, deserialization) without re-validation.

## No-fingerprint cross-cut classes

These emit NO symptom in normal traffic; symptom-driven routing misses them. Each MUST be actively probed (or justified N/A) before P5.

| class_id | What it is | Scenario file | Explicit probe |
|----------|-----------|---------------|----------------|
| `XC-CORS` | Reflected-origin / `null` / credentialed CORS | `scenarios/rest/cors-misconfiguration.md` | `curl -H 'Origin: …'`; check ACAO reflection + `ACAC: true` |
| `XC-WEBHOOK-ORACLE` | Unauth webhook/ingress state oracle | `scenarios/rest/unauthenticated-webhook-oracle.md` | No-auth POST to `/webhooks` etc.; diff 404 vs state-error vs 202 |
| `XC-TRANSPORT-DOWNGRADE` | HTTPS→HTTP redirect / missing HSTS | `scenarios/rest/https-downgrade-redirect-hsts.md` | `curl -I` http+https; cleartext `Location`; HSTS directives |
| `XC-SECURITY-HEADERS` | Header set per origin (CSP/XFO/etc.) | `scenarios/rest/https-downgrade-redirect-hsts.md` | `curl -I` each origin separately; tabulate missing headers |
| `XC-EXISTENCE-ORACLE` | Existence/enum via error-ordering | `scenarios/rest/unauth-existence-oracle.md` | Garbage key on real vs fake id; diff 401 vs 404 |
| `XC-VERBOSE-ERRORS` | Stack/schema/token-lifecycle disclosure | `scenarios/rest/verbose-error-schema-disclosure.md` | Malformed/wrong-typed body; harvest field names/types/trace |
| `API9-INVENTORY` (docs) | Public Swagger/OpenAPI/shadow versions | `scenarios/rest/exposed-documentation.md` | Walk back to `/api`; fetch `openapi.json` unauthenticated |

## Recommended probe order

The no-fingerprint classes are cheap, unauthenticated, and feed the rest — run them early so their output (schema, inventory, reachable origins) seeds the authenticated tests:

1. `XC-TRANSPORT-DOWNGRADE` + `XC-SECURITY-HEADERS` — `curl -I` every origin; one pass per host, zero auth.
2. `API9-INVENTORY` — fetch public docs/`openapi.json`; the schema it yields scopes every later probe.
3. `XC-CORS` — forge `Origin` on the authenticated endpoints found above.
4. `XC-VERBOSE-ERRORS` — malformed bodies leak the internal field map → feeds `API3-BOPLA` and injection.
5. `XC-EXISTENCE-ORACLE` + `XC-WEBHOOK-ORACLE` — error-ordering enumeration with a known-bad key / unauth POST.
6. Then the authenticated object/property/function tests (`API1`/`API3`/`API5`) against the now-known id space and schema.

## N/A justification cheat sheet

When a class auto-resolves to `not_applicable`, the `justification` MUST quote the failed trigger. Copy-ready phrasings:

- `XC-CORS` → "no browser-reachable API origin reflects `Origin`; ACAO is static/absent on all probed endpoints".
- `XC-WEBHOOK-ORACLE` → "no inbound webhook/ingress endpoint: `/webhooks|/ingress|/callback|/events` all 404/401 to unauth POST".
- `XC-TRANSPORT-DOWNGRADE` → "no HTTP (port 80) listener; only HTTPS exposed".
- `XC-EXISTENCE-ORACLE` → "id-keyed unauth responses normalized: real vs fake id return identical status/body/timing".
- `XC-VERBOSE-ERRORS` → "all malformed/wrong-typed bodies return opaque `400`; no field/type/stack disclosure".
- `API7-SSRF` → "no server-fetched URL parameter on any create/update body".

## How to use

1. The canonical engagement coverage contract is `skills/coordination/reference/coverage-matrix.md` — copy it to `OUTPUT_DIR/coverage.json` at bootstrap.
2. Mark each class `applicable` or `not_applicable` from its trigger vs the discovered surface.
3. Every applicable class needs **≥1 experiment** (a resolvable `E-NNN` / `finding-NNN` evidence ref) **or a justified N/A** (quoting the failed trigger) before P5.
4. Use the tables above to pick the scenario file and the exact probe for each pending class — the no-fingerprint rows are the ones a symptom-driven pass forgets, so spend a mission on them deliberately.
5. The engagement validator recomputes `coverage_ratio = covered / applicable` independently and FAILs thoroughness below 0.80 — pending applicable classes block COMPLETE.

A `coverage.json` row reaches `covered` only with a resolvable evidence ref; a `NA` row must quote the failed trigger:

```json
[
  {"class_id":"XC-CORS","applicability":"applicable","status":"covered",
   "evidence_ref":["E-021"],"justification":"ACAO reflected attacker origin + ACAC:true on /v1/me"},
  {"class_id":"XC-WEBHOOK-ORACLE","applicability":"not_applicable","status":"NA",
   "evidence_ref":[],"justification":"trigger 'inbound webhook/ingress endpoint' did not match: no /webhooks|/ingress|/callback|/events accepts unauth POST"}
]
```

Do not terminate while any applicable class is `pending` — "I ran out of ideas" or "I already found a flag" is not coverage-complete.

## Relationship to coverage-matrix.md

This file is the api-security-specific lookup — OWASP item → scenario → probe. `coverage-matrix.md` is the canonical, taxonomy-wide class catalog and the source of `class_id` values; it also owns the `applicable`/`covered`/`NA` state machine and the 0.80 gate. Keep `class_id`s here aligned with that catalog: if a class is added or renamed there, update the corresponding row here. When the two disagree, `coverage-matrix.md` wins — this map is a routing convenience layered on top of it, not a second source of truth.
