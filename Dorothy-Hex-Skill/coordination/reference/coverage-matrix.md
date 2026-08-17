# Attack-Class Coverage Matrix

The completion contract for **coverage-style engagements** (web / API / cloud pentests, as opposed to flag/CTF hunts). A flag engagement is done when the flag submits; a coverage engagement is done when **every applicable attack class has been tested or justified N/A**. This file is the canonical class catalog; each engagement instantiates it as `OUTPUT_DIR/coverage.json`.

Companion to `ATTACK_INDEX.md` (which inventories *what techniques the library covers*). This file defines *what an engagement must cover before it may be called COMPLETE*. The api-security fingerprint decision tree (`skills/api-security/reference/api-security-principles.md`) tells you where to START once a symptom appears; this matrix defines DONE — including the classes that emit **no fingerprint until actively probed** and are therefore missed by symptom-driven routing.

## Scoping rule

A class is **applicable** iff its trigger matches the discovered surface; otherwise it is auto-`NA` with the failed trigger as the justification. `coverage_ratio = covered / applicable`, where `applicable = total − not_applicable`. The engagement validator FAILs thoroughness below **0.80** (`validator-role.md` check 8).

## Class catalog

`class_id` is the stable key used in `coverage.json`, the THINK schema, and the validator. Technique-ref points at the scenario/skill that covers the technique.

| class_id | Taxonomy | Class — what it is | Applicability trigger | Technique ref |
|----------|----------|--------------------|-----------------------|---------------|
| `API1-BOLA` | API'23 | Broken Object Level Auth (cross-tenant object access) | any object-by-id endpoint | `api-security/.../rest/owasp-bola-bopla.md` |
| `API2-BROKEN-AUTH` | API'23 | Broken Authentication | any auth surface | `authentication/SKILL.md` |
| `API3-BOPLA` | API'23 | Broken Object Property Level Auth / mass-assignment | JSON create/update bodies | `api-security/.../rest/mass-assignment.md` |
| `API4-RESOURCE` | API'23 | Unrestricted Resource Consumption (rate/limit) | any API (characterize only; no flooding) | `api-security/.../rest/api-recon-and-discovery.md` |
| `API5-BFLA` | API'23 | Broken Function Level Auth (role/verb) | role/verb-gated endpoints | `web-app-logic/SKILL.md` |
| `API6-BUSINESS` | API'23 | Unrestricted access to sensitive business flows | workflow endpoints | `web-app-logic/SKILL.md` |
| `API7-SSRF` | API'23 | SSRF — incl. **stored connector/webhook URL** | any server-fetched URL param | `server-side/.../ssrf/*` |
| `API8-MISCONFIG` | API'23 | Security misconfiguration | always | `web-app-logic/SKILL.md` |
| `API9-INVENTORY` | API'23 | Improper inventory (shadow/old versions, **public docs/swagger**) | any API | `api-security/.../rest/exposed-documentation.md` |
| `API10-CONSUMPTION` | API'23 | Unsafe consumption of 3rd-party APIs | API consumes upstream data | `api-security/.../rest/api-recon-and-discovery.md` |
| `WEB-A03-INJECTION` | Web'21 | Injection (SQLi/NoSQLi/cmd/SSTI/XXE) | any input sink | `injection/SKILL.md` |
| `WEB-A04-DESIGN` | Web'21 | Insecure design / logic flaw | any workflow | `web-app-logic/SKILL.md` |
| `WEB-A06-COMPONENTS` | Web'21 | Vulnerable & outdated components | any fingerprinted version | `source-code-scanning/SKILL.md` |
| `WEB-A08-INTEGRITY` | Web'21 | Software/data integrity (deserialization) | deser / CI surface | `server-side/.../insecure-deserialization-resources.md` |
| `XC-SUBDOMAIN-ORIGIN` | Cross-cut | Subdomain/origin exposure (CDN bypass, exposed admin/mgmt panels) | any apex domain in scope | `reconnaissance/.../scenarios/subdomain-enumeration.md` |
| `XC-CORS` | Cross-cut | CORS misconfig (reflected origin / null / credentials) | any browser-reachable API | `api-security/.../rest/cors-misconfiguration.md` |
| `XC-WEBHOOK-ORACLE` | Cross-cut | Unauthenticated webhook/ingress state oracle | any inbound webhook/ingress endpoint | `api-security/.../rest/unauthenticated-webhook-oracle.md` |
| `XC-TRANSPORT-DOWNGRADE` | Cross-cut | HTTPS→HTTP redirect downgrade / missing HSTS | any HTTP listener | `api-security/.../rest/https-downgrade-redirect-hsts.md` |
| `XC-EXISTENCE-ORACLE` | Cross-cut | Unauth existence/enumeration oracle (org/user/object via error-ordering) | any id-keyed unauth response | `api-security/.../rest/unauth-existence-oracle.md` |
| `XC-VERBOSE-ERRORS` | Cross-cut | Verbose errors (stack/schema/framework/token-lifecycle disclosure) | any error surface | `api-security/.../rest/verbose-error-schema-disclosure.md` |
| `XC-SECURITY-HEADERS` | Cross-cut | Security headers — probe API **and** every web origin separately | every distinct host | `api-security/.../rest/https-downgrade-redirect-hsts.md` |
| `XC-STORED-XSS` | Cross-cut | Stored/reflected/DOM XSS (report **persistence** even when render needs follow-up creds) | any stored user-controlled field | `client-side/SKILL.md` |
| `XC-TLS-POSTURE` | Cross-cut | TLS posture (weak ciphers/protocols) via sslscan | any TLS listener | `cryptography/SKILL.md` (sslscan) |
| `XC-SECRET-EXPOSURE` | Cross-cut | Secret/key exposure in JS bundles, docs, git | any static JS / repo | `osint/SKILL.md` |

## Instance-file contract — `OUTPUT_DIR/coverage.json`

Generated at bootstrap from this catalog, owned by the INTEGRATE agent (sole writer, mirroring the `experiments.md` ownership rule). One row per `class_id`:

```json
{
  "class_id": "API7-SSRF",
  "taxonomy": "API-2023",
  "title": "Server-Side Request Forgery",
  "applicability": "applicable",        // applicable | not_applicable
  "status": "covered",                  // covered | pending | NA
  "evidence_ref": ["E-014", "finding-003"],
  "justification": "stored connector base_url fetched server-side; own-org POST + collaborator callback",
  "owner_batch": 4
}
```

Rules enforced by the validator:
- `status:covered` requires ≥1 `evidence_ref` that resolves to a real `E-NNN` row in `experiments.md` or an existing `finding-NNN/` dir. A `covered` row with no resolvable evidence is treated as `pending`.
- `status:NA` is legal only when `applicability:not_applicable`, and requires a `justification` quoting the failed applicability trigger.
- `status:pending` is the bootstrap default for every applicable class.

## How the loop uses it

1. **Bootstrap** seeds `coverage.json`: every catalog row instantiated; `applicability` set from the trigger vs the discovered surface; applicable rows `pending`, others `NA`+justification.
2. **THINK** (coverage mode) ranks `pending` applicable classes by value (impact × likelihood-on-surface × low-credential reachability) and spends ≥1 mission/batch on the top-ranked pending class. The wildcard slot is preserved.
3. **INTEGRATE** flips probed classes to `covered`+`evidence_ref` or justified-`NA` each batch, and reports `applicable_pending`.
4. The loop is "solved" (coverage-complete) only when `applicable_pending == 0`; it may not terminate early while applicable classes are `pending` ("I ran out of hypotheses" / "I hit a goal" is not done).
5. **Engagement validator** check 8 recomputes `coverage_ratio` independently and gates COMPLETE at 0.80.
