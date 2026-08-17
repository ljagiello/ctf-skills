# Breach Data, Email-Pattern Inference, Email Harvest

> Reference content for the `offensive-osint` skill. Originally §15 + §11 + §12 of the monolithic SKILL.md (refactored 2026-05-02 for size/load efficiency).

## 15. Breach & Leak Data

- [Have I Been Pwned](https://haveibeenpwned.com/) — breach lookup; Pwned Passwords API (k-anonymity).
- [Dehashed](https://dehashed.com/) — credential search (paid).
- [IntelX](https://intelx.io/) — data intelligence.
- [LeakCheck](https://leakcheck.io/), [Snusbase](https://snusbase.com/), [BreachDirectory](https://breachdirectory.org/), [Scattered Secrets](https://scatteredsecrets.com/), [Phonebook](https://phonebook.cz/), [LeakPeek](https://leakpeek.com/).
- [Cavalier (Hudson Rock)](https://cavalier.hudsonrock.com/) — **infostealer log lookups; FREE; highest single-source ROI for finding compromised employee credentials in corporate SSO**.

### 15.0.1 HudsonRock Cavalier — direct API recipe

The web UI wraps a **public, unauthenticated JSON API**. Hit it directly:

```bash
# By domain (canonical first call)
curl -sk -m 30 "https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-domain?domain=target.com" | jq .

# By email (single-account check)
curl -sk -m 30 "https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-email?email=alice@target.com" | jq .

# By URL (when target's app is the breach victim)
curl -sk -m 30 "https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-url?url=https://app.target.com" | jq .
```

PowerShell:
```powershell
$hr = Invoke-RestMethod -Uri "https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-domain?domain=$D" -TimeoutSec 30
"Employees: $($hr.employees) | Users: $($hr.users) | Third-party: $($hr.third_parties) | Total: $($hr.total)"
$hr.data.employees_urls | Sort-Object -Property occurrence -Descending | Select-Object -First 20
$hr.data.clients_urls   | Sort-Object -Property occurrence -Descending | Select-Object -First 15
```

**Top-level JSON fields:**
- `total` — total stealer entries touching this domain.
- `totalStealers` — global stealer-log corpus size (context only).
- `employees` — count of `<*>@<domain>` accounts found.
- `users` — count of accounts where the domain appeared as a *visited* URL (customers/vendors).
- `third_parties` — accounts touching adjacent domains in the org.
- `data.employees_urls[]` — `{occurrence, type, url}` — internal apps where employees were logging in when stolen. **Subdomain hits here = recon gold.**
- `data.clients_urls[]` — same shape; user-facing apps (often reveals undocumented public portals).
- `data.stealer_families[]` — `{_key, _value}` → which stealer (RedLine / Lumma / StealC / Vidar / Raccoon).
- `data.dates_compromised[]` — `{_key, _value}` → temporal distribution.

**Free-tier caveats (CRITICAL to know):**
- Subdomain hostnames in `data.*_urls[]` past the first few are **redacted with asterisks** (`*****.target.com`). Pivot to paid Cavalier tier or other sources for unredacted.
- Free endpoint returns counts + sample URLs only. Cleartext passwords + emails are **never** in the free response.
- Rate limit ~1 req/sec/IP; 429 on burst. Sleep 1s between calls.
- For unredacted creds + bulk enumeration → paid Cavalier portal.

**Severity mapping (per §15.1 + §15.2):** `employees ≥ 10` → CRITICAL, **regardless of whether the breached service is still online** (legacy Lotus Domino / on-prem mail decommissioned + cloud SSO migration → employees almost always reuse passwords → SSO_EXPOSURE escalates CRITICAL).

### 15.1 Domain-Level Breach Severity Mapping

When you query a breach corpus by domain, map the result to severity like so:

| Stat | Severity |
|---|---|
| ≥ 10 employees compromised | **CRITICAL** |
| 1–9 employees compromised | **HIGH** |
| ≥ 1 end-user (non-employee) compromised | **MEDIUM** |
| Domain seen in breach with 0 named accounts | **INFO** |

**Employees vs end-users distinction:** an employee account is `<anything>@<target-domain>` (the breach victim is the target's own staff). An end-user account is the target's customer who reused a password — useful for credential-stuffing risk awareness but not directly compromising the target's identity fabric.

### 15.2 SSO_EXPOSURE finding

When a discovered SSO tenant (Entra GUID / Okta slug / Google Workspace domain) intersects with the breach corpus on its domain → `SSO_EXPOSURE` finding, severity **CRITICAL**. Evidence: tenant ID + product + employee count + per-account source attribution.

**Legacy-mail-decommissioned pattern (high-value variant):**

If `mail.<domain>` / `webmail.<domain>` returns **NXDOMAIN today** but HudsonRock/HIBP corpus still has historical employee credentials against it AND `autodiscover.<domain>` resolves to Microsoft IPs (M365) or `aspmx.l.google.com` MX (Workspace), the org migrated from on-prem to cloud — and the stolen passwords almost certainly survived the migration via password reuse. **Escalate to CRITICAL `SSO_EXPOSURE`** even when the legacy host is dead.

Concrete triggers (all three together):
1. `Resolve-DnsName mail.<domain> -Type A` → NXDOMAIN (legacy gone)
2. HudsonRock corpus has employee URLs against the *old* host (e.g. `mail.<domain>/names.nsf` for Lotus Domino, `mail.<domain>/owa/` for Exchange, `mail.<domain>/iwaredir.nsf` for iNotes, `mail.<domain>/zimbra/` for Zimbra)
3. Current MX → M365 / Google Workspace / Zoho cloud (DNS confirms migration)

Evidence pack: tenant GUID + breach count + 3+ legacy URLs from corpus + autodiscover Microsoft IPs + current MX. Recommend forced password rotation + MFA audit + Conditional Access review.

---


## 11. Email-Pattern Inference (TENTATIVE candidates)

Given a `(first_name, last_name, domain)`, generate these 8 candidate addresses for breach pre-hits, phishing list curation, and downstream enrichment. Mark as **TENTATIVE** confidence until corroborated.

```
{first}.{last}@{domain}        # john.doe@example.com
{first}{last}@{domain}         # johndoe@example.com
{first}@{domain}               # john@example.com
{first[0]}{last}@{domain}      # jdoe@example.com
{first}.{last[0]}@{domain}     # john.d@example.com
{last}@{domain}                # doe@example.com
{first}_{last}@{domain}        # john_doe@example.com
{first}-{last}@{domain}        # john-doe@example.com
```

Lowercase before lookup. Strip diacritics for ASCII fallback. If the org uses a known pattern (e.g., Hunter.io shows `{first}.{last}` is dominant), prioritize that one and mark FIRM.

---

## 12. Email-Harvest Source Stack

Six parallel sources, dedup at the end:

1. **IntelX phonebook API** — 2-step search + poll. Largest single source for breach-era addresses.
2. **Hunter.io** — domain-search endpoint. ~25 free/month. Returns verified emails + roles.
3. **crt.sh** — extract X.509 SAN extensions. Many certs include admin/contact emails.
4. **DuckDuckGo SERP scrape** — HTML scrape of `"@{target-domain}"` results.
5. **Bing SERP scrape** — same query, complementary index.
6. **Wayback CDX** — historic snapshots of the target's homepage / contact / about pages often contain emails removed from the live site.

**Email regex:**
```regex
\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b
```

**Noise filter (reject numeric-only locals):**
```regex
^[0-9]+$
```
(Discards garbage like `12345@example.com` from random tokens.)

---

