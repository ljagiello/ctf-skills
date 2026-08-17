# Subdomain & Infrastructure Recon

> Reference content for the `offensive-osint` skill. Originally §27 + §28 of the monolithic SKILL.md (refactored 2026-05-02 for size/load efficiency).

## 27. Subdomain-Source Stack (Passive)

Practical "what actually returns useful data in 2026" reference, ordered by recall:

| Source | Tier | Notes |
|---|---|---|
| crt.sh | Free | Best single source for cert-derived subdomains; **frequently 502s during peak hours — see fallback chain below**. |
| VirusTotal | Freemium | Domain → passive DNS history. |
| AlienVault OTX | Free | Passive DNS + URL data. |
| Shodan | Paid (low tier) | Subdomain enum via `domain:` filter. |
| BinaryEdge | Paid | Comparable to Shodan. |
| FOFA | Freemium | Strong China-side coverage. |
| ZoomEye | Freemium | Comparable to Shodan; CN-strong. |
| Netlas | Paid | Large-scale HTTP/DNS/cert pivots. |
| SecurityTrails | Paid | Passive DNS + asset discovery. |
| RapidDNS | Free | Public passive DNS. |
| Subfinder bundled | Free | Aggregates 30+ free sources via one CLI. |
| Amass | Free | Comparable, more thorough, slower. |
| Recon-ng | Free | Modular framework; many free providers built in. |

**DNS AXFR opportunism:** for every name server discovered, attempt zone transfer:
```
dig @<ns-host> <target-domain> AXFR
```
Most NSs reject; those that don't = full zone disclosure (CRITICAL).

**Brute-force tier:** Subfinder/Subbrute against `assetnote.io` wordlists (best-curated public wordlist source).

### 27.0.1 crt.sh down? Fallback chain (try in order)

crt.sh runs on a single nginx in front of a busy Postgres; 502 / 503 / timeout in peak hours is routine. Don't retry-loop — pivot:

```bash
D="target.example"

# 1. Censys cert search (free 250 queries/month with key) — same data, different infra
censys search "names: ${D}" --index-type certificates --fields names | jq -r '.names[]' | sort -u

# 2. Cert Spotter API (sslmate) — free w/ rate limits
curl -sk "https://api.certspotter.com/v1/issuances?domain=${D}&include_subdomains=true&expand=dns_names" | \
  jq -r '.[].dns_names[]' | sort -u

# 3. CertStream archive (Calidog) — historical CT log mirror
curl -sk "https://crt.calidog.io/?q=${D}" | jq -r '.[].name_value' | sort -u

# 4. Subfinder bundled aggregator (uses 30+ sources internally — Chaos, Anubis, BinaryEdge, BufferOver, Censys, CertSpotter, Crobat, Crtsh, DNSDumpster, FOFA, Fullhunt, GitHub, HackerTarget, IntelX, PassiveTotal, Quake, Rapiddns, Shodan, Spyse, ThreatBook, ThreatMiner, URLScan, VirusTotal, WhoisXML, ZoomEye, etc.)
subfinder -d ${D} -all -recursive -silent

# 5. AlienVault OTX — free, no key
curl -sk "https://otx.alienvault.com/api/v1/indicators/domain/${D}/passive_dns" | \
  jq -r '.passive_dns[].hostname' | sort -u

# 6. ThreatMiner — free
curl -sk "https://api.threatminer.org/v2/domain.php?q=${D}&rt=5" | jq -r '.results[]'

# 7. URLScan — passive DNS via past scans
curl -sk "https://urlscan.io/api/v1/search/?q=domain:${D}" | \
  jq -r '.results[].page.domain' | sort -u

# 8. Anubis-DB / DNSDumpster (HTML scrape, last resort)
curl -sk -A "Mozilla/5.0" "https://anubisdb.com/anubis/subdomains/${D}" | jq -r '.[]'
```

PowerShell crt.sh wrapper with retry + fallback to Subfinder:

```powershell
function Get-Subs {
  param($D)
  for ($i=0; $i -lt 3; $i++) {
    try {
      $r = Invoke-WebRequest -Uri "https://crt.sh/?q=%25.$D&output=json" -UseBasicParsing -TimeoutSec 90 -UserAgent "Mozilla/5.0"
      return ($r.Content | ConvertFrom-Json | %{ $_.name_value -split "`n" } | %{ $_.Trim().ToLower() } | ?{ $_ -and $_ -notlike "*@*" -and $_ -notmatch "^\*\." } | Sort -Unique)
    } catch {
      "crt.sh attempt $($i+1) failed; sleep 5s..." | Out-Host
      Start-Sleep -Seconds 5
    }
  }
  "crt.sh down — pivot to Subfinder: subfinder -d $D -all -silent" | Out-Host
  return @()
}
```

### 27.1 Wordlist Sources for Subdomain + Content Brute-Force

| Source | URL | Notes |
|---|---|---|
| **Assetnote Wordlists** | `https://wordlists.assetnote.io/` | Best-curated; updated regularly. Subdomain top-N (1k, 10k, 100k, 1M, 10M); content-paths per CMS/framework; per-vendor (AWS, Azure, GitLab, etc.). |
| **SecLists** | `https://github.com/danielmiessler/SecLists` | Massive collection. Subdomains: `Discovery/DNS/subdomains-top1million-110000.txt`. Content: `Discovery/Web-Content/`. |
| **jhaddix all.txt** | `https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056` | Long-running curated list. |
| **OneListForAll** | `https://github.com/six2dez/OneListForAll` | Aggregated; very large (millions). |
| **dirsearch wordlists** | `https://github.com/maurosoria/dirsearch` | Bundled with the tool. |
| **raft-large-words.txt** | inside SecLists `Discovery/Web-Content/raft-large-words.txt` | Time-tested content wordlist. |
| **bo0om wordlist** | `https://github.com/bo0om/wordlists` | Russian-language-aware. |
| **commonspeak2** | `https://github.com/assetnote/commonspeak2-wordlists` | Generated from BigQuery commit data. |
| **fuzzdb** | `https://github.com/fuzzdb-project/fuzzdb` | Fuzzing payloads + wordlists. |
| **PayloadsAllTheThings** | `https://github.com/swisskyrepo/PayloadsAllTheThings` | Per-vuln-class payloads (less for enum, more for follow-on). |
| **Custom per-target** | n/a | Best practice: derive a custom wordlist from the target's own content (extract every word from their public website + LinkedIn + careers page → unique → use as seed). |

**Size guidance:**
- **<10k entries** → fast subdomain check (1–2 min); use for opportunistic/passive-supplement.
- **10k–100k entries** → standard depth (10–30 min); use as default brute-force.
- **100k–1M entries** → thorough; use when the target is a known high-value engagement (1–4 hours).
- **>1M entries** → exhaustive; reserve for week-long engagements; expect rate-limiting.

**Tooling:**
```bash
# Subfinder + brute-force with assetnote 100k
subfinder -d target.example -all -recursive | tee passive.txt
puredns bruteforce assetnote-best-dns-wordlist.txt target.example -r resolvers.txt | tee brute.txt
cat passive.txt brute.txt | sort -u > all-subs.txt

# Content brute-force on alive hosts
ffuf -u "https://target.example/FUZZ" -w raft-large-words.txt -mc 200,301,403 -t 50 -ac
```

---

## 28. Infrastructure & Attack-Surface OSINT

- [Shodan](https://www.shodan.io/), [Censys](https://search.censys.io/) — internet device + cert search.
- [GreyNoise](https://viz.greynoise.io/) — distinguish background noise from targeted scans.
- [SecurityTrails](https://securitytrails.com/) — passive DNS + asset discovery.
- [SpiderFoot](https://www.spiderfoot.net/) — automated recon + correlation.
- [theHarvester](https://github.com/laramies/theHarvester) — subdomain, email, metadata.
- [Recon-ng](https://github.com/lanmaster53/recon-ng) — web recon framework.
- [Amass](https://github.com/owasp-amass/amass) / [Subfinder](https://github.com/projectdiscovery/subfinder) — passive subdomain.
- [BuiltWith](https://builtwith.com/) — tech stack enumeration.
- [Netlas](https://netlas.io/) — large-scale HTTP/DNS/cert pivots.
- [BinaryEdge](https://www.binaryedge.io/) / [FOFA](https://fofa.so/) / [ZoomEye](https://www.zoomeye.org/) — Shodan/Censys complements.
- [RiskIQ PassiveTotal](https://community.riskiq.com/) — passive DNS/cert/host pivots.
- [Spur](https://spur.us/) — IP lookups.
- [Robtex](https://www.robtex.com/) — passive DNS + infrastructure.

### 28.1 ASN/BGP & Internet Measurement

- [Hurricane Electric BGP Toolkit](https://bgp.he.net/), [RIPEstat](https://stat.ripe.net/), [BGPView](https://bgpview.io/), [bgp.tools](https://bgp.tools/), [PeeringDB](https://www.peeringdb.com/).

**Bulk IP → ASN — recipes that actually work in 2026:**

```bash
# Cymru bulk WHOIS (fastest; no rate-limit issues; no key required)
echo -e "begin\nverbose\n8.8.8.8\n1.1.1.1\nend" | nc whois.cymru.com 43
# Or one-shot:
whois -h whois.cymru.com " -v 8.8.8.8"

# RIPEstat (free; CORS-friendly; ~1 req/sec polite limit)
curl -sk "https://stat.ripe.net/data/network-info/data.json?resource=8.8.8.8" | jq '.data'

# bgp.tools per-IP API (free; light rate-limit; requires UA)
curl -sk -A "osint-recon/1.0 (contact@example.com)" "https://bgp.tools/api/ip/8.8.8.8" | jq .

# IPinfo Lite (free 50k req/month with free key)
curl -sk "https://ipinfo.io/8.8.8.8?token=<key>" | jq .
```

**Watch out:**
- `bgpview.io` API has aggressive undocumented rate limits (~1 req/min/IP); not suitable for bulk.
- `bgp.he.net` has no public API; HTML scraping only — fragile.
- `PeeringDB` is for facility/IX info, not per-IP ASN lookup.
- For bulk (>50 IPs): use the **Cymru bulk format** above; it accepts hundreds of IPs in one TCP session.

### 28.2 Certificates & CT Monitoring

- [crt.sh](https://crt.sh/), [Censys Certificates](https://search.censys.io/certificates), [CertStream](https://certstream.calidog.io/) (real-time CT WebSocket), [Rapid7 Open Data](https://opendata.rapid7.com/), [Cert Spotter](https://sslmate.com/certspotter) (freemium).
- **Favicon mmh3 hash:** cluster infrastructure across hosts; pair with Shodan/Censys favicon search for shared-infra discovery.

### 28.3 Web tech / TLS / fingerprinting

- **httpx (ProjectDiscovery)** — Wappalyzer-compatible ~600 signatures, JARM, favicon mmh3, TLS cert SHA256, security headers, screenshots. Recommended one-shot probe wrapper for thousands of hosts.
- **JARM** — TLS handshake hash; stable per server config; useful for clustering.
- **Wappalyzer** browser extension or CLI for tech enumeration.

### 28.4 TLS Deep Audit

Beyond the cert SAN + JARM, inspect cipher suites, protocols, and config quality.

**sslyze (most thorough):**
```bash
pip install sslyze
sslyze --regular target.example:443
sslyze --json_out=tls.json target.example:443
```
Reports: protocols supported (TLS 1.0/1.1/1.2/1.3), cipher suites per protocol, cert chain, OCSP, key info, robot/heartbleed/lucky13/poodle/freak/logjam/drown/ccs/ticketbleed.

**testssl.sh (thorough + readable output):**
```bash
docker run --rm -ti drwetter/testssl.sh https://target.example
# Or native install: https://github.com/drwetter/testssl.sh
testssl.sh --jsonfile-pretty=tls-report.json target.example:443
```

**nmap script alternative (lighter):**
```bash
nmap --script ssl-enum-ciphers,ssl-cert -p 443 target.example
```

**Check for these issues:**

| Issue | Severity | What to look for |
|---|---|---|
| TLS 1.0 / 1.1 supported | MEDIUM | Deprecated; PCI-DSS forbids TLS 1.0. |
| SSL 3.0 / 2.0 supported | HIGH | Critically deprecated. |
| Weak ciphers (RC4, 3DES, CBC modes) | MEDIUM | RC4 = NOMORE attack; 3DES = SWEET32. |
| Anonymous DH | HIGH | No authentication. |
| Self-signed cert on production | MEDIUM | Trust failure. |
| Expired cert | MEDIUM | Operational + trust failure. |
| Cert valid for too long (>397 days) | LOW | Browser warnings since 2020. |
| Wildcard cert covering critical hosts | INFO | Operational risk if private key compromised. |
| Weak key size (<2048 RSA, <256 ECDSA) | HIGH | Cryptographically weak. |
| Heartbleed (CVE-2014-0160) | CRITICAL | Memory disclosure. |
| ROBOT (CVE-2017-13099) | HIGH | Bleichenbacher. |
| CCS injection (CVE-2014-0224) | HIGH | OpenSSL specific. |
| Ticketbleed (CVE-2016-9244) | HIGH | F5-specific memory disclosure. |
| HSTS not present (covered §16.4) | MEDIUM | Header audit. |

**JA3 / JA4 reference databases:**

- [ja3er.com](https://ja3er.com) — community-curated JA3 → client-software mapping.
- [TLS Fingerprint DB](https://tlsfingerprint.io/) — research aggregator.
- For server JARM: search Shodan `ssl.jarm:<hash>` to find shared infrastructure / origin candidates (see §16.15).

### 28.5 Reverse DNS Sweep & IPv6 Enumeration

When a target owns an IP range (their ASN), enumerate it.

**Reverse DNS sweep (within scope):**
```bash
# Single /24
for i in $(seq 1 254); do
  IP="203.0.113.$i"
  PTR=$(dig +short -x $IP)
  [ -n "$PTR" ] && echo "$IP -> $PTR"
done

# Larger range with parallelism
prips 203.0.113.0/22 | xargs -I {} -P 50 sh -c 'PTR=$(dig +short -x {}); [ -n "$PTR" ] && echo "{} -> $PTR"'
```

**Mass DNS approach (better for large ranges):**
```bash
# zdns: install via go install github.com/zmap/zdns/cmd/zdns@latest
prips 203.0.113.0/22 | zdns PTR
```

**Banner-only sweep (no DNS round trip):**
```bash
# masscan + banner-grab
sudo masscan -p80,443 203.0.113.0/22 --rate=1000 --banners -oX masscan.xml
```

**IPv6 enumeration:**

IPv6 has weaker enumeration tradition (huge address space precludes brute-force) but the AAAA records and known-allocation prefixes are still useful.

```bash
# AAAA records for every discovered subdomain
for sub in $(cat all-subs.txt); do
  AAAA=$(dig +short AAAA $sub)
  [ -n "$AAAA" ] && echo "$sub -> $AAAA"
done

# IPv6 reverse DNS sweep is generally infeasible (2^64 host bits per subnet)
# Instead: extract IPv6 prefixes from the target's allocations
whois -h whois.cymru.com " -v target.example.com"   # gets ASN; then look up prefix
```

**BGP route observation:**

- **RouteViews** — `http://archive.routeviews.org/` (free; historical BGP routing table snapshots).
- **RIPE RIS** — `https://ris.ripe.net/` (free; route collectors).
- Use these to detect route hijacks against the target's prefixes (defensive intel; sometimes IOC).

**Reverse DNS pivots from third-party IPs:**

If a third-party shows the target's domain in PTR records (e.g., a hosting provider's IP has PTR `customer-acme.example.com.hostingprovider.net`), that's a pivot for adjacent customer infrastructure on the same provider/datacenter.

---

