# DNS Subdomain Enumeration

## When this applies

- You have an in-scope apex domain (e.g. `target.com`) and need to enumerate subdomains.
- Goal is to expand the attack surface — staging, dev, internal, legacy hosts often live on subdomains and are less hardened than the apex.
- Combine passive (no traffic to target) and active (DNS brute-force) methods.

## Technique

Passive sources (Certificate Transparency logs, passive DNS, search engines, Wayback) are queried first because they don't touch the target. Active methods (DNS brute-force, NSEC walking, AXFR) confirm liveness and find subdomains not yet indexed.

## Steps

### 1. Passive enumeration — Certificate Transparency

CT logs publish every TLS certificate issued. Wildcard certs and SAN extensions reveal subdomains immediately.

```bash
# crt.sh JSON API
curl -s "https://crt.sh/?q=%25.target.com&output=json" \
  | jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u

# certspotter
curl -s "https://api.certspotter.com/v1/issuances?domain=target.com&include_subdomains=true&expand=dns_names" \
  | jq -r '.[].dns_names[]' | sort -u
```

Wildcard SAN certs (`*.target.com`) are a strong indicator of hidden vhosts on the same IP — see `skills/reconnaissance/reference/scenarios/vhost-enumeration.md`.

### 2. Passive enumeration — passive DNS / search

```bash
# subfinder aggregates dozens of passive sources
subfinder -d target.com -all -silent

# amass passive mode
amass enum -passive -d target.com

# assetfinder
assetfinder --subs-only target.com
```

API keys for SecurityTrails, Censys, Shodan, VirusTotal etc. dramatically improve subfinder/amass coverage — set them in `~/.config/subfinder/provider-config.yaml`.

### 3. Wayback / archive enumeration

```bash
# Wayback Machine
curl -s "http://web.archive.org/cdx/search/cdx?url=*.target.com&output=text&fl=original&collapse=urlkey" \
  | awk -F/ '{print $3}' | sort -u

# gau aggregates Wayback + Common Crawl + AlienVault OTX
gau --subs target.com | unfurl domains | sort -u
```

### 4. DNS brute-force (active)

```bash
# puredns with massdns under the hood — fastest brute-force
puredns bruteforce subdomains-top1million-110000.txt target.com -r resolvers.txt

# gobuster DNS mode
gobuster dns -d target.com -w subdomains-top1million.txt -t 50

# ffuf with DNS resolution via Host header
ffuf -u https://FUZZ.target.com -w subdomains.txt -mc 200,301,302,403
```

Common wordlists:
- `SecLists/Discovery/DNS/subdomains-top1million-110000.txt`
- `SecLists/Discovery/DNS/n0kovo_subdomains.txt`
- `SecLists/Discovery/DNS/dns-Jhaddix.txt`

### 5. Permutation generation

```bash
# alterx — apply common patterns (dev, staging, -1, -prod) to known subdomains
echo "api.target.com" | alterx | puredns resolve - -r resolvers.txt

# dnsgen
dnsgen subdomains.txt | massdns -r resolvers.txt -t A -o S
```

### 6. NSEC / NSEC3 walking (DNSSEC zones)

```bash
# Walk an NSEC chain (some DNSSEC zones leak the entire zone)
nmap --script dns-nsec-enum --script-args dns-nsec-enum.domains=target.com -sU -p 53 ns1.target.com

# nsec3walker for NSEC3
```

DNSSEC NSEC records list the next existing name in the zone — chained queries enumerate everything. NSEC3 is hashed but offline-crackable for short labels.

### 7. Wildcard detection

```bash
# Resolve a clearly fake subdomain — if it resolves, the zone uses a wildcard
dig +short xyzzy123notreal.target.com

# puredns auto-detects wildcards
puredns bruteforce wordlist.txt target.com  # filters wildcards by default
```

When a wildcard `*.target.com → 1.2.3.4` exists, every brute-force query returns `1.2.3.4` — filter by HTTP response (status code, body length, title) instead of relying on DNS resolution.

### 8. Verify subdomains are live

```bash
# httpx — probe each candidate for HTTP/S response
cat candidates.txt | httpx -title -status-code -tech-detect -o live.txt

# Resolve A records to confirm DNS exists
cat candidates.txt | dnsx -resp -a
```

## Verifying success

- Output file `subdomains.txt` with deduplicated, sorted candidates.
- `live.txt` containing only candidates that respond on 80/443.
- Diff between passive and active sets — passive-only subdomains may have moved to internal IPs (still useful for vhost brute-force).

## Common pitfalls

- **Wildcard zones** poison brute-force results — always check for `*.target.com` first.
- **Resolvers throttle aggressive queries** — use a `resolvers.txt` with public 8.8.8.8 / 1.1.1.1 + many alternatives. Run `dnsvalidator` to keep the list fresh.
- **CT logs only show TLS-issued certs** — internal/non-TLS subdomains aren't in CT.
- **CDN/Cloud subdomains** often resolve to a shared edge IP — confirm with vhost brute-force (`Host:` header) on the discovered IP.
- **Subdomain takeover candidates**: dangling CNAMEs to AWS S3, Azure, Heroku, GitHub Pages with no resource provisioned. Check with `subjack` / `dnsReaper`.
- **Passive discovery before active** — tools like amass active mode are noisy and may trip detection.

## Tools

- subfinder, amass (passive aggregators)
- puredns, massdns (high-speed brute-force)
- gobuster, ffuf (alternative brute-force)
- alterx, dnsgen (permutation)
- httpx, dnsx (validation)
- crt.sh, certspotter (CT logs)
- subjack, dnsReaper (takeover detection)
- gau, waybackurls (archive enumeration)
