# Subdomain Enumeration

## When this applies

A root domain (e.g. `example.tld`) is in scope and the goal is to enumerate every subdomain that could host a web application, API, mail server, or admin panel. Run this before any active scanning of the target.

## Technique

Subdomain enumeration combines three approaches:

1. **Passive sources** - Certificate Transparency logs, DNS history aggregators, search engines, and threat-intel feeds. No traffic to the target.
2. **DNS brute force** - Resolving candidate names from a wordlist against the target's authoritative resolvers.
3. **Permutation and alteration** - Mutating known subdomains (e.g. `dev1`, `dev-eu`, `dev.staging`) with patterns and dictionaries.

Wildcard DNS records (`*.example.tld -> A 1.2.3.4`) need detection up-front: every brute-force lookup will resolve, producing thousands of false positives. Filter by response IP and content size after resolution.

## Steps

1. **Define output structure**

   ```bash
   mkdir -p recon/{inventory,raw}
   DOMAIN=example.tld
   ```

2. **Passive collection - certificate transparency**

   ```bash
   # crt.sh JSON output (free, no auth)
   curl -s "https://crt.sh/?q=%25.${DOMAIN}&output=json" \
     | jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u \
     > recon/raw/crt-sh-${DOMAIN}.txt

   # subfinder aggregates many passive sources
   subfinder -d ${DOMAIN} -all -silent -o recon/raw/subfinder-${DOMAIN}.txt

   # amass passive mode
   amass enum -passive -d ${DOMAIN} -o recon/raw/amass-${DOMAIN}.txt
   ```

3. **Passive DNS history**

   ```bash
   # SecurityTrails, VirusTotal, AlienVault OTX (require API keys for higher quotas)
   # Use shuffledns / dnsx / chaos-client when keys are configured
   chaos -d ${DOMAIN} -silent -o recon/raw/chaos-${DOMAIN}.txt 2>/dev/null || true
   ```

4. **Combine and deduplicate**

   ```bash
   cat recon/raw/{crt-sh,subfinder,amass,chaos}-${DOMAIN}.txt 2>/dev/null \
     | grep -E "\.${DOMAIN}$" | sort -u > recon/inventory/subdomains-passive.txt
   wc -l recon/inventory/subdomains-passive.txt
   ```

5. **Wildcard detection**

   ```bash
   # Resolve a guaranteed-bogus name; if it returns an IP, wildcard is in play
   WILDCARD_IP=$(dig +short "thisshouldnotexist-$(date +%s).${DOMAIN}" | head -1)
   echo "Wildcard IP: ${WILDCARD_IP:-none}"
   ```

   If a wildcard exists, record the IP. Later filtering will drop any subdomain that resolves to that IP unless it has distinct content.

6. **DNS brute force**

   ```bash
   # Common wordlists: SecLists subdomains-top1million-{5000,20000,110000}.txt
   WORDLIST=/usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt
   shuffledns -d ${DOMAIN} -w ${WORDLIST} -r resolvers.txt \
     -o recon/raw/shuffledns-${DOMAIN}.txt -silent
   # Or with dnsx in pure mode:
   dnsx -silent -d ${DOMAIN} -w ${WORDLIST} -o recon/raw/dnsx-${DOMAIN}.txt
   ```

7. **Permutation generation**

   ```bash
   # alterx generates permutations from known names
   cat recon/inventory/subdomains-passive.txt \
     | alterx -silent \
     | dnsx -silent -resp \
     > recon/raw/permutations-${DOMAIN}.txt
   ```

8. **Live host filtering**

   ```bash
   # Resolve to A/AAAA, drop wildcard matches if filtering needed
   cat recon/raw/*.txt | sort -u \
     | dnsx -silent -a -resp-only \
     > recon/raw/resolved-${DOMAIN}.txt

   # Probe HTTP/HTTPS to find live web servers
   cat recon/raw/resolved-${DOMAIN}.txt \
     | httpx -silent -title -sc -cl -location \
     -o recon/inventory/subdomains-live.txt
   ```

9. **Response-size filter for wildcard reduction**

   When wildcard DNS responds for everything, distinguish real hosts by content:

   ```bash
   httpx -l recon/raw/resolved-${DOMAIN}.txt \
     -silent -fr -title -sc -cl -hash sha256 \
     | awk '{print $0}' | sort -k4 -u   # group by content hash
   ```

   Hosts with identical content hash and size are wildcard duplicates. Investigate hosts with unique hash or status code.

## Verifying success

- Inventory file `recon/inventory/subdomains-live.txt` contains hostnames with HTTP status, title, and content length.
- Counts: passive >= 0, brute >= 0, permutations >= 0; deduplicated total recorded.
- Wildcard status documented (`Wildcard IP: x.x.x.x` or `none`).
- Each live subdomain has at least: `name -> IP -> status code -> content length`.

## Common pitfalls

- Trusting brute-force results without wildcard filtering produces inventories with thousands of fake hosts.
- Querying `crt.sh` for the bare domain (`example.tld`) misses subdomains; use `%.example.tld`.
- Ignoring CNAMEs that point off-target - they may be takeover candidates but are not the target's own infrastructure.
- Stopping at one passive source. Subfinder, amass, and crt.sh each have unique coverage gaps.
- Running brute force on a domain with very low query budget without rate limiting.

## Tools

- `subfinder`, `amass`, `chaos-client` - passive aggregation.
- `crt.sh` (web), `cero`, `cero-tools` - certificate transparency.
- `shuffledns`, `dnsx`, `puredns` - resolver-aware brute force.
- `alterx`, `dnsgen`, `gotator` - permutation generation.
- `httpx` - HTTP/HTTPS probing and content fingerprinting.
- SecLists `Discovery/DNS/` for wordlists.
