# Reconnaissance Principles

Decision tree and core principles for domain assessment and web application mapping. Reconnaissance is the foundation of every engagement: a thorough surface map shortens every later phase.

## Core Principles

1. **Passive before active.** Cert transparency, DNS history, and search engines give breadth without touching the target.
2. **Live before deep.** Filter discovered hosts down to those that resolve and respond before running heavy scans.
3. **Run OSINT in parallel.** Repository enumeration, secret scanning, and employee footprinting are independent and feed back into the surface map.
4. **Save raw output.** Every tool invocation should produce a file under `recon/raw/` or `recon/inventory/`. Re-running scans is expensive.
5. **Record what was tested vs. discovered.** A wordlist that returned 0 hits is still a data point.
6. **Probe response shape, not just status code.** Web apps often return 200 for unknown paths; size, content hash, and timing reveal real differences.

## Decision Tree

```
Single domain or hostname given?
  -> subdomain-enumeration  (passive first, active brute as needed)

IP / netblock given?
  -> port-scanning  (focused profile based on archetype)

Subdomain or vhost suspected?
  -> vhost-enumeration  (Host-header fuzzing against IP)

Web app reachable on known port?
  -> http-header-recon       (banners, server hints)
  -> ssl-cert-recon          (SAN extraction for more vhosts)
  -> api-endpoint-discovery  (swagger, robots, sitemap, JS routes)
  -> wordlist-strategy       (technology-aware path bruting)
  -> git-leak-discovery      (.git, .svn, .DS_Store, *.bak)

Bot protection blocking automated requests?
  -> reference/anti-bot-bypass.md
```

## Archetype-Driven Scanning

Recognise the target archetype before choosing scan depth:

| Archetype | Indicator | First-pass scan |
|-----------|-----------|-----------------|
| Windows DC | 53/88/135/139/389/445 open | Focused 13-port AD scan |
| Linux web tier | 80/443/22 open | Top-1000 + service detect |
| Mixed enterprise | Multiple hosts, mixed OS | masscan top-100 across range, then nmap -sV per host |
| Serverless / CDN-fronted | Cloudflare, AWS, etc. on edge | Origin discovery first; surface scan rarely useful |
| Mobile API backend | App download links visible | Pull and decompile client; API endpoints live in the binary |

## Triage Order

For most web targets, this ordering minimises wasted effort:

1. DNS + cert transparency for subdomain breadth.
2. Port scan the live hosts.
3. HTTP header + cert SAN inspection on every web service found.
4. VHost fuzz when SAN wildcard or `X-*` headers leak hostnames.
5. Path brute with technology-aware wordlists once stack is fingerprinted.
6. API discovery (swagger, JS source review) on each web app.
7. Git/SVN leak check on every web root before moving on.

## Output Layout

```
recon/
  inventory/    JSON: subdomains.json, ports.json, endpoints.json, apis.json
  analysis/     MD: attack-surface.md, testing-checklist.md
  raw/          Tool outputs: nmap-*.xml, ffuf-*.json, subfinder-*.txt
```

Inventory files should always be valid JSON so downstream tools can ingest them without regex-parsing.

## Anti-Patterns

- Running `-p-` full-port scan on every host before triaging archetype.
- Brute-forcing subdomains with a 5M-line wordlist before checking certificate transparency.
- Trusting status code alone for path discovery on apps that return 200 for unknown routes.
- Running active scans before passive collection has completed.
- Discarding raw tool output after parsing it once.

## Related References

- `reference/anti-bot-bypass.md` - bypass techniques when automated requests are blocked.
- `reference/scenarios/` - one file per recon scenario with concrete commands.
