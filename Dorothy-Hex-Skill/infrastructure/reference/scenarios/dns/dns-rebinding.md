# DNS Rebinding

## When this applies

- Target is a service that trusts the request's `Host` header / Origin (often local services bound to 127.0.0.1, RFC1918, or cloud metadata IPs).
- The target performs an SSRF-like fetch or runs in a browser context where the user's browser will obey DNS responses controlled by the attacker.
- Goal is to bypass same-origin policy (browser) or SSRF allow-listing (server) by switching the DNS answer between two IPs after the first resolution.

## Technique

Set up a DNS server that returns a low-TTL A record pointing first at a public IP (passes SSRF allow-list / browser fetches initial page), then switches on the next query to an internal IP (127.0.0.1, 169.254.169.254, RFC1918). The target re-resolves and now sends requests to the internal address while still using the original hostname (which passes Host-based ACLs).

## Steps

### 1. Identify a vulnerable consumer

Two common shapes:

**Browser-side**: a JavaScript app served from `app.attacker.com` makes a `fetch('http://app.attacker.com/admin')`. Same-origin succeeds, but `fetch()` actually hits whatever IP the browser cached for `app.attacker.com` — by then 127.0.0.1.

**Server-side SSRF with allow-list**: server fetches a URL but checks `urlparse(url).hostname` against an allow-list. Allow-listing the hostname doesn't prevent the second DNS lookup from returning a different IP.

### 2. Set up a rebinding DNS server

```bash
# Singularity of Origin — purpose-built rebinding framework
git clone https://github.com/nccgroup/singularity
cd singularity && go build ./...
./singularity -HTTPSCertificate cert.pem -HTTPSCertificateKey key.pem
```

Or roll your own with a low-TTL bind/dnsmasq:

```python
# Minimal Python rebinder using dnslib
from dnslib import DNSRecord, RR, A
from dnslib.server import DNSServer, BaseResolver

class Rebinder(BaseResolver):
    state = {}
    def resolve(self, request, handler):
        qname = str(request.q.qname)
        n = self.state.get(qname, 0) + 1
        self.state[qname] = n
        ip = "203.0.113.5" if n == 1 else "127.0.0.1"   # flip on 2nd query
        reply = request.reply()
        reply.add_answer(RR(qname, rdata=A(ip), ttl=0))
        return reply

DNSServer(Rebinder(), port=53, address="0.0.0.0").start()
```

Set TTL = 0 or 1 second. Some browsers cap minimum TTL; pinning bypasses are documented per-browser (e.g. Chrome: 1 minute floor unless private-network ACL changes).

### 3. Trigger the consumer

For browser exploits: get the victim to load a page on the attacker domain. The page makes XHR/fetch to the rebinding hostname after a delay (`setTimeout` ~5–60s) longer than the cache.

For server-side SSRF: send a request whose URL uses the rebinding hostname. The server resolves once for the allow-list check, then resolves again when actually fetching.

### 4. Common rebinding targets

- **127.0.0.1** — admin panels of local services (CUPS, transmission-daemon, Plex, dev servers)
- **169.254.169.254** — cloud metadata (AWS IMDSv1, GCP metadata, Azure IMDS)
- **10.0.0.0/8, 172.16/12, 192.168/16** — internal corporate ranges
- **fd00::/8** — IPv6 ULA equivalents

### 5. Defenses to test

- DNS pinning at OS / browser level
- HTTP `Host` validation (rebinding leaves Host = original hostname; if the local service requires `Host: localhost`, it may reject)
- Private Network Access (PNA) headers in modern Chrome/Edge

## Verifying success

- DNS query log shows two lookups for the same hostname: first → public IP, second → internal IP.
- HTTP request log on the internal target shows traffic from the consumer with the original `Host:` header.
- Response body confirms internal-only data (e.g. AWS IMDS role credentials, admin UI HTML).

## Common pitfalls

- **Browsers cache DNS aggressively**. Chrome's minimum TTL is ~1 minute even for `TTL=0`; force eviction with multi-tab tricks or wait the full minute.
- **`Host:` header leaks attacker domain** — if the internal service validates Host strictly (e.g. requires `localhost` or `metadata.google.internal`), rebinding alone won't work; pair with Host header injection.
- **CORS preflight** for non-simple requests reveals the public IP; pre-cache the preflight before rebinding.
- **DNS-over-HTTPS / DNS-over-TLS** clients use a fixed resolver and ignore the attacker's authoritative server unless they query through a recursive that respects TTL. Test the actual resolver path.
- **Private Network Access** (Chrome 117+) blocks public-origin pages from making requests to private IPs without an explicit preflight permission header on the response.
- **AWS IMDSv2 requires a token** obtained via PUT `http://169.254.169.254/latest/api/token` with `X-aws-ec2-metadata-token-ttl-seconds`. Pure DNS rebinding fails against IMDSv2; only IMDSv1 is vulnerable.

## Tools

- Singularity of Origin (NCC Group rebinding framework, browser-driven)
- whonow (small Python rebinding DNS server)
- dnslib (build a custom rebinder)
- rbndr.us (public rebinding service for testing)
