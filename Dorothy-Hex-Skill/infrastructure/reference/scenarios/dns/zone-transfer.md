# DNS Zone Transfer (AXFR / IXFR)

## When this applies

- Target domain has at least one publicly reachable nameserver (NS record).
- Zone transfer is misconfigured to allow unauthenticated AXFR (full zone) or IXFR (incremental) requests from arbitrary clients.
- Goal is to dump every record in the zone — subdomains, mail, internal hostnames — in one query.

## Technique

A zone transfer is a normal DNS protocol operation that replicates an entire DNS zone from a primary to a secondary nameserver. When the primary's ACL is missing or misconfigured (e.g. `allow-transfer { any; };` in BIND), any client can request the zone.

## Steps

### 1. Enumerate authoritative nameservers

```bash
# Get NS records for the zone
dig +short NS target.com

# Or via host
host -t ns target.com

# Or via dnsrecon
dnsrecon -d target.com -t std
```

### 2. Attempt AXFR against each NS

```bash
# Dig AXFR
dig axfr @ns1.target.com target.com
dig axfr @ns2.target.com target.com

# host -l (zone list)
host -l target.com ns1.target.com

# Multi-NS sweep with dnsrecon
dnsrecon -d target.com -t axfr
```

A successful AXFR returns a SOA, all A/AAAA/MX/CNAME/TXT/NS records, and a closing SOA. A blocked attempt returns `Transfer failed` or no answer.

### 3. Try IXFR (incremental) when AXFR fails

Some servers block AXFR but allow IXFR:

```bash
dig ixfr=0 @ns1.target.com target.com
```

### 4. Try secondary / hidden nameservers

Sometimes the primary blocks transfers but a secondary doesn't:

```bash
# Find secondaries via SOA record
dig SOA target.com

# Internal nameservers may be exposed
dig axfr @192.168.1.53 target.com
```

### 5. Reverse zone transfers

```bash
# In-addr.arpa (IPv4)
dig axfr @ns1.target.com 1.168.192.in-addr.arpa

# ip6.arpa (IPv6)
dig axfr @ns1.target.com 0.8.b.d.0.1.0.0.2.ip6.arpa
```

PTR-record zones are often less protected than forward zones — a reverse AXFR can leak the entire IPv4 allocation for an organization.

### 6. Parse the dump

Save the AXFR output, then extract records by type:

```bash
dig axfr @ns1.target.com target.com > axfr.txt

# Subdomains (A/AAAA records)
awk '$4=="A" || $4=="AAAA" {print $1}' axfr.txt | sort -u > subdomains.txt

# Mail servers
grep -E '\sMX\s' axfr.txt

# Text records (often contain SPF, DKIM, internal notes)
grep -E '\sTXT\s' axfr.txt
```

## Verifying success

- AXFR response contains an opening SOA, multiple records, closing SOA.
- Record count > 1 (just SOA = empty zone or transfer denied).
- Records include hostnames not visible in standard recon (internal-*, dev-*, vpn-*, mgmt-*).

## Common pitfalls

- **Most modern providers** (Cloudflare, AWS Route53, Google Cloud DNS) block AXFR by default. Attempt anyway — misconfigured tenants exist.
- **Split-horizon DNS** — internal NS may be reachable from a VPN/internal segment but not from the public internet. Always test from every network position.
- **SOA-only response** = transfer denied. Don't mistake the closing SOA-only reply for a successful empty zone.
- **IXFR requires a serial number** — `ixfr=0` requests the full zone since serial 0 (effectively AXFR).
- **`dig` may time out** for large zones — increase with `+time=30 +tries=1`.
- **TCP fallback** — AXFR uses TCP/53. If only UDP/53 is allowed at the perimeter, transfers fail silently.

## Tools

- dig (primary, all DNS query types)
- host (`-l` for zone list)
- dnsrecon (`-t axfr` does multi-NS sweep)
- fierce (`--domain` includes AXFR attempt)
- dnsenum (full enumeration with AXFR)
- nmap NSE: `dns-zone-transfer.nse`
