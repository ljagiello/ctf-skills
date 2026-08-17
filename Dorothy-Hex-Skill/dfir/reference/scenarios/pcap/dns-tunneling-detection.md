# DNS Tunneling Detection

## When this applies

You suspect data exfiltration or C2 channel hidden in DNS traffic. Indicators include: unusual sustained DNS load, very long subdomain labels, high TXT record query volume, queries to a single authoritative domain, or NULL/CNAME records with binary-looking payloads.

## Technique

DNS tunneling abuses the recursive resolver chain by encoding data in subdomain labels (egress) and TXT/CNAME/NULL responses (ingress). Detection focuses on volumetric and entropy anomalies: query rate per domain, subdomain length distribution, character-frequency entropy, and rare record types. Iodine, dnscat2, and DET use distinct fingerprints.

## Steps

1. Per-second-level-domain query counts:
   ```bash
   tshark -r capture.pcap -Y "dns.flags.response == 0" -T fields -e dns.qry.name | \
     awk -F. '{print $(NF-1)"."$NF}' | sort | uniq -c | sort -rn | head
   ```
   Tunneled traffic concentrates queries on one domain (often hundreds/thousands).
2. Subdomain length distribution — tunneling pads to ~63 chars:
   ```bash
   tshark -r capture.pcap -Y "dns.flags.response == 0" -T fields -e dns.qry.name | \
     awk '{print length($1)}' | sort | uniq -c | sort -rn | head
   ```
3. Entropy check on the deepest label:
   ```python
   import math
   from collections import Counter
   def entropy(s):
       c = Counter(s); n = len(s)
       return -sum((v/n) * math.log2(v/n) for v in c.values())
   # Run on first label of each query name; > 4.0 is suspicious for short strings
   ```
4. Rare record types — TXT or NULL queries from internal hosts:
   ```bash
   tshark -r capture.pcap -Y "dns.qry.type == 16 or dns.qry.type == 10" \
     -T fields -e ip.src -e dns.qry.name -e dns.qry.type
   ```
   Type 16 = TXT, 10 = NULL (used by iodine), 33 = SRV (rare from clients).
5. Fingerprint specific tools:
   - **iodine**: queries with structure `<base32>.<domain>` and CNAME responses.
   - **dnscat2**: TXT queries; payload starts with hex session ID + sequence number.
   - **DET**: short labels but very high frequency, fixed payload size.
6. Reconstruct payload (after identifying the encoding):
   ```python
   # base32 example
   import base64
   names = [...]  # collected query names in order
   payload = b"".join(base64.b32decode(n.split(".")[0].upper() + "="*((-len(n.split(".")[0]))%8)) for n in names)
   ```
7. Decode hostnames captured from a log corpus (no PCAP). DNS-tunneled exfil often lands in DNS query logs, web access logs, or aggregator dumps as hostnames matching `<long-label>.<short-label>.<TLD>`. Decode the long label of **every** record — flags, credentials, and `/etc/passwd` fragments are routinely hidden in 100+ entry haystacks among legitimate-looking entries:
   ```python
   # log_exfil_decode.py
   import base64, json, re, sys
   recs = json.load(open(sys.argv[1]))                 # log dump as JSON list
   pat = re.compile(r"([A-Za-z0-9+/=_-]{16,})\.[A-Za-z0-9-]{1,8}\.[A-Za-z]{2,8}$")
   for r in recs:
       host = r.get("hostname") or r.get("query") or r.get("url", "")
       m = pat.search(host)
       if not m: continue
       lbl = m.group(1)
       for fn in (base64.b64decode, base64.b32decode,
                  lambda b: base64.urlsafe_b64decode(b + b"=" * ((-len(b)) % 4))):
           try:
               out = fn(lbl.encode() + b"=" * ((-len(lbl)) % 4))
               if 0x20 <= out[0] <= 0x7e:              # printable first byte
                   print(host, "→", out[:120])
                   break
           except Exception:
               pass
   ```
   Decode the **entire** set, not a sample — operators sometimes interleave decoy entries with the real payload to defeat spot-checks. Common encoding: base64 standard, base64 URL-safe, base32 (iodine), hex.

## Verifying success

- One domain dominates query volume (≥80% of one host's DNS).
- Mean subdomain length > 30 with low variance (vs. normal traffic ~12 chars).
- Decoded payload yields readable structure (HTTP request, JSON, command).

## Common pitfalls

- Antivirus DNS-based reputation lookups (e.g. McAfee TrustedSource, OpenDNS) generate long subdomain queries — easily mistaken for tunneling. Verify the domain owner before alerting.
- CDN edge resolution can also produce many queries to one domain. Look at *length and entropy* together, not volume alone.
- Some tunneling tools fragment across mixed record types — restrict your filter too tightly and you lose half the payload.
- DoH (DNS-over-HTTPS) won't show in this filter; check for unusual TLS to known DoH endpoints (`1.1.1.1`, `8.8.8.8` over 443) instead.

## Tools

- `tshark` — `dns.qry.name`, `dns.qry.type`, `dns.flags.response`
- `tcpdump -r capture.pcap -nn 'udp port 53'`
- `dns2tcp` / `iodine` / `dnscat2` source — verify reconstruction by running the matching client
- `passivedns` / `dnstop` — long-term DNS volumetric monitoring
- `RITA` (Active Countermeasures) — automated beacon and tunneling scoring
