# DNS C2 Detection API Reference

## MITRE ATT&CK Mapping

| Technique | ID | Description |
|-----------|----|-------------|
| Application Layer Protocol: DNS | T1071.004 | C2 communication over DNS protocol |
| Exfiltration Over Alternative Protocol | T1048 | Data exfiltration via DNS tunneling |
| Dynamic Resolution: Domain Generation Algorithms | T1568.002 | DGA-based C2 infrastructure |
| Protocol Tunneling | T1572 | Tunneling arbitrary traffic through DNS |
| Encrypted Channel | T1573 | Encrypted C2 payloads in DNS records |

## DNS Record Types Used in C2

| Record Type | Typical C2 Use | Max Data Per Query |
|-------------|----------------|--------------------|
| A | Beacon check-in, small responses (IP-encoded) | 4 bytes (IPv4 address) |
| AAAA | Beacon check-in, slightly larger responses | 16 bytes (IPv6 address) |
| TXT | Command delivery, large payload transfer | ~255 bytes per string, multiple strings |
| CNAME | Data exfiltration in subdomain, response tunneling | ~253 bytes |
| MX | Data tunneling via preference + exchange fields | ~253 bytes |
| NULL | Iodine tunnel primary record type | ~65535 bytes |
| SRV | C2 with port/priority metadata | ~253 bytes |

## Shannon Entropy Thresholds

| Entropy Range | Classification | Typical Source |
|---------------|----------------|----------------|
| 0.0 - 2.0 | Very low | Single-character or trivial labels |
| 2.0 - 3.0 | Normal | Common English-based domain labels |
| 3.0 - 3.5 | Elevated | Long or mixed-case labels, some CDNs |
| 3.5 - 4.0 | Suspicious | Hex-encoded data, base32 encoding, DGA |
| 4.0 - 4.5 | High | DNS tunneling (Iodine, dnscat2, dns2tcp) |
| 4.5+ | Very high | Encrypted or base64-encoded payloads |

## Known Tunneling Tool Signatures

### Iodine
- **Encoding**: Base32, Base64, Base128, Raw
- **Record types**: NULL (primary), TXT, CNAME, MX, A
- **Subdomain pattern**: Long alphanumeric strings (50+ chars)
- **Entropy range**: 3.8 - 4.2
- **Detection**: High query volume to single domain, NULL record type queries

### dnscat2
- **Encoding**: Hex-encoded, encrypted
- **Record types**: TXT, CNAME, MX, A
- **Subdomain pattern**: Hex strings (16+ chars), optional `dnscat.` prefix
- **Entropy range**: 3.5 - 4.5
- **Detection**: Consistent query intervals, hex-only subdomain labels

### dns2tcp
- **Encoding**: Base32
- **Record types**: TXT, KEY
- **Subdomain pattern**: Base32 strings (20+ chars)
- **Entropy range**: 3.6 - 4.0
- **Detection**: KEY record type usage, base32 character set

### Cobalt Strike DNS Beacon
- **Encoding**: Hex-encoded metadata
- **Record types**: A, AAAA, TXT
- **Subdomain pattern**: Short hex strings (8-20 chars)
- **Entropy range**: 3.2 - 4.0
- **Detection**: Regular beacon intervals (default 60s), A-record check-ins followed by TXT downloads

### Sliver DNS C2
- **Encoding**: Base32/custom
- **Record types**: A, TXT
- **Subdomain pattern**: Alphanumeric strings (30+ chars)
- **Entropy range**: 3.5 - 4.2
- **Detection**: High subdomain length variance, mixed record types

## DGA Feature Extraction

| Feature | Description | DGA Indicator |
|---------|-------------|---------------|
| Shannon entropy | Bits per character of domain label | > 3.5 |
| Label length | Character count of domain (excl. TLD) | > 15 unusual |
| Consonant ratio | Consonants / total alphabetic chars | > 0.7 |
| Digit ratio | Digits / total characters | > 0.3 |
| Vowel-consonant ratio | Vowels / consonants | < 0.3 |
| Bigram frequency score | Average English bigram match frequency | < 0.002 |
| Hex character ratio | Hex chars / total chars | > 0.8 |
| Max consecutive consonants | Longest consonant run | > 4 |
| Unique character ratio | Unique chars / total chars | < 0.4 |
| Has dictionary words | Whether label contains English words | No = DGA indicator |

## Beaconing Detection Parameters

| Parameter | Typical Threshold | Description |
|-----------|-------------------|-------------|
| Interval regularity | Jitter < 10% of mean interval | Low variance indicates automated beaconing |
| Min queries | > 50 queries to same domain | Sufficient data for statistical analysis |
| Time span | > 1 hour | Beacon must persist across time |
| Consistent query size | Std dev < 5 bytes | Tunnel payloads have consistent sizes |
| Night-time activity | Queries during 00:00-06:00 | Unusual for legitimate user browsing |
| Single source | 1-3 source IPs per domain | C2 typically from compromised host only |

## Zeek DNS Log Fields

| Field | Type | Forensic Use |
|-------|------|--------------|
| ts | time | Query timestamp |
| uid | string | Connection UID |
| id.orig_h | addr | Source IP (compromised host) |
| id.resp_h | addr | DNS resolver IP |
| query | string | Full queried domain name |
| qtype_name | string | Query type (A, TXT, NULL, CNAME) |
| rcode_name | string | Response code (NOERROR, NXDOMAIN) |
| answers | vector | Response records |
| TTLs | vector | TTL values for answers |
| rejected | bool | Whether query was rejected |

## Suricata EVE DNS Fields

| Field | Type | Forensic Use |
|-------|------|--------------|
| timestamp | string | Event timestamp (ISO 8601) |
| src_ip | string | Source IP |
| dest_ip | string | Destination IP (resolver) |
| dns.type | string | "query" or "answer" |
| dns.rrname | string | Queried domain name |
| dns.rrtype | string | Record type |
| dns.rcode | string | Response code |
| dns.answers | array | Response answer records |
| dns.tx_id | int | Transaction ID |

## Suricata Rules for DNS C2

```
# Detect high-entropy DNS queries (potential tunneling)
alert dns any any -> any any (msg:"ET DNS Potential DNS Tunneling - High Entropy Query"; dns.query; pcre:"/^[a-z0-9]{30,}\./i"; threshold:type threshold, track by_src, count 10, seconds 60; sid:9000001; rev:1;)

# Detect TXT record queries to unusual domains
alert dns any any -> any any (msg:"ET DNS Suspicious TXT Record Query Volume"; dns.query; dns_query; content:"|00 10|"; threshold:type threshold, track by_src, count 20, seconds 60; sid:9000002; rev:1;)

# Detect NULL record queries (Iodine indicator)
alert dns any any -> any any (msg:"ET DNS NULL Record Query - Possible Iodine Tunnel"; dns.query; content:"|00 0a|"; threshold:type threshold, track by_src, count 5, seconds 60; sid:9000003; rev:1;)
```

## Splunk SPL Queries

```spl
# High-entropy DNS subdomain detection
index=dns sourcetype=zeek_dns
| eval subdomain=mvindex(split(query,"."),0)
| eval sub_len=len(subdomain)
| where sub_len > 20
| eval entropy=0
| stats count dc(query) as unique_queries avg(sub_len) as avg_len by src_ip query_type
| where count > 50 AND avg_len > 25

# DNS beaconing detection via standard deviation
index=dns sourcetype=zeek_dns
| sort 0 _time
| streamstats current=f last(_time) as prev_time by src_ip query
| eval interval=_time - prev_time
| stats count avg(interval) as avg_interval stdev(interval) as stdev_interval by src_ip query
| where count > 50 AND stdev_interval < (avg_interval * 0.1)
| table src_ip query count avg_interval stdev_interval
```

## Python API - Key Functions

```python
# Shannon entropy calculation
import math
from collections import Counter

def shannon_entropy(data):
    counter = Counter(data)
    length = len(data)
    return -sum((c / length) * math.log2(c / length) for c in counter.values())

# DGA feature extraction
def extract_features(domain):
    return {
        "length": len(domain),
        "entropy": shannon_entropy(domain),
        "digit_ratio": sum(c.isdigit() for c in domain) / len(domain),
        "consonant_ratio": sum(c in "bcdfghjklmnpqrstvwxyz" for c in domain.lower()) / max(sum(c.isalpha() for c in domain), 1),
    }
```

## References

- Zeek DNS logging: https://docs.zeek.org/en/current/scripts/base/protocols/dns/main.zeek.html
- Suricata DNS rules: https://docs.suricata.io/en/latest/rules/dns-keywords.html
- Iodine DNS tunnel: https://github.com/yarrick/iodine
- dnscat2: https://github.com/iagox86/dnscat2
- dns2tcp: https://github.com/alex-sector/dns2tcp
- Cobalt Strike DNS beacon: https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/listener-setup_dns-beacon.htm
- SANS DNS tunneling detection: https://www.sans.org/white-papers/34152/
- MITRE T1071.004: https://attack.mitre.org/techniques/T1071/004/
- MITRE T1568.002: https://attack.mitre.org/techniques/T1568/002/
