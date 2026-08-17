# Denial of Service Assessment

Assessing resilience against resource exhaustion and amplification attacks.

## Techniques
- **Network-layer**: SYN flood, UDP flood, ICMP flood
- **Application-layer**: HTTP flood, Slowloris, RUDY
- **Amplification**: DNS, NTP, SSDP, memcached reflection
- **Protocol abuse**: TCP state exhaustion

## Tools
- hping3, LOIC (authorized only), Slowloris, ab (Apache Bench)

## Quick Commands
```bash
# SYN flood test (authorized)
hping3 -S --flood -V -p 80 target

# Slowloris
slowloris target -p 80 -s 200

# HTTP load test
ab -n 10000 -c 100 http://target/
```

## Methodology
1. Baseline normal traffic patterns
2. Test network-layer resilience (with authorization)
3. Test application-layer handling
4. Assess rate limiting and WAF effectiveness
5. Document thresholds and failure points

**MITRE**: T1498, T1499 | **CWE**: CWE-400 | **CAPEC**: CAPEC-125
