# SYN Scan Testing Log

**Attack Type**: TCP SYN Scan (Stealth Scan)
**MITRE**: T1046 (Network Service Discovery)

## Last Updated
<!-- Auto-updated by pentester-executor -->

## Test Matrix

| Row | Target | Command | Ports Found | Duration | Result | Notes |
|-----|--------|---------|-------------|----------|--------|-------|
<!-- Append test results below -->

## Command Templates

```bash
# Fast SYN scan (top 1000 ports)
nmap -sS -T4 TARGET

# Full port range
nmap -sS -p- --min-rate 10000 TARGET

# With service detection
nmap -sS -sV -p- TARGET

# Specific port ranges
nmap -sS -p 1-1024,8000-9000 TARGET
```

## Common Patterns

### Fast Initial Discovery
- Use `-T4` or `--min-rate 10000` for speed
- Top 1000 ports first, then full range if needed
- Reduces scan time from hours to minutes

### Stealth Considerations
- SYN scan requires root/sudo
- Half-open connection (no full handshake)
- Less likely to trigger IDS than TCP connect

### Port State Interpretation
- **open**: SYN/ACK received
- **closed**: RST received
- **filtered**: No response (firewall)

## Learnings

<!-- Document what worked/failed during tests -->

### Successful Techniques
<!-- Add entries as tests are performed -->

### Failed Techniques
<!-- Add entries when techniques fail -->

### WAF/IDS Triggers
<!-- Document when scans were detected/blocked -->

## Performance Data

### Scan Speed Benchmarks
<!-- Track average scan times for optimization -->

### Rate Limiting Observations
<!-- Document when rate limiting was encountered -->
