# UDP Scan Testing Log

**Attack Type**: UDP Port Scanning
**MITRE**: T1046 (Network Service Discovery)

## Last Updated
<!-- Auto-updated by pentester-executor -->

## Test Matrix

| Row | Target | Command | Ports Found | Duration | Result | Notes |
|-----|--------|---------|-------------|----------|--------|-------|
<!-- Append test results below -->

## Command Templates

```bash
# Top 100 UDP ports
nmap -sU --top-ports 100 TARGET

# Specific UDP services
nmap -sU -p 53,161,162,500 TARGET

# UDP with version detection
nmap -sU -sV --top-ports 20 TARGET

# Fast UDP scan
nmap -sU -T4 --max-retries 1 --top-ports 100 TARGET
```

## Common Patterns

### UDP Challenges
- Much slower than TCP (no handshake)
- Open ports often don't respond (marked open|filtered)
- Version detection helps confirm open ports

### High-Value UDP Services
- **53**: DNS
- **161/162**: SNMP
- **123**: NTP
- **500**: IPSec IKE
- **1434**: MS-SQL Monitor

### Speed Optimization
- Scan top 100 ports only
- Use `--max-retries 1` for speed
- Increase timing with `-T4`
- Focus on specific service ports

## Learnings

### Successful Techniques
<!-- Add entries as tests are performed -->

### Failed Techniques
<!-- Add entries when techniques fail -->

### Service Identification
<!-- Document which services were successfully identified -->

## Performance Data

### Scan Times
<!-- Track average scan durations for different port counts -->

### Confirmation Methods
<!-- Document techniques that confirmed open UDP ports -->
