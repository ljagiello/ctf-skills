# ICMP Scan Testing Log

**Attack Type**: ICMP Echo/Discovery
**MITRE**: T1018 (Remote System Discovery)

## Last Updated
<!-- Auto-updated by pentester-executor -->

## Test Matrix

| Row | Target Range | Command | Hosts Up | Duration | Result | Notes |
|-----|--------------|---------|----------|----------|--------|-------|
<!-- Append test results below -->

## Command Templates

```bash
# ICMP ping sweep
nmap -sn -PE TARGET_RANGE

# Multiple ICMP types
nmap -sn -PE -PP -PM TARGET_RANGE

# With ARP (local network)
nmap -sn -PR TARGET_RANGE

# Disable ping (assume all up)
nmap -Pn TARGET
```

## Common Patterns

### Network Discovery
- Use ping sweep for large ranges first
- Combine ICMP echo (-PE), timestamp (-PP), netmask (-PM)
- Local networks: ARP ping (-PR) faster and more reliable

### Firewall Bypass
- Many networks block ICMP
- Use `-Pn` to skip ping and scan anyway
- Combine with TCP SYN to port 80/443 for discovery

### ICMP Types
- **Echo (Type 8)**: Standard ping
- **Timestamp (Type 13)**: Time sync
- **Address Mask (Type 17)**: Subnet info

## Learnings

### Successful Techniques
<!-- Add entries as tests are performed -->

### Failed Techniques
<!-- Add entries when techniques fail -->

### Network Characteristics
<!-- Document network behavior patterns -->

## Performance Data

### Discovery Rate
<!-- Track hosts found per scan type -->

### False Negatives
<!-- Document hosts missed by ICMP but found by other methods -->
