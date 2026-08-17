# Firewall Detection Testing Log

**Attack Type**: Firewall & IDS/IPS Detection
**MITRE**: T1590.006 (Gather Victim Network Information: Network Security Appliances)

## Last Updated
<!-- Auto-updated by pentester-executor -->

## Test Matrix

| Row | Target | Test Type | Firewall Detected | Device Type | Bypass Attempted | Notes |
|-----|--------|-----------|-------------------|-------------|------------------|-------|
<!-- Append test results below -->

## Detection Methods

```bash
# ACK scan (firewall mapping)
nmap -sA -p 80,443 TARGET

# Firewall detection via responses
nmap -sS -p- --reason TARGET

# Fragment packets
nmap -sS -f TARGET

# Decoy scan
nmap -sS -D RND:10 TARGET

# Custom packet crafting (hping3)
hping3 -S -p 80 -c 1 TARGET
```

## Common Patterns

### Firewall Signatures
- **Filtered ports**: No response (dropped)
- **Consistent filtering**: Stateful firewall
- **RST responses**: Stateless firewall
- **TTL changes**: Firewall in path

### IDS/IPS Detection
- Connection resets mid-scan
- Scan rate throttling
- Consistent timeouts at certain speeds

### Evasion Techniques
- **Fragmentation (-f)**: Split packets
- **Decoys (-D)**: Hide among fake sources
- **Timing (-T0/-T1)**: Slow scans
- **Source port (--source-port)**: Spoof trusted ports

## Learnings

### Successful Bypasses
<!-- Document evasion techniques that worked -->

### Failed Bypasses
<!-- Techniques that were detected/blocked -->

### Firewall Fingerprints
<!-- Identify specific firewall products -->

## Detection Patterns

### Rate Limit Thresholds
<!-- Document when scans triggered rate limiting -->

### Blocked Techniques
<!-- Track which techniques are consistently blocked -->
