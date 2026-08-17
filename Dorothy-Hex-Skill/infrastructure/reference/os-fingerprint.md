# OS Fingerprinting Testing Log

**Attack Type**: Operating System Detection
**MITRE**: T1082 (System Information Discovery)

## Last Updated
<!-- Auto-updated by pentester-executor -->

## Test Matrix

| Row | Target | Command | OS Detected | Accuracy | Method | Notes |
|-----|--------|---------|-------------|----------|--------|-------|
<!-- Append test results below -->

## Command Templates

```bash
# Basic OS detection
nmap -O TARGET

# Aggressive OS detection
nmap -O --osscan-guess TARGET

# OS + version detection
nmap -A TARGET

# TTL-based detection (passive)
ping TARGET -c 1
# TTL 64 = Linux/Unix, 128 = Windows, 255 = Network device
```

## Common Patterns

### Active Fingerprinting (nmap -O)
- Analyzes TCP/IP stack behavior
- Requires at least 1 open and 1 closed port
- Best with root privileges

### Passive Indicators
- **TTL Values**: 64 (Linux), 128 (Windows), 255 (Cisco)
- **Window Size**: OS-specific TCP window
- **TCP Options**: Ordering reveals OS

### Service-Based OS Detection
- **SMB**: Windows version
- **SSH Banner**: Linux distro hints
- **HTTP Server**: Often reveals OS

## Learnings

### Successful Techniques
<!-- Add entries as tests are performed -->

### Failed Techniques
<!-- Add entries when techniques fail -->

### OS-Specific Behaviors
<!-- Document OS characteristics discovered -->

## Pattern Recognition

### TTL Patterns
<!-- Track TTL values observed -->

### Service Combinations
<!-- Document service patterns that indicate specific OS -->
