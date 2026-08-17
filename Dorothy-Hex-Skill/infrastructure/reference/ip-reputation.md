# IP Reputation Testing Log

**Attack Type**: IP Reputation & Threat Intelligence
**MITRE**: T1590.005 (Gather Victim Network Information: IP Addresses)

## Last Updated
<!-- Auto-updated by pentester-executor -->

## Test Matrix

| Row | IP Address | Service | Reputation | Blocklists | History | Notes |
|-----|------------|---------|------------|------------|---------|-------|
<!-- Append test results below -->

## Check Methods

```bash
# AbuseIPDB lookup
curl -G https://api.abuseipdb.com/api/v2/check \
  --data-urlencode "ipAddress=TARGET" \
  -H "Key: YOUR_API_KEY"

# VirusTotal lookup
curl -X GET "https://www.virustotal.com/api/v3/ip_addresses/TARGET" \
  -H "x-apikey: YOUR_API_KEY"

# Shodan lookup
shodan host TARGET

# Passive DNS (SecurityTrails)
curl -X GET "https://api.securitytrails.com/v1/ips/TARGET" \
  -H "APIKEY: YOUR_API_KEY"
```

## Common Patterns

### Reputation Indicators
- **Clean**: No reports, not in blocklists
- **Suspicious**: Some reports, minimal blocklists
- **Malicious**: Multiple reports, many blocklists

### Historical Data
- Previous compromises
- Associated domains
- Hosting provider patterns
- Geolocation changes

### Service Correlation
- Cloud providers (AWS, Azure, GCP)
- VPN/Proxy exit nodes
- Tor exit nodes
- Known C2 infrastructure

## Learnings

### Clean IPs with Hidden Issues
<!-- Document false negatives in reputation -->

### False Positives
<!-- IPs flagged but actually safe -->

### Provider Patterns
<!-- Hosting provider security patterns -->

## Threat Intelligence

### Known Bad Patterns
<!-- Document patterns of malicious IPs -->

### Compromised Indicators
<!-- Signs an IP may be compromised -->
