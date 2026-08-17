# API Reference: Purdue Model OT Network Segmentation Audit

## Libraries Used

| Library | Purpose |
|---------|---------|
| `scapy` | Network packet analysis and traffic flow validation |
| `requests` | Firewall API calls for rule review |
| `json` | Parse asset inventory and segmentation policy |
| `ipaddress` | Validate IP ranges and subnet assignments |
| `socket` | Port connectivity testing across Purdue levels |

## Installation

```bash
pip install scapy requests
```

## Purdue Model Levels

| Level | Name | Examples | Network Zone |
|-------|------|----------|-------------|
| L0 | Process | Sensors, actuators, valves | Field Network |
| L1 | Basic Control | PLCs, RTUs, safety controllers | Control Network |
| L2 | Area Supervisory | HMIs, SCADA servers, historians | Supervisory Network |
| L3 | Site Operations | Patch servers, AV, AD for OT | Operations Network |
| L3.5 | DMZ | Data diodes, jump servers | Industrial DMZ |
| L4 | Enterprise | ERP, email, business apps | Corporate Network |
| L5 | Internet | Cloud, remote access, third parties | External |

## Core Audit Functions

### Define Asset Zone Mapping
```python
import ipaddress

PURDUE_ZONES = {
    "L0": [ipaddress.ip_network("10.10.0.0/24")],
    "L1": [ipaddress.ip_network("10.10.1.0/24")],
    "L2": [ipaddress.ip_network("10.10.2.0/24")],
    "L3": [ipaddress.ip_network("10.10.3.0/24")],
    "L3.5": [ipaddress.ip_network("10.10.35.0/24")],
    "L4": [ipaddress.ip_network("10.20.0.0/16")],
    "L5": [ipaddress.ip_network("0.0.0.0/0")],
}

def classify_ip(ip):
    addr = ipaddress.ip_address(ip)
    for level, subnets in PURDUE_ZONES.items():
        for subnet in subnets:
            if addr in subnet:
                return level
    return "UNKNOWN"
```

### Validate Allowed Traffic Flows
```python
# Purdue model: traffic should only flow between adjacent levels
ALLOWED_FLOWS = {
    ("L0", "L1"), ("L1", "L0"),
    ("L1", "L2"), ("L2", "L1"),
    ("L2", "L3"), ("L3", "L2"),
    ("L3", "L3.5"), ("L3.5", "L3"),
    ("L3.5", "L4"), ("L4", "L3.5"),
    ("L4", "L5"), ("L5", "L4"),
}

def validate_flow(src_ip, dst_ip):
    src_level = classify_ip(src_ip)
    dst_level = classify_ip(dst_ip)
    flow = (src_level, dst_level)
    return {
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_level": src_level,
        "dst_level": dst_level,
        "allowed": flow in ALLOWED_FLOWS or src_level == dst_level,
        "violation": flow not in ALLOWED_FLOWS and src_level != dst_level,
    }
```

### Analyze Network Traffic for Segmentation Violations
```python
from scapy.all import rdpcap, IP

def analyze_pcap_for_violations(pcap_path):
    packets = rdpcap(pcap_path)
    violations = []
    seen = set()
    for pkt in packets:
        if IP in pkt:
            flow_key = (pkt[IP].src, pkt[IP].dst)
            if flow_key in seen:
                continue
            seen.add(flow_key)
            result = validate_flow(pkt[IP].src, pkt[IP].dst)
            if result["violation"]:
                violations.append(result)
    return violations
```

### Port Connectivity Test Across Levels
```python
import socket

def test_segmentation(src_level_hosts, dst_level_hosts, ports):
    """Test that connections between non-adjacent levels are blocked."""
    results = []
    for src in src_level_hosts:
        for dst in dst_level_hosts:
            for port in ports:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(3)
                    result = sock.connect_ex((dst, port))
                    status = "open" if result == 0 else "closed"
                    sock.close()
                except socket.timeout:
                    status = "filtered"
                results.append({
                    "src": src, "dst": dst, "port": port,
                    "status": status,
                    "expected": "filtered",
                    "pass": status != "open",
                })
    return results
```

### Audit Firewall Rules for DMZ Compliance
```python
def audit_dmz_rules(firewall_rules):
    """Check that L3.5 DMZ properly isolates OT from IT."""
    findings = []
    for rule in firewall_rules:
        src_zone = classify_ip(rule["src_ip"])
        dst_zone = classify_ip(rule["dst_ip"])

        # Direct L4->L2 or L4->L1 bypasses DMZ
        if src_zone == "L4" and dst_zone in ("L0", "L1", "L2"):
            findings.append({
                "rule_id": rule["id"],
                "issue": f"Direct {src_zone}->{dst_zone} bypasses DMZ",
                "severity": "critical",
                "remediation": "Route through L3.5 DMZ",
            })

        # L5 direct to any OT level
        if src_zone == "L5" and dst_zone in ("L0", "L1", "L2", "L3"):
            findings.append({
                "rule_id": rule["id"],
                "issue": f"Internet ({src_zone}) directly reaches OT ({dst_zone})",
                "severity": "critical",
                "remediation": "Block all direct internet-to-OT traffic",
            })
    return findings
```

## Output Format

```json
{
  "audit_date": "2025-01-15",
  "total_flows_analyzed": 15420,
  "segmentation_violations": 12,
  "critical_violations": 3,
  "violations": [
    {
      "src_ip": "10.20.5.100",
      "dst_ip": "10.10.1.50",
      "src_level": "L4",
      "dst_level": "L1",
      "violation": true,
      "severity": "critical",
      "detail": "Enterprise host directly accessing PLC network"
    }
  ],
  "dmz_compliance": {
    "data_diode_present": true,
    "jump_server_hardened": true,
    "direct_ot_it_paths": 0
  }
}
```
