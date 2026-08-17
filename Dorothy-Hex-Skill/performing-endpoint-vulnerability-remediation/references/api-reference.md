# API Reference — Performing Endpoint Vulnerability Remediation

## Libraries Used

| Library | Purpose |
|---------|---------|
| `csv` | Parse vulnerability scan CSV exports (Nessus, Qualys, Rapid7) |
| `subprocess` | Check installed Windows patches via `wmic qfe` and PowerShell |
| `socket` | Validate port-based remediation via TCP connect |
| `json` | Read/write remediation plans and reports |
| `argparse` | CLI argument parsing for scan file and host parameters |
| `datetime` | Track patch dates and SLA deadlines |

## CLI Interface

```bash
python agent.py parse --scan-file scan.csv
python agent.py patches
python agent.py validate --host 10.0.0.1 --port 445
python agent.py report --scan-file scan.csv [--output plan.json]
```

## Core Functions

### `parse_scan_report(csv_file)` — Parse and prioritize vulnerabilities by severity
```python
def parse_scan_report(csv_file):
    """Parse Nessus/Qualys CSV export, group by host, sort by severity."""
    with open(csv_file, newline="") as f:
        reader = csv.DictReader(f)
        vulns = []
        for row in reader:
            vulns.append({
                "host": row.get("Host", row.get("IP")),
                "plugin_id": row.get("Plugin ID", row.get("QID")),
                "severity": row.get("Risk", row.get("Severity", "Info")),
                "name": row.get("Name", row.get("Title")),
                "cve": row.get("CVE", ""),
                "solution": row.get("Solution", row.get("Fix", "")),
            })
    severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
    return sorted(vulns, key=lambda v: severity_order.get(v["severity"], 5))
```

### `check_windows_patches()` — List installed Windows hotfixes via WMIC
```python
def check_windows_patches():
    """Query installed patches on a Windows endpoint."""
    result = subprocess.run(
        ["wmic", "qfe", "get", "HotFixID,InstalledOn,Description", "/format:csv"],
        capture_output=True, text=True, timeout=30,
    )
    patches = []
    for line in result.stdout.strip().split("\n")[1:]:
        parts = line.strip().split(",")
        if len(parts) >= 4:
            patches.append({
                "hotfix_id": parts[1],
                "description": parts[2],
                "installed_on": parts[3],
            })
    return patches
```

### `validate_remediation(host, port)` — TCP connect to verify port closure
```python
def validate_remediation(host, port):
    """Verify that a vulnerable port has been closed after remediation."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5)
    try:
        result = sock.connect_ex((host, int(port)))
        return {
            "host": host,
            "port": port,
            "status": "open" if result == 0 else "closed",
            "remediated": result != 0,
        }
    finally:
        sock.close()
```

### `generate_remediation_report(scan_file, output)` — Group vulns by host for remediation
```python
def generate_remediation_report(scan_file, output=None):
    """Generate a prioritized remediation plan from scan results."""
    vulns = parse_scan_report(scan_file)
    by_host = {}
    for v in vulns:
        by_host.setdefault(v["host"], []).append(v)

    report = {
        "total_vulns": len(vulns),
        "hosts_affected": len(by_host),
        "by_severity": {},
        "remediation_plan": [],
    }
    for severity in ["Critical", "High", "Medium", "Low"]:
        count = sum(1 for v in vulns if v["severity"] == severity)
        report["by_severity"][severity] = count

    for host, host_vulns in sorted(by_host.items()):
        report["remediation_plan"].append({
            "host": host,
            "vuln_count": len(host_vulns),
            "critical": sum(1 for v in host_vulns if v["severity"] == "Critical"),
            "patches": [v["name"] for v in host_vulns[:10]],
        })

    if output:
        with open(output, "w") as f:
            json.dump(report, f, indent=2)
    return report
```

## Output Format

```json
{
  "total_vulns": 245,
  "hosts_affected": 42,
  "by_severity": {
    "Critical": 8,
    "High": 35,
    "Medium": 112,
    "Low": 90
  },
  "remediation_plan": [
    {
      "host": "10.0.0.50",
      "vuln_count": 12,
      "critical": 2,
      "patches": ["MS17-010: EternalBlue", "CVE-2024-21887: Ivanti RCE"]
    }
  ]
}
```

## Dependencies

No external packages — Python standard library only.
