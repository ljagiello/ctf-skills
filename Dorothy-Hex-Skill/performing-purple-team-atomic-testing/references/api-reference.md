# API Reference: Purple Team Atomic Testing Agent

## Overview

Parses Atomic Red Team YAML test definitions, correlates execution logs with SIEM detection results, generates MITRE ATT&CK Navigator heatmap layers, computes per-tactic coverage gap analysis, suggests Sigma rules for blind spot techniques, and produces PowerShell retest scripts. Supports the full purple team detection validation loop: execute atomic test, query SIEM for alerts, identify blind spots, write detection rules, and re-validate.

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| pyyaml | >=6.0 | Parsing Atomic Red Team YAML test definitions |

## CLI Usage

```bash
# Full analysis: report + navigator layer + sigma suggestions + retest script
python agent.py --mode all \
  --atomics-path C:\AtomicRedTeam\atomics \
  --log-dir C:\AtomicRedTeam\logs \
  --detections detection_results.json

# Generate only the coverage gap report
python agent.py --mode report \
  --atomics-path C:\AtomicRedTeam\atomics \
  --log-dir C:\AtomicRedTeam\logs \
  --output-report coverage_report.json

# Generate only the ATT&CK Navigator layer
python agent.py --mode navigator \
  --atomics-path C:\AtomicRedTeam\atomics \
  --log-dir C:\AtomicRedTeam\logs \
  --detections detection_results.json \
  --output-layer coverage_layer.json \
  --layer-name "Q1 2026 Purple Team Coverage"

# Generate Sigma rule suggestions for blind spots
python agent.py --mode sigma \
  --atomics-path C:\AtomicRedTeam\atomics \
  --log-dir C:\AtomicRedTeam\logs \
  --detections detection_results.json \
  --output-sigma sigma_suggestions.json

# Generate PowerShell retest script for blind spots
python agent.py --mode retest \
  --atomics-path C:\AtomicRedTeam\atomics \
  --log-dir C:\AtomicRedTeam\logs \
  --detections detection_results.json \
  --output-retest retest_blind_spots.ps1
```

## Arguments

| Argument | Required | Description |
|----------|----------|-------------|
| `--atomics-path` | No | Path to Atomic Red Team atomics directory (default: `C:\AtomicRedTeam\atomics`) |
| `--log-dir` | No | Path to atomic test execution log directory (default: `C:\AtomicRedTeam\logs`) |
| `--detections` | No | Path to SIEM detection validation results JSON export |
| `--mode` | No | Output mode: `report`, `navigator`, `sigma`, `retest`, or `all` (default: `all`) |
| `--output-layer` | No | Output path for ATT&CK Navigator layer JSON (default: `navigator_layer.json`) |
| `--output-report` | No | Output path for coverage gap report JSON (default: `coverage_report.json`) |
| `--output-sigma` | No | Output path for Sigma rule suggestions JSON (default: `sigma_suggestions.json`) |
| `--output-retest` | No | Output path for PowerShell retest script (default: `retest_blind_spots.ps1`) |
| `--layer-name` | No | Name for the ATT&CK Navigator layer (default: `Purple Team Coverage`) |

## Key Functions

### `load_atomics_inventory(atomics_path)`
Parses all Atomic Red Team YAML files (`T*/T*.yaml`) from the atomics directory. Returns a dictionary keyed by technique ID containing technique name, test count, supported platforms, executor types, and per-test details (name, description, platforms, executor, elevation required, has cleanup).

### `load_execution_logs(log_dir)`
Loads atomic test execution logs from JSON files matching `T*_*.json` pattern. Tracks per-technique execution count, success/failure counts, hostnames, and last execution timestamp.

### `load_detection_results(detection_file)`
Loads SIEM detection validation results from a JSON file. Each entry maps a technique ID to detection status (detected boolean), alert count, rule name, confidence level (high/medium/low), data sources, SIEM query, and false positive rate.

### `compute_coverage_report(inventory, execution_logs, detection_results)`
Generates a comprehensive coverage gap analysis report including:
- **Executive summary**: total techniques with atomics, executed, detected, and coverage percentages
- **Per-tactic breakdown**: 14 ATT&CK tactics with in-scope techniques, available atomics, executed count, detected count, and detection coverage percentage
- **Gap classification**: blind spots (executed but not detected), not tested (atomics available but not run), and low confidence (detected but unreliable)
- **Prioritized recommendations**: CRITICAL (write rules for blind spots), HIGH (improve low-coverage tactics), MEDIUM (expand testing, tune rules)

### `generate_navigator_layer(inventory, execution_logs, detection_results, layer_name)`
Produces an ATT&CK Navigator v4.5 layer JSON file compatible with `https://mitre-attack.github.io/attack-navigator/`. Color-codes techniques:
- Green (`#66bb6a`): Detected with high/medium confidence
- Yellow (`#ffeb3b`): Detected with low confidence (partial)
- Red (`#ff6666`): Blind spot -- tested but no detection
- Gray (`#d3d3d3`): Not tested -- atomics available

Each technique entry includes metadata (tests available, platforms, executed status, detected status, last execution time, total runs).

### `suggest_sigma_rules(blind_spots)`
Generates Sigma rule stubs for blind spot techniques using built-in templates. Covers common techniques including T1059.001 (PowerShell), T1003.001 (LSASS), T1547.001 (Registry Run Keys), T1053.005 (Scheduled Task), T1070.004 (File Deletion), T1218.011 (Rundll32), and T1105 (Ingress Tool Transfer). Returns rule YAML with title, logsource, detection selection, and ATT&CK tags. Techniques without templates return a manual creation note with ATT&CK reference link.

### `print_coverage_report(report)`
Prints a formatted coverage report to stdout including executive summary, per-tactic coverage table with percentages, critical blind spots list, low-confidence detections, and prioritized recommendations.

### `generate_powershell_test_script(blind_spots, output_path)`
Generates a PowerShell script that re-executes all blind spot techniques using Invoke-AtomicRedTeam with prerequisite checks, execution logging, 30-second SIEM ingestion delays between tests, and cleanup commands. Includes an authorized-testing disclaimer header.

## Detection Results JSON Schema

The `--detections` input file should be a JSON array or object with a `results` key, where each entry contains:

```json
{
  "technique_id": "T1059.001",
  "detected": true,
  "alert_count": 3,
  "rule_name": "Suspicious PowerShell Execution",
  "confidence": "high",
  "data_sources": ["powershell", "sysmon"],
  "siem_query": "index=windows EventCode=4104",
  "false_positive_rate": 0.05
}
```

## ATT&CK Tactic Coverage

The agent tracks 14 ATT&CK Enterprise tactics with top techniques per tactic:

| Tactic | Tactic ID | Techniques Tracked |
|--------|-----------|-------------------|
| Execution | TA0002 | T1059.001, T1059.003, T1047, T1053.005, and 7 more |
| Persistence | TA0003 | T1547.001, T1136.001, T1543.003, T1197, and 8 more |
| Privilege Escalation | TA0004 | T1548.002, T1134.001, T1068, T1055.001, and 2 more |
| Defense Evasion | TA0005 | T1070.001, T1218.011, T1027, T1562.001, and 8 more |
| Credential Access | TA0006 | T1003.001, T1003.002, T1110.001, T1558.003, and 7 more |
| Discovery | TA0007 | T1082, T1083, T1087.001, T1016, and 7 more |
| Lateral Movement | TA0008 | T1021.001, T1021.002, T1021.003, T1570, and 2 more |
| Collection | TA0009 | T1005, T1039, T1074.001, T1113, and 2 more |
| Command and Control | TA0011 | T1071.001, T1105, T1573.001, T1219, and 3 more |
| Exfiltration | TA0010 | T1041, T1048.003, T1567.002 |
| Impact | TA0040 | T1485, T1486, T1489, T1490, T1491.002 |

## Sigma Rule Templates

Built-in templates are provided for high-priority blind spot techniques:

| Technique | Sigma Title | Event Source | Event ID |
|-----------|-------------|-------------|----------|
| T1059.001 | Suspicious PowerShell Script Block Execution | PowerShell | 4104 |
| T1003.001 | LSASS Memory Access for Credential Dumping | Sysmon | 10 |
| T1547.001 | Registry Run Key Persistence | Sysmon | 13 |
| T1053.005 | Scheduled Task Created via Command Line | Security | 4698 |
| T1070.004 | Indicator Removal - File Deletion | Sysmon | 23 |
| T1218.011 | Suspicious Rundll32 Execution | Sysmon | 1 |
| T1105 | Ingress Tool Transfer via Common Utilities | Sysmon | 1 |
