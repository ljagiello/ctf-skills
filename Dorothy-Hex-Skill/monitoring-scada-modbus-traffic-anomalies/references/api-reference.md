# API Reference: Modbus TCP Traffic Anomaly Detector

## Overview

Monitors SCADA/ICS Modbus TCP traffic for unauthorized function codes, register value manipulation, device enumeration, rogue masters, and timing anomalies. Supports pcap analysis and live network capture using Scapy with configurable baselines and register safety limits. For authorized OT/ICS security monitoring only.

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| scapy | >=2.5 | Packet capture, parsing, and Modbus TCP dissection |
| numpy | >=1.24 | Statistical analysis for timing and value anomaly detection |

## CLI Usage

```bash
# Analyze a pcap file
python agent.py --pcap modbus_capture.pcap \
  --authorized-masters 10.1.1.10 10.1.1.11 \
  --authorized-writers 10.1.1.10 \
  --register-limits-file register_limits.json \
  --baseline-file baseline.json \
  --output report.json

# Build a baseline from pcap
python agent.py --pcap normal_traffic.pcap \
  --baseline-mode --baseline-file baseline.json

# Live capture on network interface
python agent.py --interface eth0 --duration 3600 \
  --authorized-masters 10.1.1.10 10.1.1.11 \
  --authorized-writers 10.1.1.10 \
  --baseline-file baseline.json \
  --output report.json
```

## Arguments

| Argument | Required | Description |
|----------|----------|-------------|
| `--pcap` | No* | Path to pcap file containing Modbus TCP traffic |
| `--interface` | No* | Network interface for live packet capture |
| `--duration` | No | Live capture duration in seconds (default: 0 = indefinite) |
| `--authorized-masters` | No | Space-separated list of authorized Modbus master IPs |
| `--authorized-writers` | No | Space-separated list of IPs allowed to send write commands |
| `--register-limits-file` | No | JSON file defining safe value ranges per register address |
| `--baseline-file` | No | Path to load existing or save new baseline profile |
| `--baseline-mode` | No | Build baseline without generating alerts |
| `--output` | No | Output report path (default: `modbus_anomaly_report.json`) |

\* Either `--pcap` or `--interface` is required.

## Register Limits File Format

```json
{
  "40001": {
    "name": "Reactor Temperature Setpoint",
    "min": 50,
    "max": 200,
    "unit": "C",
    "max_rate": 5
  },
  "40010": {
    "name": "Pump Speed",
    "min": 0,
    "max": 3600,
    "unit": "RPM",
    "max_rate": 200
  }
}
```

## Key Classes

### `ModbusAnomalyDetector`
Main detection engine that processes packets and generates alerts.

**Methods:**
- `analyze_packet(src_ip, dst_ip, dst_port, raw_payload, timestamp)` - Analyze a single Modbus TCP packet for anomalies. Returns list of alert dictionaries.
- `generate_report()` - Generate JSON anomaly report sorted by severity.

### `ModbusBaseline`
Maintains statistical profiles of normal Modbus communication patterns.

**Methods:**
- `record(src_ip, dst_ip, function_code, timestamp, registers, values)` - Record a packet observation into the baseline.
- `get_fc_distribution(src_ip, dst_ip)` - Get function code frequency distribution for a master-slave pair.
- `get_timing_stats(src_ip, dst_ip)` - Get mean and standard deviation of inter-packet intervals.
- `get_register_stats(register_addr)` - Get min/max/mean/std for observed register values.
- `save(filepath)` / `load(filepath)` - Persist or restore baseline to/from JSON.

## Key Functions

### `parse_mbap_header(data)`
Parses the 7-byte Modbus Application Protocol header (transaction ID, protocol ID, length, unit ID). Returns None for invalid headers (protocol ID != 0 or insufficient data).

### `parse_modbus_pdu(data)`
Extracts function code, register addresses, values, and exception status from the Modbus PDU. Supports FC 01-06, 15, 16 request parsing.

### `analyze_pcap(pcap_file, detector)`
Loads a pcap file with Scapy, filters for port 502 TCP traffic, and passes each Modbus packet to the detector.

### `live_capture(interface, detector, duration)`
Starts real-time Scapy sniffing on the specified interface with a BPF filter for TCP port 502.

## Alert Types

| Alert | Severity | Trigger |
|-------|----------|---------|
| `ROGUE_MODBUS_MASTER` | CRITICAL | Connection from IP not in authorized masters list |
| `UNAUTHORIZED_MODBUS_WRITE` | CRITICAL | Write function code from IP not in authorized writers list |
| `REGISTER_VALUE_OUT_OF_RANGE` | CRITICAL | Register value outside defined safe operating range |
| `DEVICE_ENUMERATION` | HIGH/CRITICAL | Diagnostic function codes (FC 7, 8, 17, 43) detected |
| `NEW_FUNCTION_CODE` | HIGH | Function code never seen in baseline for this master-slave pair |
| `REGISTER_VALUE_EXCESSIVE_RATE` | HIGH | Register value change exceeds maximum allowed rate |
| `EXCEPTION_BURST` | HIGH | 10+ Modbus exceptions per minute from a single slave |
| `TIMING_ANOMALY` | MEDIUM | Inter-packet interval deviates >3 sigma from baseline mean |
| `MALFORMED_MBAP_HEADER` | MEDIUM | Frame with invalid MBAP header structure |
