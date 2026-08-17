# API Reference: BLE Attack Detection Agent

## Overview

Scans, enumerates, and analyzes Bluetooth Low Energy devices for security vulnerabilities including weak pairing, replay attack susceptibility, insecure GATT permissions, advertising spoofing, and Man-in-the-Middle indicators. Combines Ubertooth/nRF hardware sniffing with bleak-based GATT enumeration and crackle-based encryption analysis. For authorized wireless security testing only.

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| bleak | >=0.21 | Cross-platform asyncio BLE GATT client for scanning and enumeration |
| tshark | (system) | Command-line Wireshark for BLE packet extraction and field analysis |
| ubertooth-btle | (system) | Ubertooth One CLI for passive BLE sniffing and packet capture |
| crackle | (system) | BLE Legacy Pairing encryption cracker for LTK recovery |

## CLI Usage

```bash
# Scan for BLE devices in range
python agent.py --mode scan --scan-duration 15 --output scan_report.json

# Enumerate GATT services on a target device
python agent.py --mode enumerate --target AA:BB:CC:DD:EE:FF --output gatt_report.json

# Test replay vulnerability on a specific characteristic
python agent.py --mode replay --target AA:BB:CC:DD:EE:FF \
  --char-uuid 0000fff1-0000-1000-8000-00805f9b34fb \
  --replay-payload 0102030405 --output replay_report.json

# Monitor for BLE advertising spoofing
python agent.py --mode monitor --scan-duration 60 \
  --known-devices known.json --output monitor_report.json

# Analyze a BLE packet capture
python agent.py --mode analyze --pcap capture.pcapng --output pcap_report.json

# Full assessment with Ubertooth capture
python agent.py --mode full --target AA:BB:CC:DD:EE:FF \
  --ubertooth-capture 120 --pcap-format ppi \
  --char-uuid 0000fff1-0000-1000-8000-00805f9b34fb \
  --replay-payload 0102030405 --output full_report.json
```

## Arguments

| Argument | Required | Description |
|----------|----------|-------------|
| `--mode` | No | Operating mode: `scan`, `enumerate`, `replay`, `monitor`, `analyze`, `full` (default: `scan`) |
| `--target` | Conditional | Target BLE device address (required for enumerate/replay modes) |
| `--scan-duration` | No | BLE scan duration in seconds (default: 10) |
| `--char-uuid` | Conditional | GATT characteristic UUID for replay testing |
| `--replay-payload` | Conditional | Hex-encoded payload for replay test |
| `--pcap` | Conditional | Path to BLE pcap/pcapng file for analysis mode |
| `--ubertooth-capture` | No | Capture with Ubertooth for N seconds; 0 to disable (default: 0) |
| `--pcap-format` | No | Ubertooth capture format: `pcapng`, `ppi`, `le` (default: `pcapng`) |
| `--known-devices` | No | JSON file mapping known device addresses to names for spoofing detection |
| `--output` | No | Output report file path (default: `ble_security_report.json`) |

## Key Functions

### `scan_ble_devices(scan_duration)`
Discovers BLE devices using bleak BleakScanner. Returns device address, name, RSSI, service UUIDs, manufacturer data, service data, and TX power for each device found.

### `enumerate_gatt_services(target_address, timeout)`
Connects to a BLE peripheral and enumerates all GATT services, characteristics, and descriptors. Reads characteristic values when readable. Flags writable characteristics, write-without-response properties, and characteristics containing sensitive keyword patterns.

### `test_replay_vulnerability(target_address, char_uuid, test_payload_hex, read_after)`
Writes a captured/test payload to a characteristic, then replays the same payload to detect if the device accepts stale commands without freshness validation. Reads state before and after to confirm replay effect.

### `detect_advertising_spoofing(scan_duration, known_devices)`
Monitors BLE advertising in real-time to detect spoofing indicators: same device name from multiple addresses (cloned device), known device names from unknown addresses (impersonation), and abnormal RSSI fluctuations (relay attack).

### `analyze_pcap_for_ble_attacks(pcap_path)`
Analyzes BLE packet captures using tshark and crackle. Detects Just Works pairing, Legacy Pairing without Secure Connections, excessive connection attempts, and attempts LTK recovery with crackle.

### `run_ubertooth_capture(output_path, target_address, duration, pcap_format)`
Starts a passive BLE capture using Ubertooth One in either promiscuous or follow mode. Supports pcapng, PPI (crackle-compatible), and LE pseudoheader output formats.

### `generate_report(scan_results, gatt_profiles, replay_results, spoofing_findings, pcap_findings, output_path)`
Aggregates all findings into a JSON report with severity breakdown and full device/GATT data.

## Threat Detection Coverage

| Threat | Detection Method | Finding ID |
|--------|-----------------|------------|
| Insecure GATT Permissions | GATT enumeration, property analysis | BLE-GATT-001/002/003 |
| Replay Attack | Payload write + re-write + state comparison | BLE-REPLAY-001 |
| Device Spoofing | Multi-address name monitoring | BLE-SPOOF-001/002/003 |
| Just Works Pairing | PCAP SMP opcode analysis | BLE-PAIR-001 |
| Legacy Pairing (No SC) | PCAP auth_req flag analysis | BLE-PAIR-002 |
| Weak Encryption | crackle LTK recovery | BLE-CRACK-001 |
| Connection Flooding | PCAP connection event counting | BLE-PCAP-002 |
