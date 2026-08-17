# API Reference: iOS App Security Assessment Agent

## Overview

Automates iOS application security testing using Frida dynamic instrumentation, Objection runtime exploration, SSL pinning bypass, keychain extraction, and IPA static analysis. Covers OWASP MASVS categories including STORAGE, NETWORK, AUTH, RESILIENCE, and PLATFORM. For authorized penetration testing only.

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| frida | >=16.0 | Dynamic instrumentation framework for iOS process injection |
| frida-tools | >=12.0 | CLI utilities (frida-ps, frida-trace) for device interaction |
| objection | >=1.11 | High-level Frida-powered mobile security exploration toolkit |

## CLI Usage

```bash
# Static IPA analysis only
python agent.py --ipa target.ipa --output-dir ./analysis

# Dynamic testing with SSL pinning bypass and keychain dump
python agent.py --bundle-id com.target.app --ssl-bypass --keychain --output report.json

# Full assessment with jailbreak bypass
python agent.py --bundle-id com.target.app --ipa target.ipa \
  --ssl-bypass --keychain --jailbreak-bypass \
  --device usb --frida-timeout 45 --output full_report.json
```

## Arguments

| Argument | Required | Description |
|----------|----------|-------------|
| `--bundle-id` | Conditional | Target app bundle identifier for dynamic testing |
| `--ipa` | Conditional | Path to IPA file for static analysis |
| `--device` | No | Frida device type: `usb`, `remote`, `local` (default: `usb`) |
| `--ssl-bypass` | No | Execute SSL pinning bypass Frida script |
| `--keychain` | No | Dump and analyze keychain item security |
| `--jailbreak-bypass` | No | Execute jailbreak detection bypass script |
| `--frida-timeout` | No | Frida script execution timeout in seconds (default: 30) |
| `--output` | No | Output report file path (default: `ios_assessment_report.json`) |
| `--output-dir` | No | Directory for IPA extraction artifacts (default: `.`) |

At least one of `--bundle-id` or `--ipa` is required.

## Key Functions

### `analyze_ipa_static(ipa_path, output_dir)`
Extracts and statically analyzes an IPA package. Checks Info.plist for ATS configuration, URL schemes, and background modes. Scans binary strings for hardcoded API keys, secrets, AWS credentials, Firebase URLs, and private keys. Inspects provisioning profile for debug entitlements.

### `run_frida_script(target_bundle, script_source, device_type, timeout_sec)`
Executes a Frida JavaScript payload against a target iOS app. Attempts to attach to a running process first, falls back to spawning the app. Collects messages sent from the Frida script via the `send()` API.

### `run_objection_command(bundle_id, command)`
Runs a single Objection command against the target app using subprocess. Returns stdout, stderr, and return code. Handles timeout and missing installation gracefully.

### `assess_keychain_security(bundle_id)`
Dumps keychain items via Objection and analyzes accessibility attributes. Flags items using insecure attributes (kSecAttrAccessibleAlways, kSecAttrAccessibleAfterFirstUnlock) and passwords lacking biometric/passcode access control.

### `generate_report(findings, target_app, output_path)`
Aggregates all findings into a JSON report with severity breakdown (critical/high/medium/low) and metadata including timestamp and target identifier.

## Frida Script Payloads

| Script | Target APIs | Purpose |
|--------|-------------|---------|
| `SSL_PINNING_BYPASS_SCRIPT` | SecTrustEvaluate, SecTrustEvaluateWithError, AFSecurityPolicy, TSKPinningValidator | Bypasses certificate pinning across system and third-party frameworks |
| `KEYCHAIN_DUMP_SCRIPT` | SecItemCopyMatching | Enumerates keychain item classes and counts accessible items |
| `JAILBREAK_DETECTION_BYPASS_SCRIPT` | NSFileManager, UIApplication canOpenURL, fork() | Hides jailbreak indicators from filesystem, URL scheme, and process checks |

## OWASP MASVS Coverage

| MASVS Category | Tests | Functions |
|----------------|-------|-----------|
| MASVS-STORAGE | MASTG-TEST-0055, 0058 | `assess_keychain_security`, `analyze_ipa_static` |
| MASVS-NETWORK | MASTG-TEST-0066, 0068 | SSL pinning bypass, ATS configuration check |
| MASVS-RESILIENCE | MASTG-TEST-0079, 0083 | Jailbreak bypass, debug entitlement check |
| MASVS-PLATFORM | MASTG-TEST-0075 | URL scheme analysis |
