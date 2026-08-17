---
name: dfir
description: Digital forensics and incident response - Windows event log analysis, PCAP forensics, filesystem artifact analysis, AD attack detection, and timeline correlation. Use when investigating security incidents, analyzing Sherlocks, or performing threat hunting on provided evidence files.
---

# DFIR

Investigate security incidents by analyzing event logs, network captures, and filesystem artifacts. Detect and reconstruct AD attack chains.

## Techniques

| Domain | Key Capabilities |
|--------|-----------------|
| **Windows Event Logs** | EVTX parsing, Event ID correlation, logon tracking, privilege enumeration |
| **Network Forensics** | PCAP analysis, NTLM extraction, LLMNR/NBT-NS poisoning detection, relay identification |
| **Filesystem Forensics** | MFT parsing, Prefetch analysis, VSS artifact recovery, Linux persistence, timeline reconstruction |
| **AD Attack Detection** | Kerberoasting, AS-REP roasting, NTDS dump, NTLM relay, credential theft |
| **Memory Forensics** | Volatility3 analysis: process trees, file extraction, SID resolution, command lines |
| **Hash Analysis** | NTLMv2 hash construction from pcap, offline cracking validation |

## Workflow

1. **Inventory evidence** — List all artifacts (EVTX, pcap, MFT, prefetch, registry)
2. **Parse structured data** — EVTX with `python-evtx`, pcap with `tshark`, MFT with `analyzeMFT`
3. **Identify attack indicators** — Key Event IDs, suspicious traffic patterns, anomalous files
4. **Correlate across sources** — Match timestamps, IPs, LogonIDs, and process IDs across artifacts
5. **Reconstruct timeline** — Build chronological attack chain with UTC timestamps
6. **Answer investigative questions** — Map findings to specific incident response queries

## Tools

```bash
pip install python-evtx windowsprefetch analyzeMFT
brew install wireshark p7zip hashcat
```

| Tool | Purpose |
|------|---------|
| `python-evtx` | Parse Windows .evtx files |
| `tshark` | CLI pcap analysis (NTLM, LLMNR, SMB filters) |
| `analyzeMFT` | Parse NTFS Master File Table |
| `windowsprefetch` | Parse Windows prefetch files (Windows host only) |
| `hashcat` | Hash cracking (NTLMv2 mode 5600, Kerberos mode 13100/18200) |
| `volatility3` | Memory dump analysis (pstree, filescan, dumpfiles, getsid, cmdline) |
| `7z` | Extract AES-encrypted evidence ZIPs |

## Quick Reference: Key Event IDs

| Event ID | Log | Indicates |
|----------|-----|-----------|
| 4624 | Security | Successful logon (check Type + IP mismatch) |
| 4768 | Security | TGT request (PreAuthType=0 → AS-REP roast) |
| 4769 | Security | TGS request (EncType=0x17 → Kerberoast) |
| 4799 | Security | Group membership enumerated (VSS/ntdsutil) |
| 5140 | Security | Network share accessed |
| 7036 | System | Service state change (VSS start → NTDS dump) |
| 325/326/327 | Application | ESENT database create/detach/close |
| 330 | Application | ESENT database file info |
| 3006/3008 | DNS Client Events | DNS query sent/response received (malicious domain lookups) |
| 106/200 | Task Scheduler | Scheduled task created/executed (persistence via schtasks) |

## Reference

- [windows-event-analysis.md](reference/windows-event-analysis.md) — EVTX parsing patterns and AD attack detection
- [network-forensics.md](reference/network-forensics.md) — PCAP analysis for NTLM, LLMNR, relay detection
- [filesystem-forensics.md](reference/filesystem-forensics.md) — MFT, Prefetch, VSS artifact analysis

## Critical Rules

- **Answer formatting**: When forensics questions ask for "the value" of a code variable (e.g., PHP `$shell`), include language-specific string delimiters and terminators (e.g., `'value';` not just `value`). Check placeholder hints for format clues.
- For malicious Office OOXML, inspect more than VBA streams: attackers may split staged Base64 or script content across drawing/object descriptors, shared strings, named cells, and hidden UserForm control captions/values.
- When a VBA byte array starts with an `fnstenv`/`pop` decoder stub, convert signed integers to raw bytes and test a Shikata-style rolling XOR decode before treating the shellcode as corrupt.
- For legacy Excel BIFF/XLS malware, inspect `BOUNDSHEET` records for `hidden` or `very hidden` worksheets and specifically check for Excel 4.0 macro sheets; changing the hidden-state byte or parsing the sheet directly can expose staged strings and flag fragments that never appear in normal workbook views.
- For webshell traffic in PCAPs, recover static keys from the uploaded server-side code first, then decrypt operator tasking before chasing later payloads; if a dropped XOR key file is referenced by a shellcode stage, verify where the encoded region actually starts instead of XORing the whole blob from offset zero.
- **PowerShell stager pattern** (in-place reverse + base64 + IEX): when a stage-1 PS script does `[array]::Reverse($charArr)` followed by `FromBase64String("$charArr")`, the `-join` line is often a red herring — string interpolation of a char array uses `$OFS=' '` and `FromBase64String` tolerates whitespace. Reverse the original base64 string (not the joined-with-spaces version) and decode to get stage 2.
- **Multi-fragment flag exfil**: forensic challenges may split a flag across (a) a hardcoded `$partN` in the malware that is *defined but never referenced* (often base64'd), and (b) a field of the captured C2 POST body. Decrypt the body with the static AES key from the leaked stage-2 source (PowerShell `Encrypt-String` puts `IV‖ciphertext` then base64-wraps); inspect every JSON field for further base64.
- All timestamps in **UTC** — convert from local time zones in pcap/logs. **AM/PM trap**: 12:XX AM = 00:XX (midnight), 12:XX PM = 12:XX (noon). 12 AM ≠ 01:00.
- Parse EVTX with `python-evtx` (XML namespace: `http://schemas.microsoft.com/win/2004/08/events/event`)
- Use `tshark` for pcap (not scapy for large files) — filter with `-Y` display filters
- Decompress Win10 prefetch (MAM\x04 header) with `dissect.util.compression.lzxpress_huffman`
- For AES-encrypted ZIPs (compression method 99), use `7z` not `unzip`
