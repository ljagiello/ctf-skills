# DFIR Principles

Decision tree from artifact type to analysis path. Use this to mount the right scenario set immediately when given evidence.

## 1. Artifact triage

| You receive | Mount first | Then |
|-------------|-------------|------|
| `.pcap` / `.pcapng` | `scenarios/pcap/` | If TLS, `tls-decryption.md` first; if HTTP, `http-objects-export.md`; if NTLM/SMB, `network-forensics.md` (root reference) |
| Memory dump (`.raw`, `.lime`, `.dmp`) | `scenarios/memory/volatility-process-analysis.md` | Then `injected-code-detection.md` and `network-artifacts-from-mem.md` |
| LSASS dump only | `scenarios/memory/memory-credential-extraction.md` | — |
| `$MFT` / NTFS image | `scenarios/filesystem/ntfs-mft-analysis.md` | Pair with `prefetch-analysis.md`, `lnk-file-analysis.md` |
| `*.evtx` (Windows) | `scenarios/log-analysis/windows-event-logs.md` | If Sysmon channel present, also `sysmon-rules.md` |
| `auth.log` / `syslog` / journald | `scenarios/log-analysis/linux-auth-logs.md` | — |
| Apache / nginx access log | `scenarios/log-analysis/webserver-logs.md` | — |
| Splunk / Elastic stack | `scenarios/log-analysis/splunk-spl-queries.md` | — |
| Multi-source incident | `scenarios/filesystem/timeline-creation.md` | Build super-timeline first, then drill |

## 2. Investigation question to scenario

| Question | Scenario(s) |
|----------|-------------|
| "Did <program> run on this host?" | `prefetch-analysis.md`, `windows-event-logs.md` (4688), `sysmon-rules.md` (EID 1) |
| "Did the user open <folder>?" | `shellbags-userassist.md` |
| "What credentials were stolen?" | `memory-credential-extraction.md`, `pcap/credential-extraction.md` |
| "How did they move laterally?" | `ad-attack-detection/lateral-movement-indicators.md` |
| "Was a Golden/Silver Ticket forged?" | `ad-attack-detection/golden-ticket-detection.md` |
| "Did NTDS get dumped?" | `windows-event-analysis.md` (root), 4799 + ESENT 325/326/327, `dcsync-detection.md` |
| "Is there a process injection / hollowing?" | `memory/injected-code-detection.md` |
| "What flowed in/out via DNS?" | `pcap/dns-tunneling-detection.md` |
| "Was a webshell deployed?" | `log-analysis/webserver-logs.md` |
| "Is there C2 we can decrypt?" | `pcap/c2-traffic-decryption.md` |

## 3. Universal workflow

1. **Inventory** — list every evidence file with size, hash, mtime.
2. **Normalize timestamps** — convert all sources to UTC. AM/PM trap: 12:XX AM = 00:XX, 12:XX PM = 12:XX.
3. **Parse structured first, free-text second** — EVTX/MFT/Prefetch before strings hunting.
4. **Anchor on a small set of indicators** — known IP, user, process, hash, time window.
5. **Pivot across sources** — every finding should be confirmed by a *second* artifact class.
6. **Reconstruct the chain** — initial access → execution → persistence → priv-esc → lateral → exfil.
7. **Reverse the analyst burden** — write reproducible scripts, not point-and-click. Future you will need to replay.

## 4. High-yield correlation keys

| Key | Joins |
|-----|-------|
| `TargetLogonId` (Windows) | Every event in a logon session — 4624 → 4688 → 4663 → 4634 |
| `ProcessGuid` (Sysmon) | Process tree across reboots and PID reuse |
| `tcp.stream` (Wireshark) | All packets in one TCP conversation |
| FILETIME (1601-epoch, 100ns) | Convert: `epoch + timedelta(microseconds=ft//10)` |
| MFT entry number | Cross-reference USN journal, plaso, prefetch references |
| NetBIOS / MachineId | Pair LNK metadata with EVTX 4624 source workstation |

## 5. Anti-patterns

- Submitting the first `strings`-extracted flag-shaped string from a PCAP — almost always a decoy. Decrypt the channel first.
- Treating $STANDARD_INFORMATION timestamps as authoritative — they are stompable. Cross-check with $FILE_NAME.
- Claiming "no execution" because Prefetch is missing — Server SKUs and SSDs may disable Prefetcher.
- Brute-forcing C2 passwords with rockyou — recover the key from the dropper or stage-2 source instead.
- Ignoring USN journal — it captures file lifecycle reasons that MFT alone cannot infer.
- Trusting attacker-cleared logs — pivot to forwarded/SIEM copies and EVTX `104` events for tampering proof.

## 6. Output discipline

- All timestamps in UTC, ISO 8601 (`2024-09-01T13:18:30Z`).
- Every claim cites: artifact path, record ID/offset, exact field name, and the timestamp.
- For a process: PID, ProcessGuid, ImageName, ParentImageName, CommandLine, CreateTime, ExitTime.
- For a network connection: protocol, src IP:port, dst IP:port, time, owning PID and ProcessGuid.
- For a credential: account name, domain, hash type/format, source artifact, recovery method.
