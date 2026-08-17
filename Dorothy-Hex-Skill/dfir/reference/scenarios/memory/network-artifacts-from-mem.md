# Network Artifacts From Memory

## When this applies

You need attacker IPs, C2 domains, listening ports, or in-flight connections from a memory image — possibly because no PCAP exists, because the network stream is encrypted, or because you want to attribute connections to a specific process at a specific moment.

## Technique

Walk the kernel network structures: TCB hash table (Windows `_TCPT_OBJECT` / `_TCP_ENDPOINT`), UDP endpoint tables, AFD socket layer. Volatility's `windows.netscan` reads these directly out of the dump. Combined with `windows.netstat` (active connections list) and process correlation, you reconstruct the connection graph at acquisition time. DNS cache, hosts file, and putty/ssh client artifacts add domain-level detail.

## Steps

1. Active and recent connections:
   ```bash
   vol -f memory.raw windows.netscan
   ```
   Columns: Offset, Proto, LocalAddr, ForeignAddr, State, PID, Owner, Created.
   Suspicious patterns:
   - `ESTABLISHED` to non-RFC1918 from non-browser process
   - `LISTENING` on high port from unusual binary
   - Owner = `lsass.exe` with non-DC remote (potential pass-the-ticket pivot)
2. Filter to investigation IPs:
   ```bash
   vol -f memory.raw windows.netscan | grep -E '203\.0\.113|198\.51\.100'
   ```
3. Sockets (older Windows):
   ```bash
   vol -f memory.raw windows.sockets   # only on XP/2003 / vol2 sockets
   vol -f memory.raw windows.sockscan
   ```
4. Linux:
   ```bash
   vol -f memory.lime linux.netstat
   vol -f memory.lime linux.sockstat
   ```
5. DNS resolver cache (Windows 10+):
   ```bash
   vol -f memory.raw windows.registry.printkey \
     --key 'ControlSet001\Services\Dnscache\Parameters'
   # Or: yarascan for plaintext domains in svchost.exe (DnsCache service)
   vol -f memory.raw yarascan.YaraScan --yara-rules \
     'rule dns { strings: $a = /[a-z0-9-]+\.[a-z]{2,}/ wide condition: any of them }'
   ```
6. PuTTY / OpenSSH artifacts (last hostname/port typed):
   ```bash
   strings -el memory.raw | grep -E 'ssh -l|PuTTY:|HostKey|known_hosts'
   ```
7. Cross-correlate connection PID with `pstree` and `cmdline`:
   ```bash
   vol -f memory.raw windows.pstree | grep -A1 1234
   vol -f memory.raw windows.cmdline --pid 1234
   ```

## Verifying success

- The same suspect IP appears in `netscan` AND in carved DNS cache AND in process-injected shellcode (yarascan).
- `Created` timestamp on the socket matches a logon or process-creation event in EVTX (4624 / 4688).
- Reverse DNS / WHOIS confirms attacker infrastructure.

## Common pitfalls

- `netscan` finds *both* live and freed structures. `State` = `CLOSED` may still appear long after disconnect — useful for history but don't claim it's "active".
- Windows ASLR randomizes pool layout, but vol3 ISF resolves it; symbol pack mismatch produces empty output. Verify `windows.info` first.
- Process-port mappings break for kernel-level rootkits that patch TCB. Cross-check with `windows.driverirp` and YARA scans of network buffers.
- IPv6 addresses are stored differently and may show as `::ffff:1.2.3.4` (mapped) — match both forms.
- DNS cache process (Dnscache service in svchost) tier-rotates entries; only the most recent ~1000 are retained.

## Tools

- `volatility3`: `windows.netscan`, `windows.netstat`, `linux.netstat`
- `volatility2`: `connscan`, `connections`, `sockets`, `sockscan`
- `MemProcFS` `/sys/net/tcp/` view
- `bulk_extractor` — carves IPs, URLs, emails from raw memory
