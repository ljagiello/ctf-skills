# Network Forensics

## PCAP Analysis with tshark

### LLMNR Poisoning Detection

```bash
# Show LLMNR queries and responses — rogue device responds to multicast queries
tshark -r capture.pcap -Y "llmnr" -T fields -e ip.src -e ip.dst -e dns.qry.name -e dns.a

# Pattern: victim queries 224.0.0.252, rogue IP responds with its own address
# The queried name is typically a typo (e.g., "DCC01" instead of "DC01")
```

**Indicators**:
- LLMNR response from non-DC IP resolving to itself
- Victim then initiates SMB/NTLM to the rogue IP
- DHCP hostname of rogue device often reveals attacker OS (e.g., "kali")

```bash
# Find rogue machine hostname via DHCP
tshark -r capture.pcap -Y "dhcp.option.hostname" -T fields -e ip.src -e dhcp.option.hostname
```

### NTLM Authentication Extraction

```bash
# Extract all NTLM auth events (negotiate=1, challenge=2, authenticate=3)
tshark -r capture.pcap -Y "ntlmssp" -T fields \
  -e frame.time -e ip.src -e ip.dst \
  -e ntlmssp.messagetype \
  -e ntlmssp.auth.username -e ntlmssp.auth.domain \
  -e ntlmssp.ntlmserverchallenge \
  -e ntlmssp.ntlmv2_response.ntproofstr

# Note: NTLM may travel over IPv6 — check ipv6.src/ipv6.dst if ip fields are empty
tshark -r capture.pcap -Y "ntlmssp.messagetype == 0x00000001" -T fields \
  -e ipv6.src -e ipv6.dst -e eth.src -e eth.dst
```

### NTLMv2 Hash Construction for Cracking

Extract from the **first** NTLM exchange (Type 2 challenge + Type 3 authenticate):

```bash
# 1. Get server challenge (from Type 2 message)
CHALLENGE=$(tshark -r capture.pcap -Y "ntlmssp.messagetype == 0x00000002" -T fields \
  -e ntlmssp.ntlmserverchallenge -c 1)

# 2. Get username, domain, full NTLMv2 response, NTProofStr (from Type 3 message)
tshark -r capture.pcap -Y "ntlmssp.messagetype == 0x00000003" -T fields \
  -e ntlmssp.auth.username -e ntlmssp.auth.domain \
  -e ntlmssp.ntlmv2_response -e ntlmssp.ntlmv2_response.ntproofstr -c 1
```

**Hash format** (hashcat mode 5600):
```
username::domain:server_challenge:NTProofStr:blob_after_NTProofStr
```

Where `blob_after_NTProofStr` = full NTLMv2 response with first 32 hex chars (NTProofStr) removed:
```bash
FULL_RESPONSE="<ntlmv2_response hex>"
NTPROOFSTR="${FULL_RESPONSE:0:32}"
BLOB="${FULL_RESPONSE:32}"
echo "${USERNAME}::${DOMAIN}:${CHALLENGE}:${NTPROOFSTR}:${BLOB}" > hash.txt
hashcat -m 5600 hash.txt /path/to/wordlist
```

### NTLM Relay Detection

**Pattern**: Three-party NTLM exchange across IPs:
1. Victim (A) → Attacker (B): NTLM Negotiate + Authenticate
2. Attacker (B) → Target (C): Relayed NTLM Negotiate + Authenticate
3. Target (C) → Attacker (B): NTLM Challenge (forwarded back to victim)

```bash
# Identify relay by checking NTLM auth destinations
tshark -r capture.pcap -Y "ntlmssp.messagetype == 0x00000003" -T fields \
  -e frame.time -e ip.src -e ip.dst -e ntlmssp.auth.username

# Check SMB tree connects to see relay target shares
tshark -r capture.pcap -Y "smb2.cmd == 3" -T fields \
  -e frame.time -e ip.src -e ip.dst -e smb2.tree
```

**Key indicator**: Same username authenticating to attacker IP AND from attacker IP to a different target within milliseconds.

### SMB Share Access

```bash
# All SMB2 tree connect requests (share access)
tshark -r capture.pcap -Y "smb2.cmd == 3 && ip.src == <victim_ip>" -T fields \
  -e frame.time -e ip.dst -e smb2.tree
```

### Carving HTTP Objects from a Noisy PCAP

For challenges that bury a malicious download or C2 POST body inside otherwise benign QUIC/TLS traffic:

```bash
# Carve every HTTP request/response body to disk in one pass
mkdir -p objects
tshark -r capture.pcapng --export-objects "http,objects" -q

# What got captured:
ls -la objects/
# Each file is named after the URI; both request bodies and response bodies appear.
```

Then inspect: `file objects/*`, `head -c 200 objects/*`, and `strings objects/* | grep -i 'flag\|<?php\|powershell'`.

**Why this beats stream-following on a 22 MB PCAP:** `--export-objects` reassembles chunked transfer-encoding, gzip, and large multipart bodies in one shot. Manual `follow,tcp,raw,N` per stream loses framing on the first multi-segment response.

### Decoding a PowerShell Stager Captured Mid-Flight

Loader pattern commonly seen in SAINT-style stagers:

```powershell
$blob   = "<long base64 string, REVERSED>"
$arr    = $blob.ToCharArray()
[array]::Reverse($arr)                    # mutates in place
-join $arr 2>&1> $null                    # red herring — result discarded
$stage2 = [Text.Encoding]::UTF8.GetString(
            [Convert]::FromBase64String("$arr"))   # "$arr" interpolates with $OFS=' '
Invoke-Expression $stage2                 # often via aliased pWn / iEx
```

To recover stage 2: take the original base64 string from the captured file, reverse the *string* (Python `s[::-1]`), then `base64.b64decode`. The whitespace from PowerShell's interpolation is harmless — `FromBase64String` ignores it.

### Decrypting a C2 POST Body When the Stage-2 Key Is in the PCAP

PowerShell `Encrypt-String` recipes from public stagers wrap as `IV(16) ‖ ciphertext` and base64-encode. If the static AES key is hardcoded in the stage-2 script you already recovered:

```python
import base64, sys
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7

key  = base64.b64decode(b"<key_b64_from_stage2>")          # 32 bytes for AES-256
raw  = base64.b64decode(open("c2_body.bin","rb").read())
iv, ct = raw[:16], raw[16:]
pt = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor().update(ct) + b""
pt = PKCS7(128).unpadder().update(pt)
print(pt)
```

CTF gotcha: malware authors often embed flag fragments in JSON fields of the exfiltrated data (e.g. `Email` = base64 of part 2), with a separate `$part1` defined-but-unused in the stage-2 source. Always check both halves before assuming a single-source flag.

## Timestamp Handling

**pcap timestamps** include timezone offset (e.g., `+0200`). Always convert to UTC:
- `13:18:30+0200` → `11:18:30 UTC`
- Check `frame.time_epoch` for unambiguous UTC timestamps

**EVTX timestamps** are already UTC (`SystemTime` attribute).
