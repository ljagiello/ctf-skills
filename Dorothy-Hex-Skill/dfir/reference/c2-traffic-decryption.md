# Forensics — Decrypting C2 Framework Traffic from PCAP/Memory

A high-recurrence forensics pattern: PCAP (often with a paired memory dump or dropper binary) of a known C2 framework. The objective (flag, leaked secret, exfil content) is hidden inside encrypted command/response traffic. The win condition is recovering the session key from secondary artifacts and replaying the framework's crypto.

## Step 1 — Fingerprint the framework

Look for unique URI / header / response signatures:

| Framework | URI / Header / Body signature                                   | Key location                             |
|-----------|-----------------------------------------------------------------|------------------------------------------|
| Covenant Grunt | `/en-us/{index,test,docs}.html`, JSON `GruntEncryptedMessage` body, strings `GruntStager`, `CovenantCertHash`, `MessageTransform` | 32-byte session key in the implant process memory dump |
| SharPyShell | POST to `*.aspx`, base64'd AES-256-CBC body, `If-Match: <id>` header pattern | sha256-hex of password (32 bytes), hardcoded in the dropper's `.cs` source |
| Empire 4.x | `/news.php`, `/login/process.php`, `Cookie: session=`           | Staging key in stager (PowerShell or Python source) |
| Sliver | gRPC + DNS C2, mTLS handshake | Implant binary; reverse the per-session ECDH derivation |
| Tiny SHell (tsh / `creaktive/tsh`) | TCP, no HTTP framing; first 40 bytes are `IV1‖IV2` (per-direction IV); each frame ends `HMAC-SHA1(ct‖u32 counter)` | Hardcoded `secret` string in the dropper ELF (e.g. `S3cr3tP@ss`) |
| **NimPlant** | HTTP `/api/v2/{login,ping,query}`, port 4444; AES-CTR with per-implant 16-byte key derived from `xor_string`; strings `BeaconData*` in implant binary | Recover by brute-forcing the `xor_string` integer key (small space, ~10^4) against any decrypted JSON marker. The session AES key is then visible in the implant's `~/.config/np/<id>` file or in the per-implant constants in the binary. |

Tools: `tshark -Y http -T fields -e http.host -e http.user_agent -e http.request.uri`, then `--export-objects http,out/` to pull bodies. For non-HTTP, `tshark -Y "tcp.port==X" -T fields -e data.data` and reassemble with scapy.

## Step 2 — Recover the session key

Three escalation paths, in order:

1. **Hardcoded key in dropper.** Most common. `strings -n 8 dropper.exe | grep -i 'pass\|key\|secret'` then check the source-style comments and resource sections.
2. **Memory carving.** Dump the implant process. Carve the key by:
   - Type-aware scan: search for `byte[N]` heap arrays — in .NET dumps look for an 8-byte little-endian length prefix followed by N bytes (e.g. `20 00 00 00 00 00 00 00` for a 32-byte buffer). Yields ~10⁴ candidates.
   - **HMAC oracle**: take one captured ciphertext+HMAC pair from the PCAP. For each candidate key, compute the framework's HMAC; the unique match is the real key. ~10⁴ candidates × ms-per-hmac ≈ minutes.
3. **Crib-drag XOR**: when traffic is XORed with a small repeating key (e.g. shellcode body XOR'd with 8-byte key), drag a known prefix (`cmd.exe /c `, MZ header, `cmd.exe`, `WinExec`) across the ciphertext until printable bytes appear. The aligned XOR'd offset gives the key.

## Step 3 — Decrypt and walk the operator session

Replay the framework's crypto using its public source:
- Covenant Grunt → `Covenant/Models/Grunts/Grunt.cs::Encrypt` (AES-256-CBC + HMAC-SHA-256, IV per message, key = session key).
- SharPyShell → `core/ChannelAES.py::encrypt` (AES-256-CBC, key = `bytes.fromhex(sha256_hex)`, IV = key[:16], PKCS7).
- tsh PEL → `pel.c::pel_recv_msg` (key = `SHA1(secret‖IV)[:16]`, AES-128-CBC, LCT = IV[:16], HMAC-SHA1 every frame, counter increments).

Decrypted output is usually a tty session: `whoami`, file ops, mimikatz, screenshots, keylogger captures. **The objective string often appears as a typed password, an exfil filename, or a created-file-content** — not necessarily in the first decrypted message.

## Step 4 — Decoys

C2-themed challenges almost always include 1–2 fake flag-shaped strings to mislead anyone who only `strings` the pcap. Always validate by submitting the candidate that's the operator's *clear intent* (e.g. the password they typed into a phishing form), not the first match.

## Worked examples

- **Covenant Grunt + .NET heap key carving**: recover AES key by HMAC-oracle scan over .NET `byte[32]` heap arrays in the PowerShell minidump; decrypt the 20–30 messages → keylogger capture yields the typed admin-portal password as the answer.
- **Tiny SHell (tsh) with hardcoded secret**: decrypt the PEL stream; the operator's command line typically reveals an additional password (e.g. for an exfil-zip `zip -P<password> ...`); carve the zip out of the file-transfer frames, then run `firefox_decrypt.py` on the contained Firefox profile to extract the saved-credential string.
- **SharPyShell with sha256-hex password in dropper**: decrypt all round-trips; embedded `inject_shellcode_as` payload XORs a 121-byte tail with an 8-byte key. Crib-drag `cmd.exe /c ` to recover the XOR key, decode the `WinExec("cmd.exe /c echo <secret> > flag.txt")` shellcode. Decoys are common — verify the operator's stated intent.
- **NimPlant + small-keyspace xor_string**: brute-force `xor_key` from `xor_string` (~10^4 keyspace) → recover per-implant AES-CTR session keys → full operator timeline decrypted. Watch for split secrets: half the answer may live in the C2 stream tail while the other half lives in an external download URL recorded in the operator commands. Always check whether the artifact bundle is complete before exhausting submissions.

## Anti-pattern: do NOT
- Submit the first flag-shaped string you `strings` out of the pcap — almost always a decoy.
- Brute-force the C2 password with rockyou — bespoke C2 passwords are not in wordlists; recover from artifacts.
- Skip the dropper. Even when a memory dump is present, the dropper has the cleanest source-of-truth for the crypto choice.

