# Credential Extraction from PCAP

## When this applies

A PCAP captured cleartext or weakly-protected authentication. You need to recover usernames, passwords, hashes, or tokens for: incident scope, lateral-movement reconstruction, or to generate offline cracking inputs (NTLMv2, Kerberos, NetNTLM).

## Technique

Mine each authentication-bearing protocol with focused tshark filters or specialized tools. The five high-yield protocols are HTTP Basic, FTP, Telnet, SMB/NTLM (challenge-response, hashable), and SMTP/POP3/IMAP. Each has a stable Wireshark display filter and field set.

## Steps

1. **HTTP Basic / cookies**:
   ```bash
   tshark -r capture.pcap -Y 'http.authorization' -T fields \
     -e ip.src -e http.host -e http.authorization
   # Decode "Basic <b64>" -> user:pass
   echo -n "<base64>" | base64 -d
   # Cookies for session theft
   tshark -r capture.pcap -Y 'http.cookie' -T fields -e ip.src -e http.host -e http.cookie
   ```
2. **FTP** (cleartext USER/PASS):
   ```bash
   tshark -r capture.pcap -Y 'ftp.request.command in {"USER","PASS"}' \
     -T fields -e ip.src -e ip.dst -e ftp.request.command -e ftp.request.arg
   ```
3. **Telnet** (typed character-by-character):
   ```bash
   tshark -r capture.pcap -Y "tcp.port==23" -q -z follow,tcp,ascii,0
   # Or per-stream:
   for s in $(tshark -r capture.pcap -Y "tcp.port==23" -T fields -e tcp.stream | sort -u); do
     tshark -r capture.pcap -q -z follow,tcp,ascii,$s
   done
   ```
4. **SMB/NTLM** — extract NTLMv2 hash for hashcat (mode 5600):
   ```bash
   # See network-forensics.md for full extraction pipeline.
   tshark -r capture.pcap -Y "ntlmssp.messagetype == 0x00000003" -T fields \
     -e ntlmssp.auth.username -e ntlmssp.auth.domain \
     -e ntlmssp.ntlmv2_response -e ntlmssp.ntlmv2_response.ntproofstr
   tshark -r capture.pcap -Y "ntlmssp.messagetype == 0x00000002" -T fields \
     -e ntlmssp.ntlmserverchallenge
   # Format: USER::DOMAIN:CHALLENGE:NTPROOFSTR:BLOB (BLOB = response[32:])
   ```
5. **SMTP / POP3 / IMAP** AUTH LOGIN/PLAIN:
   ```bash
   tshark -r capture.pcap -Y 'smtp.req.parameter or pop.request.parameter or imap.request' \
     -T fields -e ip.src -e ip.dst -e smtp.req.parameter -e pop.request.parameter -e imap.request
   # AUTH LOGIN: server sends "VXNlcm5hbWU6" (Username:), client sends b64(user), b64(pass) on next two lines
   # AUTH PLAIN: single line "AUTH PLAIN <b64>" where b64 decodes to "\0user\0pass"
   ```
6. **Bulk one-shot tool**:
   ```bash
   pip install pcredz
   pcredz -f capture.pcap -o creds.txt
   # Detects HTTP basic, FTP, Telnet, SMTP, POP3, IMAP, SMB, NTLMv1/v2, Kerberos, SNMP
   ```

## Verifying success

- Extracted credentials login successfully against the source service (when authorized to verify).
- NTLMv2 hash crackable in hashcat (`hashcat -m 5600 hash.txt rockyou.txt`) or matches a known account.
- Session cookies replay into HTTP requests with same User-Agent and yield authenticated content.

## Common pitfalls

- HTTPS / FTPS / IMAPS strip-mining requires TLS decryption first (see tls-decryption.md).
- NTLMv2 hash format is brittle: missing the server challenge or splitting NTProofStr from the BLOB makes the hash uncrackable. Always pull from the **first** Type 2/Type 3 pair in a session.
- Kerberos AS-REQ pre-auth hashes (etype 23, RC4) can be cracked offline (`hashcat -m 7500/19900` for AS-REQ/AS-REP). Filter `kerberos.msg_type == 10` for AS-REQ.
- Cleartext-protocol filters miss when servers run on non-standard ports — pivot to `tcp.port == X` and verify with stream-follow.
- Some browsers transmit `Authorization: Bearer ...` JWTs. Capture and decode the JWT (`jwt-decode`) — alg=none or weak HS256 keys are common.

## Tools

- `tshark` filters: `http.authorization`, `ftp.request`, `ntlmssp.messagetype`, `kerberos.msg_type`, `smtp.req.parameter`
- `pcredz` — auto-discovers ~10 credential types
- `NetworkMiner` — file + credential carving GUI
- `hashcat` — modes 5600 (NTLMv2), 5500 (NetNTLMv1), 13100 (Kerberoast TGS), 18200 (AS-REP)
