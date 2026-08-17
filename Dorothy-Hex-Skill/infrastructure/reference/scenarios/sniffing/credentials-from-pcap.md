# Extracting Credentials from PCAP

## When this applies

- You have a pcap (live capture or historical) with cleartext or hash-bearing protocol traffic.
- Goal is to harvest usernames, passwords, session tokens, API keys, NTLM hashes, and Kerberos artifacts.
- Common sources: HTTP Basic Auth, FTP, Telnet, SMTP/POP/IMAP, SMB-NTLM challenge/response, Kerberos AS-REQ.

## Technique

Use protocol-aware tools (NetworkMiner, tshark, Pcredz, dsniff) to walk every flow in the pcap, identifying authentication exchanges and extracting their credential portions. Cleartext protocols give plaintext; challenge/response protocols give hashes that can be cracked offline.

## Steps

### 1. Triage the pcap

```bash
# Overview — protocols, hosts, packet count
capinfos capture.pcap
tshark -r capture.pcap -q -z io,phs       # protocol hierarchy
tshark -r capture.pcap -q -z conv,tcp     # TCP conversations
```

Top protocols to focus on for credentials: HTTP, FTP, Telnet, SMB, Kerberos, LDAP, SMTP/POP/IMAP, SNMP, DNS (community strings sometimes leak), NTLMSSP.

### 2. Automated extraction tools

```bash
# Pcredz — covers HTTP basic, FTP, IMAP, POP, SMTP, SNMP, Kerberos, NTLMv1/v2, etc.
Pcredz -f capture.pcap

# NetworkMiner (GUI / Mono)
NetworkMiner.exe capture.pcap     # Windows
mono NetworkMiner.exe capture.pcap   # Linux

# net-creds (older, python2)
sudo net-creds.py -p capture.pcap
```

NetworkMiner is the gold standard — extracts files, credentials, certificates, and sessions in one pass.

### 3. HTTP Basic Auth

```bash
tshark -r capture.pcap -Y 'http.authorization' -T fields \
    -e http.host -e http.request.uri -e http.authorization

# Decode the base64
echo "dXNlcjpwYXNz" | base64 -d
```

### 4. HTTP Form-based POST

```bash
tshark -r capture.pcap -Y 'http.request.method == POST' \
    -T fields -e http.host -e http.request.uri -e urlencoded-form.value

# Or extract entire bodies
tshark -r capture.pcap -Y 'http.request.method == POST' --export-objects http,/tmp/http-objects/
```

Look for `Content-Type: application/x-www-form-urlencoded` requests with `password=`, `pass=`, `pwd=`, `user=`, `email=` fields.

### 5. FTP / Telnet / IMAP / POP3 / SMTP cleartext

```bash
# FTP USER and PASS
tshark -r capture.pcap -Y 'ftp.request.command == "USER" or ftp.request.command == "PASS"' \
    -T fields -e ftp.request.command -e ftp.request.arg

# Telnet (find streams via Wireshark "Follow → TCP Stream")
tshark -r capture.pcap -Y 'tcp.port == 23' --reassemble-tcp

# IMAP/POP3 LOGIN
tshark -r capture.pcap -Y 'imap.line contains "LOGIN" or pop.request.command == "PASS"'
```

Wireshark's GUI: `Analyze → Follow → TCP Stream` reads the entire conversation in cleartext form.

### 6. SMB NTLMv1 / NTLMv2 hash extraction

```bash
# tshark NTLMSSP fields
tshark -r capture.pcap -Y 'ntlmssp.auth.username' \
    -T fields -e ntlmssp.auth.username -e ntlmssp.auth.domain

# Pcredz extracts ready-to-crack hashes
Pcredz -f capture.pcap
# Output format: user::domain:LMHash:NTHash:Challenge
```

Crack with hashcat:

```bash
hashcat -m 5500 ntlmv1.txt rockyou.txt    # NTLMv1
hashcat -m 5600 ntlmv2.txt rockyou.txt    # NTLMv2
```

### 7. Kerberos AS-REQ / TGS-REP extraction

```bash
# kerbrute / kerberize / scripts to extract Kerberos hashes from pcap
# tshark direct
tshark -r capture.pcap -Y 'kerberos.cipher' \
    -T fields -e kerberos.CNameString -e kerberos.realm -e kerberos.cipher

# extract AS-REP for AS-REP roastable accounts
# Use tools like KrbRelayUp or scripts that wrap tshark output into hashcat $krb5asrep$ format
```

Crackable hash modes:
- `$krb5asrep$23$user@REALM:...` → hashcat `-m 18200`
- `$krb5tgs$23$*user*spn*` → hashcat `-m 13100`
- `$krb5pa$23$user$realm$...` → hashcat `-m 7500`

### 8. SNMPv1/v2c community strings

```bash
tshark -r capture.pcap -Y 'snmp.community' -T fields -e snmp.community | sort -u
```

Cleartext community strings ride in every SNMP packet. SNMPv3 is encrypted/authenticated and not extractable without keys.

### 9. WPA / WPA2 4-way handshake

```bash
# Convert wireless pcap to hashcat format
hcxpcapngtool -o handshake.hc22000 capture.pcap

# Crack
hashcat -m 22000 handshake.hc22000 rockyou.txt
```

WPA3 SAE handshakes (`-m 22000` mode) are also extractable but PMKID/SAE-specific.

### 10. SSL/TLS — only with the keylog

```bash
# Decrypt TLS in tshark/Wireshark
tshark -r capture.pcap -o tls.keylog_file:sslkeys.log -Y http
```

Without the SSLKEYLOGFILE or the server's private key (RSA-only ciphers), TLS is opaque. Modern ECDHE cipher suites cannot be decrypted post-hoc even with the private key.

### 11. File extraction

```bash
# All HTTP objects
tshark -r capture.pcap --export-objects http,/tmp/http-objects/

# SMB objects (files transferred)
tshark -r capture.pcap --export-objects smb,/tmp/smb-objects/

# NetworkMiner GUI: Files tab — automatic per-protocol extraction
```

## Verifying success

- A list of `<protocol> | <host:port> | <username> | <password/hash>` rows extracted.
- Cracked hashes match successful logins on the target service.
- Extracted session cookies replay successfully against the target web app.

## Common pitfalls

- **Truncated pcaps** (snaplen limits) cut off the credential portion — re-capture with `-s 0`.
- **TCP segmentation** of HTTP requests can split the Authorization header across packets — tshark with `--reassemble-tcp` is required.
- **TLS / encrypted traffic** is opaque without keys. Don't waste time grepping pcap for plaintext on port 443.
- **NTLMv1 vs v2** uses different hashcat modes — Pcredz prefixes correctly.
- **Kerberos pre-auth without weak encryption** (RC4) is harder to crack — AES is far slower.
- **Old tools (Pcredz, net-creds) are Python 2** — may need a virtualenv or container.
- **NetworkMiner Free** has limits on automated extraction; the Professional license unlocks more file types.
- **HTTP/2 binary framing** breaks naive grep — use HTTP/2-aware tools.

## Tools

- Pcredz (multi-protocol credential extraction)
- NetworkMiner (GUI, comprehensive)
- tshark / Wireshark (manual analysis with display filters)
- net-creds (legacy CLI)
- dsniff suite (`dsniff`, `mailsnarf`, `urlsnarf`)
- hcxpcapngtool (WPA handshake conversion)
- hashcat / john (offline cracking)
- kerbrute / kerberize (Kerberos hash extraction helpers)
