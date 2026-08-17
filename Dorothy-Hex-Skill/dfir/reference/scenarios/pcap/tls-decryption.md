# TLS Decryption in Wireshark

## When this applies

A PCAP contains TLS-encrypted traffic (HTTPS, IMAPS, mTLS) and you need to read the plaintext for forensic analysis. Decryption is feasible when (a) you have the SSLKEYLOGFILE the client wrote, or (b) you have the server's RSA private key and the cipher uses RSA key exchange (no PFS).

## Technique

Wireshark/tshark can decrypt TLS sessions by feeding it ephemeral keying material. The portable approach is the `SSLKEYLOGFILE` text format, which most browsers, curl, Python, Go, and OpenSSL builds will write when the env var is set. Each line records `<label> <client_random> <key>`, allowing decryption of any modern TLS 1.2/1.3 handshake including PFS ciphers.

## Steps

1. Capture or obtain the keylog file. To produce one yourself:
   ```bash
   export SSLKEYLOGFILE=/tmp/keys.log
   curl https://target/ -o /dev/null
   firefox  # writes ephemeral keys for every session
   ```
2. Configure Wireshark:
   - Edit > Preferences > Protocols > TLS
   - "(Pre)-Master-Secret log filename" = path to keys.log
   - Enable "Reassemble TLS records spanning multiple TCP segments"
3. Open the PCAP — TLS streams now decode. Confirm by selecting a TLS frame; "Decrypted TLS" tab appears.
4. tshark equivalent:
   ```bash
   tshark -r capture.pcap -o tls.keylog_file:/tmp/keys.log \
     -Y http -T fields -e http.host -e http.request.uri
   ```
5. Server private-key path (RSA-only, no DHE/ECDHE):
   - Preferences > Protocols > TLS > RSA keys list
   - Add `ip,port,protocol,/path/to/server.key`
   - Will fail silently for any cipher with `_DHE_` or `_ECDHE_` in the name.
6. Export decrypted HTTP objects after enabling decryption:
   ```bash
   tshark -r capture.pcap -o tls.keylog_file:/tmp/keys.log \
     --export-objects "http,decrypted_objs" -q
   ```

## Verifying success

- Wireshark shows "Decrypted TLS" tab on TLS application data frames.
- `tshark ... -Y http` returns rows (the filter only matches decrypted HTTP, not encrypted TCP).
- File magic bytes appear at the start of `Application Data` payloads.

## Common pitfalls

- TLS 1.3 requires the keylog file (private key alone never works, all TLS 1.3 uses ephemeral DH).
- Keylog file must include lines for the exact `Client Random` of the captured handshake — partial captures (missing `Client Hello`) cannot be decrypted even with the right key.
- macOS Wireshark caches preferences per-pcap-load. After changing the keylog path, close and re-open the PCAP.
- Some apps (Java without `-Djavax.net.debug=ssl:keymanager`, Go before 1.8) do not honor `SSLKEYLOGFILE`.
- mTLS handshakes need the server keylog from the server side; client-side keylog is sufficient for mutual TLS as long as the *client* wrote the keylog.

## Tools

- Wireshark / tshark — `tls.keylog_file` preference
- `curl --insecure --tls-export-secrets`-style flags (varies by build)
- `mitmproxy` — auto-writes keylog at `~/.mitmproxy/sslkeys.log` when used as proxy
- Python `ssl.SSLContext.keylog_filename` for scripted captures
