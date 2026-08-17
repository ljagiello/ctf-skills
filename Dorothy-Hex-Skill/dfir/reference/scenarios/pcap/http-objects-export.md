# HTTP Object Export from PCAP

## When this applies

Investigating malware delivery, exfiltration, or webshell traffic in HTTP/HTTPS captures. You need every transferred file (HTML, JS, executables, uploads) carved to disk so you can `file`, `strings`, hash, and pivot into deeper analysis.

## Technique

Wireshark's "Export Objects > HTTP" reassembles chunked transfer-encoding, decompresses gzip/deflate, joins multipart bodies, and writes one file per request/response. `tshark --export-objects` is the scriptable form. Both treat the PCAP in two passes for full reassembly.

## Steps

1. One-shot dump (TLS first if needed — see tls-decryption.md):
   ```bash
   mkdir -p http_objects
   tshark -r capture.pcap --export-objects "http,http_objects" -q
   ```
2. List with size and type:
   ```bash
   ls -la http_objects/
   file http_objects/*
   ```
3. Triage by content:
   ```bash
   # Suspicious binaries
   for f in http_objects/*; do
     head -c 4 "$f" | xxd | grep -q '4d5a' && echo "MZ: $f"
   done
   # Webshell strings
   strings http_objects/* | grep -iE 'eval|base64_decode|powershell|<?php|cmd.exe' | head
   ```
4. For multipart uploads (POSTs), bodies are saved as the URI. Grep request URIs first:
   ```bash
   tshark -r capture.pcap -Y "http.request" -T fields \
     -e ip.src -e http.request.method -e http.host -e http.request.uri
   ```
5. For TLS-encrypted HTTPS, set `tls.keylog_file` via `-o`:
   ```bash
   tshark -r capture.pcap -o tls.keylog_file:keys.log \
     --export-objects "http,http_objects" -q
   ```
6. HTTP/2 traffic uses a separate dispatcher:
   ```bash
   tshark -r capture.pcap --export-objects "http2,h2_objects" -q
   ```

## Verifying success

- File count matches `tshark -r capture.pcap -Y http.response -T fields -e http.content_length | wc -l` (approximately).
- `file` produces correct types — gzip should be auto-decompressed (no `gzip compressed data` results).
- For exfil, sum of POST body sizes matches the bytes seen in the relevant tcp.stream.

## Common pitfalls

- Names collide on duplicate URIs — Wireshark suffixes with `(N)`. Don't assume one URI = one file.
- Streamed responses with Content-Length missing may truncate. Compare extracted size to `tshark` reported `http.content_length`.
- Server compressed responses with Brotli are **not** decompressed by Wireshark (only gzip/deflate). Decode manually with `brotli -d`.
- Connect-tunneled HTTPS won't be exported until TLS is decrypted.
- Filenames with path-traversal characters (e.g. `../`) get sanitized by tshark — but inspect filesystem on Linux carefully.

## Tools

- `tshark --export-objects http,DIR` (also `http2`, `smb`, `tftp`, `dicom`, `imf`)
- Wireshark > File > Export Objects > HTTP
- `NetworkMiner` (Windows/mono) — also extracts files plus credentials, OS fingerprinting
- `chaosreader` — perl tool for older PCAPs, splits per-stream HTML reports
