# TCP Stream Extraction

## When this applies

You have a PCAP and need to view, extract, or reassemble the contents of a single TCP conversation: HTTP body, plain-text protocol payload, file transfer, or shell session. Use this any time `--export-objects` is too aggressive (binary protocol) or you need exact byte-level fidelity.

## Technique

Wireshark labels every TCP conversation with a numeric `tcp.stream` index starting at 0. Filter by `tcp.stream eq N` to isolate one conversation, then dump the bytes with Wireshark "Follow > TCP Stream", `tshark -z follow,tcp,raw,N`, or scapy reassembly.

## Steps

1. List all TCP streams with byte counts:
   ```bash
   tshark -r capture.pcap -q -z conv,tcp
   ```
   Identify suspect streams by destination port, byte count, or peer IP.
2. Inspect a stream interactively:
   ```bash
   tshark -r capture.pcap -Y "tcp.stream eq 3" -V | less
   ```
3. Extract raw bytes (concatenates both directions):
   ```bash
   tshark -r capture.pcap -q -z follow,tcp,raw,3 > stream3.txt
   ```
   The dump includes a header; strip it and `xxd -r -p` to recover binary.
4. Direction-split extraction with scapy (when raw mode merges client/server bytes you need separate):
   ```python
   from scapy.all import rdpcap, TCP, IP
   c2s, s2c = b"", b""
   for p in rdpcap("capture.pcap"):
       if TCP in p and p[TCP].payload:
           if (p[IP].src, p[TCP].sport) == ("10.0.0.5", 4444):
               s2c += bytes(p[TCP].payload)
           else:
               c2s += bytes(p[TCP].payload)
   open("c2s.bin","wb").write(c2s)
   open("s2c.bin","wb").write(s2c)
   ```
5. For HTTP, prefer `--export-objects http,out/` then `file out/*` to dispatch on type.

## Verifying success

- Output starts with a known protocol marker (`HTTP/`, `220 ` for FTP, `SSH-2.0`, `MZ` for PE binary).
- File size matches `tcp.stream` byte total from `conv,tcp`.
- For binaries, `file extracted.bin` returns the expected type.

## Common pitfalls

- `follow,tcp,raw` interleaves directions with no separator. Use ascii mode (`follow,tcp,ascii,N`) to preserve direction markers, or split with scapy.
- Streams with retransmissions or out-of-order segments need Wireshark's reassembly (enabled by default). Manual scapy concatenation is wrong if there are gaps — verify `tcp.analysis.flags` is empty.
- Large PCAPs (>500 MB) hang Wireshark UI. Use `tshark -2` (two-pass) for accurate stream indexing on disk.
- `tcp.stream` indices are not stable across PCAPs even from the same session — always recompute per file.

## Tools

- `tshark` — `-q -z conv,tcp`, `-z follow,tcp,raw,N`, `-Y "tcp.stream eq N"`
- Wireshark — Statistics > Conversations > TCP, right-click "Follow > TCP Stream"
- scapy — `rdpcap`, manual reassembly with direction filtering
- `editcap -A start -B end capture.pcap subset.pcap` — slice by time before extraction
