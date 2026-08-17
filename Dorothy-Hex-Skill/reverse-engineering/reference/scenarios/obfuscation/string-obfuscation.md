# String Obfuscation — ROT, XOR, Custom Encodings

## When this applies

- `strings` yields almost no useful output, but the binary clearly does network / file / registry operations (so paths and URLs must exist somewhere).
- You see calls to a small "decoder" function before each suspicious operation, taking an offset/length and returning a string pointer.
- Common families: single-byte XOR, multi-byte XOR, Caesar/ROT, base64, custom alphabet encodings, RC4.
- Trigger keywords: "obfuscated strings", "encoded strings", "string decoder", "stack strings".

## Technique

Two complementary approaches:

1. **Static decode**: identify the encoding scheme (single-byte XOR with key, base64+XOR, etc.), then run the decoder offline on every encoded blob in the binary.
2. **Dynamic decode**: hook or emulate the decoder function at every call site, capture the decoded plaintext.

Static is faster when the algorithm is simple; dynamic is more reliable when the algorithm is complex or per-string keyed.

## Steps

### 1. Locate the decoder

```python
# In Ghidra or IDA: look for a function called many times that:
#  - Takes 1-2 small int args (offset, length) or a pointer
#  - Returns a string pointer
#  - References a large blob in .data / .rdata
```

Or scan strings for what *should* be there and isn't:
- HTTP-talking malware: no `http://`, no domain names visible → strings are encoded.
- File-touching malware: no `\\Users\\` or `/tmp/` → encoded paths.
- Persistent malware: no `Software\\Microsoft\\Windows\\CurrentVersion\\Run` → registry strings encoded.

### 2. Reverse the algorithm

Single-byte XOR is the most common:

```python
encoded = open('binary','rb').read()[blob_offset:blob_offset+blob_size]
for key in range(1, 256):
    decoded = bytes(c ^ key for c in encoded)
    if b'\x00' not in decoded[:20] and decoded[:5].decode('ascii', errors='ignore').isprintable():
        print(key, decoded[:80])
```

Multi-byte XOR with key length 2-16: `xortool` or hand-rolled with Kasiski/IC analysis.

For base64-then-XOR: decode base64 first, then XOR.

For custom alphabet:
```python
# Find the alphabet string in the decoder (look at .data references)
custom_alphabet = "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789..."
standard = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
# Translate, then std_b64decode
trans = str.maketrans(custom_alphabet, standard)
decoded = base64.b64decode(s.translate(trans))
```

### 3. Find all encoded blobs

Once the algorithm is known, scan the binary for blobs that decode to printable ASCII:

```python
binary = open('target.exe','rb').read()
key = 0x42
for offset in range(0, len(binary) - 4):
    for length in (8, 16, 32, 64, 128):
        candidate = bytes(c ^ key for c in binary[offset:offset+length])
        try:
            s = candidate.split(b'\x00')[0].decode('ascii')
            if s.isprintable() and len(s) >= 6:
                print(f"{offset:08x} ({length}): {s}")
        except UnicodeDecodeError:
            continue
```

### 4. Dynamic alternative — hook the decoder

If the algorithm is complex (RC4 with per-call key, multi-stage), emulate or hook:

```python
# Frida (cross-platform)
Interceptor.attach(Module.findExportByName(null, "decode_string"), {
    onEnter(args) { this.idx = args[0].toInt32(); },
    onLeave(retval) {
        console.log(this.idx, '->', retval.readUtf8String());
    }
});
```

Or `Unicorn`-emulate the decoder for each known call site, capturing the output.

### 5. Substitute in the analysis

In Ghidra: `Define Data > String` at the encoded blob's address, then add a comment with the decoded value. Better: write a Ghidra script that automates "for each call to decode_string, look up the index, decode, and add a comment at the call site."

```python
# Ghidra script
for ref in getReferencesTo(decode_func.entryPoint):
    call_site = ref.fromAddress
    # Find the constant arg (idx) just before the call
    idx_value = ...
    plaintext = decode_offline(blob[idx_value])
    setEOLComment(call_site, f'-> "{plaintext}"')
```

## Verifying success

- Decoded strings are printable, semantically meaningful (URLs / paths / commands).
- Annotated decompiled code reads naturally — `open_file(decode(123))` becomes `open_file("C:\\Windows\\Temp\\...")`.
- Cross-reference: the decoded string fits the calling context (a URL fed to `InternetOpenUrl`, a path fed to `CreateFile`).

## Common pitfalls

- **Wrong key.** Single-byte XOR brute force usually works in seconds; if no key produces printable output, the algorithm isn't single-byte XOR.
- **Mixed encodings.** Some samples use different keys for different categories of strings. Triage by length and offset clusters.
- **Stack strings missed.** Decoder may not exist as a function — strings are built byte-by-byte on the stack inline. Use FLOSS for this case (see `static-analysis/string-extraction.md`).
- **Encoding within encoding.** Base64-then-XOR-then-RC4 is real (some banking trojans). Identify each layer in turn.
- **Anti-RE encoding.** Some samples encode strings *as well as* shuffle the decode function's return path through callfuscation — linearize first (see `obfuscation/callfuscation.md`).

## Tools

- `xortool` (Python) — multi-byte XOR with key-length detection.
- `floss` (Mandiant) — stack strings and decoded strings.
- `cyberchef` — interactive multi-stage decoding (browser-based).
- `frida` — runtime hooking.
- `unicorn-engine` — emulate decoders without running the binary.
- Ghidra/IDA scripting — automate annotation of call sites.
