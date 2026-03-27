---
name: solve-challenge
description: Solves CTF challenges by analyzing files, connecting to services, and applying exploitation techniques. Orchestrates category-specific CTF skills for pwn, crypto, web, reverse engineering, forensics, OSINT, malware analysis, and miscellaneous challenges. Use when given a CTF challenge to solve, a challenge file to analyze, or a service endpoint to exploit.
license: MIT
compatibility: Requires filesystem-based agent (Claude Code or similar) with bash, Python 3, and internet access. Orchestrates other ctf-* skills.
allowed-tools: Bash Read Write Edit Glob Grep Task WebFetch WebSearch Skill
metadata:
  user-invocable: "true"
  argument-hint: "[category] [challenge-file-or-url]"
---

# CTF Challenge Solver

You're a skilled CTF player. Your goal is to solve the challenge and find the flag.

## Environment Setup

Two setup strategies depending on your workflow:

### Pre-install (recommended before competitions)

**Python packages (all platforms):**
```bash
pip install pwntools pycryptodome z3-solver sympy gmpy2 hashpumpy fpylll py_ecc \
  angr frida-tools qiling requests flask-unsign sqlmap \
  ropper ROPgadget volatility3 yara-python pefile capstone \
  oletools unicorn scapy Pillow numpy matplotlib shodan \
  uncompyle6 lief dnspython dnslib dissect.cobaltstrike
```

**Linux (apt):**
```bash
apt install gdb radare2 binutils binwalk foremost libimage-exiftool-perl \
  tshark sleuthkit ffmpeg steghide testdisk john pcapfix \
  nmap whois dnsutils hashcat strace ltrace imagemagick curl jq \
  apktool upx qemu-system-x86 sagemath qrencode
```

**macOS (Homebrew):**
```bash
brew install gdb radare2 binutils binwalk exiftool wireshark sleuthkit \
  ffmpeg testdisk john-jumbo nmap whois bind hashcat ghidra \
  imagemagick curl jq apktool upx qemu qrencode
```

**Ruby gems (all platforms):**
```bash
gem install one_gadget seccomp-tools zsteg
```

**Go tools (all platforms, requires Go):**
```bash
go install github.com/ffuf/ffuf/v2@latest
```

**Manual install:**
- pwndbg — Linux: [github.com/pwndbg/pwndbg](https://github.com/pwndbg/pwndbg), macOS: `brew install pwndbg/tap/pwndbg-gdb`
- RsaCtfTool — `git clone https://github.com/RsaCtfTool/RsaCtfTool`
- SageMath — Linux: `apt install sagemath`, macOS: `brew install --cask sage`
- steghide — Linux: `apt install steghide` (not available via Homebrew)
- dnSpy — [github.com/dnSpy/dnSpy](https://github.com/dnSpy/dnSpy) (.NET decompiler, Windows)

### On-demand (during challenges)

Each category skill's `SKILL.md` has a **Prerequisites** section listing only the tools needed for that category. Install as you go.

## Workflow

### Step 1: Recon

1. **Explore files** -- List the challenge directory, run `file *` on everything
2. **Triage binaries** -- `strings`, `xxd | head`, `binwalk`, `checksec` on binaries
3. **Fetch links** -- If the challenge mentions URLs, fetch them FIRST for context
4. **Connect** -- Try remote services (`nc`) to understand what they expect
5. **Read hints** -- Challenge descriptions, filenames, and comments often contain clues

### Step 2: Categorize

Determine the primary category, then invoke the matching skill.

**By file type:**
- `.pcap`, `.pcapng`, `.evtx`, `.raw`, `.dd`, `.E01` -> forensics
- `.elf`, `.exe`, `.so`, `.dll`, binary with no extension -> reverse or pwn (check if remote service provided -- if yes, likely pwn)
- `.py`, `.sage`, `.txt` with numbers -> crypto
- `.apk`, `.wasm`, `.pyc` -> reverse
- Web URL or source code with HTML/JS/PHP/templates -> web
- Images, audio, PDFs with no obvious content -> forensics (steganography)

**By challenge description keywords:**
- "buffer overflow", "ROP", "shellcode", "libc", "heap" -> pwn
- "RSA", "AES", "cipher", "encrypt", "prime", "modulus", "lattice", "LWE", "GCM" -> crypto
- "XSS", "SQL", "injection", "cookie", "JWT", "SSRF" -> web
- "disk image", "memory dump", "packet capture", "registry", "power trace", "side-channel", "spectrogram", "audio tracks", "MKV" -> forensics
- "find", "locate", "identify", "who", "where" -> osint
- "obfuscated", "packed", "C2", "malware", "beacon" -> malware
- "jail", "sandbox", "escape", "encoding", "signal", "game", "Nim", "commitment", "Gray code" -> misc

**By service behavior:**
- Port with interactive prompt, crash on long input -> pwn
- HTTP service -> web
- netcat with math/crypto puzzles -> crypto
- netcat with restricted shell or eval -> misc (jail)

### Step 3: Invoke the Category Skill

Once you identify the category, **invoke the matching skill** to get specialized techniques:

| Category | Invoke | When to Use |
|----------|--------|-------------|
| Web | `/ctf-web` | XSS, SQLi, SSTI, SSRF, JWT, file uploads, prototype pollution |
| Pwn | `/ctf-pwn` | Buffer overflow, format string, heap, ROP, sandbox escape |
| Crypto | `/ctf-crypto` | RSA, AES, ECC, PRNG, ZKP, classical ciphers |
| Reverse | `/ctf-reverse` | Binary analysis, game clients, VMs, obfuscated code |
| Forensics | `/ctf-forensics` | Disk images, memory dumps, event logs, stego, network captures |
| OSINT | `/ctf-osint` | Social media, geolocation, DNS, public records |
| Malware | `/ctf-malware` | Obfuscated scripts, C2 traffic, PE/.NET analysis |
| Misc | `/ctf-misc` | Jails, encodings, RF/SDR, esoteric languages, constraint solving |

You can also invoke `/ctf-<category>` to load the full skill instructions with detailed techniques.

### Step 4: Pivot When Stuck

If your first approach doesn't work:

1. **Re-examine assumptions** -- Is this really the category you think? A "web" challenge might need crypto for JWT forgery. A "forensics" PCAP might contain a pwn exploit to replay.
2. **Try a different category skill** -- Many challenges span multiple categories. Invoke a second skill for the cross-cutting technique.
3. **Look for what you missed** -- Hidden files, alternate ports, response headers, comments in source, metadata in images.
4. **Simplify** -- If an exploit is too complex, check if there's a simpler path (default creds, known CVE, logic bug).
5. **Check edge cases** -- Off-by-one, race conditions, integer overflow, encoding mismatches.

**Common multi-category patterns:**
- Forensics + Crypto: encrypted data in PCAP/disk image, need crypto to decrypt
- Web + Reverse: WASM or obfuscated JS in web challenge
- Web + Crypto: JWT forgery, custom MAC/signature schemes
- Reverse + Pwn: reverse the binary first, then exploit the vulnerability
- Forensics + OSINT: recover data from dump, then trace it via public sources
- Misc + Crypto: jail escape requires building crypto primitives under constraints
- OSINT + Stego: social media posts with unicode homoglyph steganography (Cyrillic lookalikes encode bits)
- Web + Forensics: paywall bypass (curl reveals content hidden by CSS overlays)
- Misc + Crypto + Game Theory: multi-phase interactive challenges with AES decryption → HMAC commitment → combinatorial game solving (GF(256) Nim)
- Crypto + Geometry + Lattice: multi-layer challenges progressing from spatial reconstruction → subspace recovery → LWE solving → AES-GCM decryption
- Forensics + Signal Processing: power traces / side-channel analysis requiring statistical analysis of measurement data
- Forensics + Network + Encoding: timing-based encoding in PCAP (inter-packet intervals encode binary data)

## Flag Formats

Flags vary by CTF. Common formats:
- `flag{...}`, `FLAG{...}`, `CTF{...}`, `TEAM{...}`
- Custom prefixes: check the challenge description or CTF rules for the format (e.g., `ENO{...}`, `HTB{...}`, `picoCTF{...}`)
- Sometimes just a plaintext string with no wrapper

**Validation rule (important):**
- If you find multiple flag-like strings, treat them as candidates and validate before finalizing.
- Prefer the token tied to the intended artifact/workflow (not random metadata noise or obvious decoys).
- Do a corpus-wide uniqueness check and include the source file/path when reporting.

```bash
# Search for common flag patterns in files
grep -rniE '(flag|ctf|eno|htb|pico)\{' .
# Search in binary/memory output
strings output.bin | grep -iE '\{.*\}'
```

## Quick Reference

```bash
# Recon
file *                                    # Identify file types
strings binary | grep -i flag             # Quick string search
xxd binary | head -20                     # Hex dump header
binwalk -e firmware.bin                   # Extract embedded files
checksec --file=binary                    # Check binary protections

# Connect
nc host port                              # Connect to challenge
echo -e "answer1\nanswer2" | nc host port # Scripted input
curl -v http://host:port/                 # HTTP recon

# Python exploit template
python3 -c "
from pwn import *
r = remote('host', port)
r.interactive()
"
```

## Challenge

$ARGUMENTS
