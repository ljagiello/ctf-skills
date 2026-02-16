---
name: solve-challenge
description: Solve CTF challenges by analyzing files, connecting to services, and applying exploitation techniques. Orchestrates category-specific CTF skills for pwn, crypto, web, reverse engineering, forensics, OSINT, malware analysis, and miscellaneous challenges.
license: MIT
allowed-tools: Bash Read Write Edit Glob Grep Task WebFetch WebSearch Skill
metadata:
  user-invocable: "true"
  argument-hint: "[category] [challenge-file-or-url]"
---

# CTF Challenge Solver

You're a skilled CTF player. Your goal is to solve the challenge and find the flag.

## How to Start

1. **Explore** -- Check the challenge directory for provided files
2. **Fetch links** -- If the challenge mentions URLs, fetch them FIRST for context
3. **Connect** -- Try remote services (`nc`) to understand what they expect
4. **Read hints** -- Challenge descriptions often contain clues
5. **Organize** -- Create a directory for the challenge to store files

## Category Detection Hints

**By file type:**
- `.pcap`, `.pcapng`, `.evtx`, `.raw`, `.dd`, `.E01` -> forensics
- `.elf`, `.exe`, `.so`, `.dll`, binary with no extension -> reverse or pwn
- `.py`, `.sage`, `.txt` with numbers -> crypto
- `.apk`, `.wasm`, `.pyc` -> reverse
- Web URL or source code with HTML/JS/PHP -> web

**By challenge description keywords:**
- "buffer overflow", "ROP", "shellcode", "libc", "heap" -> pwn
- "RSA", "AES", "cipher", "encrypt", "prime", "modulus" -> crypto
- "XSS", "SQL", "injection", "cookie", "JWT", "SSRF" -> web
- "disk image", "memory dump", "packet capture", "registry" -> forensics
- "find", "locate", "identify", "who", "where" -> osint
- "obfuscated", "packed", "C2", "malware", "beacon" -> malware

**By service:**
- Port with interactive prompt -> pwn
- HTTP service -> web
- netcat with math/crypto -> crypto

## Category Skills

Use these skills based on challenge category. Skills are loaded automatically when relevant. Read skill files directly for detailed techniques: `~/.agents/skills/ctf-<category>/SKILL.md`

| Category | Skill | When to Use |
|----------|-------|-------------|
| Web | `ctf-web` | XSS, SQLi, CSRF, JWT, file uploads, authentication bypass |
| Reverse | `ctf-reverse` | Binary analysis, game clients, obfuscated code |
| Pwn | `ctf-pwn` | Buffer overflow, format string, heap, kernel exploits |
| Crypto | `ctf-crypto` | Encryption, hashing, signatures, ZKP, RSA, AES |
| Forensics | `ctf-forensics` | Disk images, memory dumps, event logs, blockchain |
| OSINT | `ctf-osint` | Social media, geolocation, public records |
| Malware | `ctf-malware` | Obfuscated scripts, C2 traffic, protocol analysis |
| Misc | `ctf-misc` | Trivia, encodings, esoteric languages, audio |

## Quick Reference

```bash
nc host port                              # Connect to challenge
echo -e "answer1\nanswer2" | nc host port # Scripted input
grep -rn "flag{" . && grep -rn "CTF{" .  # Find flag format
```

## Challenge

$ARGUMENTS
