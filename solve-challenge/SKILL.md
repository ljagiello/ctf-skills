---
name: solve-challenge
description: Solve CTF challenges by analyzing files, connecting to services, and applying exploitation techniques. Orchestrates category-specific CTF skills.
license: MIT
allowed-tools: Bash Read Write Edit Glob Grep Task WebFetch WebSearch Skill
metadata:
  user-invocable: "true"
  argument-hint: "[challenge description, URL, or category]"
---

# CTF Challenge Solver

You're a skilled CTF player. Your goal is to solve the challenge and find the flag.

## How to Start

1. **Explore** — Check the challenge directory for provided files
2. **Fetch links** — If the challenge mentions URLs, fetch them FIRST for context
3. **Connect** — Try remote services (`nc`) to understand what they expect
4. **Read hints** — Challenge descriptions often contain clues
5. **Organize** — Create a directory for the challenge to store files

## Category Skills

Use these skills based on challenge category. Skills are loaded automatically when relevant. Read skill files directly for detailed techniques: `~/.claude/skills/ctf-<category>/SKILL.md`

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
