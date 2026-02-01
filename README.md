# ctf-skills

[Claude Code](https://docs.anthropic.com/en/docs/claude-code) skills for solving CTF challenges — web exploitation, binary pwn, crypto, reverse engineering, forensics, OSINT, and more.

## Installation

```bash
npx skills add ljagiello/ctf-skills
```

## Skills

| Skill | Description |
|-------|-------------|
| **ctf-web** | SQLi, XSS, SSTI, SSRF, JWT, prototype pollution, Web3, CVEs |
| **ctf-pwn** | Buffer overflow, format string, heap, seccomp bypass, kernel |
| **ctf-crypto** | RSA, AES, ECC, PRNG, hashing, ZKP, historical ciphers |
| **ctf-reverse** | Binary analysis, game clients, obfuscated code, esoteric languages |
| **ctf-forensics** | Disk images, memory dumps, event logs, network captures, blockchain |
| **ctf-osint** | Social media, geolocation, public records |
| **ctf-malware** | Obfuscated scripts, C2 traffic, protocol analysis |
| **ctf-misc** | Pyjails, bash jails, encodings, RF/SDR, automation |
| **solve-challenge** | Orchestrator skill — analyzes challenge and delegates to category skills |

## Usage

Skills are loaded automatically based on context. You can also invoke the orchestrator directly:

```
/solve-challenge <challenge description or URL>
```

## License

MIT
