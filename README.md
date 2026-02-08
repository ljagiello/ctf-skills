# ctf-skills

[Claude Code](https://docs.anthropic.com/en/docs/claude-code) skills for solving CTF challenges — web exploitation, binary pwn, crypto, reverse engineering, forensics, OSINT, and more.

## Installation

```bash
npx skills add ljagiello/ctf-skills
```

## Skills

| Skill | Description |
|-------|-------------|
| **ctf-web** | SQLi, XSS, SSTI, SSRF, JWT, prototype pollution, file upload RCE, Node.js VM escape, XXE, JSFuck, Web3/Solidity, CVEs |
| **ctf-pwn** | Buffer overflow, format string, `__free_hook`, ROP chains, heap exploitation, signed int bypass, canary-aware overflow, seccomp bypass, kernel pwn |
| **ctf-crypto** | RSA, AES, ECC, PRNG, ZKP, S-box collision, Manger's oracle, GF(2) CRT, affine ciphers, historical ciphers |
| **ctf-reverse** | Binary analysis, custom VMs, WASM, Rust serde, Python bytecode, OPAL, UEFI, game clients, anti-debug, .NET/Android RE |
| **ctf-forensics** | Disk images, memory dumps, Windows forensics, 3D printing, network captures, PDF/border stego, blockchain |
| **ctf-osint** | Social media, geolocation, username enumeration, DNS recon, archive research |
| **ctf-malware** | Obfuscated scripts, C2 traffic, custom crypto protocols, .NET malware, PyInstaller unpacking |
| **ctf-misc** | Pyjails, bash jails, encodings, RF/SDR, DNS exploitation, Unicode stego, floating-point tricks |
| **find-skills** | Discover and install additional agent skills from the open ecosystem |
| **solve-challenge** | Orchestrator skill — analyzes challenge and delegates to category skills |

## Usage

Skills are loaded automatically based on context. You can also invoke the orchestrator directly:

```
/solve-challenge <challenge description or URL>
```

## License

MIT
