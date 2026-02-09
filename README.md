# ctf-skills

[Claude Code](https://docs.anthropic.com/en/docs/claude-code) skills for solving CTF challenges — web exploitation, binary pwn, crypto, reverse engineering, forensics, OSINT, and more.

## Installation

```bash
npx skills add ljagiello/ctf-skills
```

## Skills

| Skill | Files | Description |
|-------|-------|-------------|
| **ctf-web** | 6 | SQLi, XSS, SSTI, SSRF, JWT, prototype pollution, file upload RCE, Node.js VM escape, XXE, JSFuck, Web3/Solidity, CVEs |
| **ctf-pwn** | 5 | Buffer overflow, ROP chains, format string, heap exploitation, seccomp bypass, sandbox escape, custom VMs, kernel pwn |
| **ctf-crypto** | 8 | RSA, AES, ECC, PRNG, ZKP, classic/modern ciphers, S-box collision, Manger's oracle, GF(2) CRT, historical ciphers |
| **ctf-reverse** | 3 | Binary analysis, custom VMs, WASM, Rust serde, Python bytecode, OPAL, UEFI, game clients, anti-debug, .NET/Android RE |
| **ctf-forensics** | 6 | Disk/memory forensics, Windows/Linux forensics, steganography, network captures, 3D printing, blockchain |
| **ctf-osint** | 0 | Social media, geolocation, username enumeration, DNS recon, archive research |
| **ctf-malware** | 0 | Obfuscated scripts, C2 traffic, custom crypto protocols, .NET malware, PyInstaller unpacking |
| **ctf-misc** | 6 | Pyjails, bash jails, encodings, RF/SDR, DNS exploitation, Unicode stego, floating-point tricks, WASM, K8s |
| **find-skills** | 0 | Discover and install additional agent skills from the open ecosystem |
| **solve-challenge** | 0 | Orchestrator skill — analyzes challenge and delegates to category skills |

## Usage

Skills are loaded automatically based on context. You can also invoke the orchestrator directly:

```
/solve-challenge <challenge description or URL>
```

## License

MIT
