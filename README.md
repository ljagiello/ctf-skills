# ctf-skills

[Agent Skills](https://agentskills.io) for solving CTF challenges — web exploitation, binary pwn, crypto, reverse engineering, forensics, OSINT, and more. Works with any tool that supports the Agent Skills spec, including [Claude Code](https://docs.anthropic.com/en/docs/claude-code).

## Installation

```bash
npx skills add ljagiello/ctf-skills
```

## Skills

| Skill | Files | Description |
|-------|-------|-------------|
| **ctf-web** | 6 | SQLi, XSS, SSTI, SSRF, JWT, prototype pollution, file upload RCE, Node.js VM escape, XXE, JSFuck, Web3/Solidity, delegatecall abuse, HAProxy bypass, polyglot XSS, CVEs |
| **ctf-pwn** | 6 | Buffer overflow, ROP chains, format string, heap exploitation, FSOP, seccomp bypass, sandbox escape, custom VMs, VM UAF slab reuse, kernel pwn |
| **ctf-crypto** | 8 | RSA, AES, ECC, PRNG, ZKP, LWE/CVP lattice attacks, AES-GCM, classic/modern ciphers, S-box collision, Manger's oracle, GF(2) CRT, historical ciphers |
| **ctf-reverse** | 3 | Binary analysis, custom VMs, WASM, RISC-V, Rust serde, Python bytecode, OPAL, UEFI, game clients, anti-debug, convergence bitmap, .NET/Android RE |
| **ctf-forensics** | 7 | Disk/memory forensics, Windows/Linux forensics, steganography, network captures, USB HID drawing, UART decode, side-channel power analysis, packet timing, 3D printing, signals/hardware (VGA, HDMI, DisplayPort) |
| **ctf-osint** | 3 | Social media, geolocation, Street View panorama matching, username enumeration, DNS recon, archive research, Google dorking, Telegram bots, FEC filings |
| **ctf-malware** | 3 | Obfuscated scripts, C2 traffic, custom crypto protocols, .NET malware, PyInstaller unpacking, PE analysis, sandbox evasion |
| **ctf-misc** | 6 | Pyjails, bash jails, encodings, RF/SDR, DNS exploitation, Unicode stego, floating-point tricks, game theory, commitment schemes, WASM, K8s, custom assembly sandbox escape |
| **solve-challenge** | 0 | Orchestrator skill — analyzes challenge and delegates to category skills |

## Usage

Skills are loaded automatically based on context. You can also invoke the orchestrator directly:

```
/solve-challenge <challenge description or URL>
```

## License

MIT
