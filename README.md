# ctf-skills

[Agent Skills](https://agentskills.io) for solving CTF challenges — web exploitation, binary pwn, crypto, reverse engineering, forensics, OSINT, and more. Works with any tool that supports the Agent Skills spec, including [Claude Code](https://docs.anthropic.com/en/docs/claude-code).

## Installation

```bash
npx skills add ljagiello/ctf-skills
```

## Skills

| Skill | Files | Description |
|-------|-------|-------------|
| **ctf-web** | 6 | SQLi, XSS, SSTI, SSRF, JWT, prototype pollution, file upload RCE, Node.js VM escape, XXE, JSFuck, Web3/Solidity, delegatecall abuse, Groth16 proof forgery, phantom market unresolve, HAProxy bypass, polyglot XSS, CVEs, HTTP TRACE bypass, LLM jailbreak, Tor fuzzing, SSRF→Docker API RCE, PHP type juggling, PHP LFI / php://filter |
| **ctf-pwn** | 6 | Buffer overflow, ROP chains, SROP with UTF-8 constraints, format string, heap exploitation, FSOP, GC null-ref cascading corruption, stride-based OOB leak, canary byte-by-byte brute force, seccomp bypass, sandbox escape, custom VMs, VM UAF slab reuse, kernel pwn |
| **ctf-crypto** | 8 | RSA (small e, common modulus, Wiener, Fermat, Pollard p-1, Hastad broadcast, Coppersmith, Manger), AES, ECC, PRNG, ZKP, Groth16 broken setup, DV-SNARG forgery, braid group DH, LWE/CVP lattice attacks, AES-GCM, classic/modern ciphers, Kasiski examination, multi-byte XOR frequency analysis, S-box collision, GF(2) CRT, historical ciphers, OTP key reuse, logistic map PRNG, RsaCtfTool |
| **ctf-reverse** | 3 | Binary analysis, custom VMs, WASM, RISC-V, Rust serde, Python bytecode, OPAL, UEFI, game clients, anti-debug, Binary Ninja, dogbolt.org, Sprague-Grundy game theory, kernel module maze solving, multi-threaded VM channels, multi-layer self-decrypting brute-force, convergence bitmap, .NET/Android RE |
| **ctf-forensics** | 7 | Disk/memory forensics, Windows/Linux forensics, steganography, network captures, tcpdump, TLS/SSL keylog decryption, USB HID drawing, UART decode, side-channel power analysis, packet timing, 3D printing, signals/hardware (VGA, HDMI, DisplayPort), BMP bitplane QR, image puzzle reassembly, audio FFT notes, KeePass v4 cracking |
| **ctf-osint** | 3 | Social media, geolocation, Street View panorama matching, username enumeration, DNS recon, archive research, Google dorking, Telegram bots, FEC filings |
| **ctf-malware** | 3 | Obfuscated scripts, C2 traffic, custom crypto protocols, .NET malware, PyInstaller unpacking, PE analysis, sandbox evasion |
| **ctf-misc** | 6 | Pyjails, bash jails, encodings, RF/SDR, DNS exploitation, Unicode stego, floating-point tricks, game theory, commitment schemes, WASM, K8s, custom assembly sandbox escape, ML weight perturbation negation, cookie checkpoint, Flask cookie leakage, WebSocket game manipulation, Whitespace esolang, Docker group privesc |
| **solve-challenge** | 0 | Orchestrator skill — analyzes challenge and delegates to category skills |

## Usage

Skills are loaded automatically based on context. You can also invoke the orchestrator directly:

```
/solve-challenge <challenge description or URL>
```

## License

MIT
