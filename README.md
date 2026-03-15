# ctf-skills

[Agent Skills](https://agentskills.io) for solving CTF challenges — web exploitation, binary pwn, crypto, reverse engineering, forensics, OSINT, and more. Works with any tool that supports the Agent Skills spec, including [Claude Code](https://docs.anthropic.com/en/docs/claude-code).

## Installation

```bash
npx skills add ljagiello/ctf-skills
```

## Skills

| Skill | Files | Description |
|-------|-------|-------------|
| **ctf-web** | 6 | SQLi, XSS, SSTI, SSRF, JWT (JWK/JKU/KID injection), prototype pollution, file upload RCE, Node.js VM escape, XXE, JSFuck, Web3/Solidity, delegatecall abuse, Groth16 proof forgery, phantom market unresolve, HAProxy bypass, polyglot XSS, CVEs, HTTP TRACE bypass, LLM jailbreak, Tor fuzzing, SSRF→Docker API RCE, PHP type juggling, PHP LFI / php://filter, DOM XSS jQuery hashchange, XML entity WAF bypass, React Server Components Flight RCE (CVE-2025-55182), XS-Leak timing oracle, GraphQL CSRF, SSTI `__dict__.update()` quote bypass, ERB SSTI Sequel bypass, affine cipher OTP brute-force, Express.js `%2F` middleware bypass, IDOR on WIP endpoints |
| **ctf-pwn** | 6 | Buffer overflow, ROP chains, ret2csu, ret2vdso, bad char XOR bypass, exotic gadgets (BEXTR/XLAT/STOSB/PEXT), stack pivot (xchg rax,esp), SROP with UTF-8 constraints, format string, heap exploitation (unlink, House of Apple 2, Einherjar), FSOP, GC null-ref cascading corruption, stride-based OOB leak, canary byte-by-byte brute force, seccomp bypass, sandbox escape, custom VMs, VM UAF slab reuse, io_uring UAF SQE injection, integer truncation int32→int16, Linux kernel exploitation (ret2usr, kernel ROP prepare_kernel_cred/commit_creds, modprobe_path, core_pattern, tty_struct kROP, userfaultfd race, SLUB heap spray, KPTI trampoline/signal handler bypass, KASLR/FGKASLR __ksymtab bypass, SMEP/SMAP, GDB module debugging, initramfs/virtio-9p workflow) |
| **ctf-crypto** | 8 | RSA (small e, common modulus, Wiener, Fermat, Pollard p-1, Hastad broadcast, Coppersmith, Manger, Manger OAEP timing, p=q bypass, cube root CRT, phi multiple factoring), AES, ECC (Ed25519 torsion side channel), ECDSA nonce reuse, PRNG, ZKP, Groth16 broken setup, DV-SNARG forgery, braid group DH, LWE/CVP lattice attacks, AES-GCM, classic/modern ciphers, Kasiski examination, multi-byte XOR frequency analysis, S-box collision, GF(2) CRT, historical ciphers, OTP key reuse, logistic map PRNG, RsaCtfTool, tropical semiring residuation |
| **ctf-reverse** | 3 | Binary analysis, custom VMs, WASM, RISC-V, Rust serde, Python bytecode, OPAL, UEFI, game clients, anti-debug, pwntools binary patching, Binary Ninja, dogbolt.org, Sprague-Grundy game theory, kernel module maze solving, multi-threaded VM channels, multi-layer self-decrypting brute-force, convergence bitmap, .NET/Android RE, CVP/LLL lattice validation, JNI RegisterNatives, decision tree obfuscation, GLSL shader VM, GF(2^8) Gaussian elimination, Z3 single-line Python circuit, sliding window popcount, Ruby/Perl polyglot |
| **ctf-forensics** | 7 | Disk/memory forensics, RAID 5 XOR recovery, Windows/Linux forensics, steganography, network captures, tcpdump, TLS/SSL keylog decryption, USB HID drawing, UART decode, side-channel power analysis, packet timing, 3D printing, signals/hardware (VGA, HDMI, DisplayPort), BMP bitplane QR, image puzzle reassembly, audio FFT notes, KeePass v4 cracking, cross-channel multi-bit LSB, F5 JPEG DCT detection, PNG palette stego, keyboard acoustic side-channel, TCP flag covert channel, Brotli decompression bomb seam, Git reflog/fsck squash recovery |
| **ctf-osint** | 3 | Social media, geolocation, Google Lens cropped region search, reflected/mirrored text reading, Street View panorama matching, What3Words micro-landmark matching, username enumeration, DNS recon, archive research, Google dorking, Telegram bots, FEC filings |
| **ctf-malware** | 3 | Obfuscated scripts, C2 traffic, custom crypto protocols, .NET malware, PyInstaller unpacking, PE analysis, sandbox evasion |
| **ctf-misc** | 6 | Pyjails, bash jails, encodings, RF/SDR, DNS exploitation, Unicode stego, floating-point tricks, game theory, commitment schemes, WASM, K8s, custom assembly sandbox escape, ML weight perturbation negation, cookie checkpoint, Flask cookie leakage, WebSocket game manipulation, Whitespace esolang, Docker group privesc, LoRA adapter weight merging, De Bruijn sequence, Brainfuck instrumentation, WASM linear memory manipulation, quine context detection, repunit decomposition |
| **solve-challenge** | 0 | Orchestrator skill — analyzes challenge and delegates to category skills |

## Usage

Skills are loaded automatically based on context. You can also invoke the orchestrator directly:

```
/solve-challenge <challenge description or URL>
```

## License

MIT
