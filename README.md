# ctf-skills

[Agent Skills](https://agentskills.io) for solving CTF challenges — web exploitation, binary pwn, crypto, reverse engineering, forensics, OSINT, and more. Works with any tool that supports the Agent Skills spec, including [Claude Code](https://docs.anthropic.com/en/docs/claude-code).

## Installation

```bash
npx skills add ljagiello/ctf-skills
```

## Environment Setup

Two setup strategies depending on your workflow:

### Pre-install (recommended before competitions)

Use the central installer entrypoint:

```bash
bash scripts/install_ctf_tools.sh all
```

Run a narrower mode when you only want one tool group:

```bash
bash scripts/install_ctf_tools.sh python
bash scripts/install_ctf_tools.sh pat
bash scripts/install_ctf_tools.sh apt
bash scripts/install_ctf_tools.sh brew
bash scripts/install_ctf_tools.sh gems
bash scripts/install_ctf_tools.sh go
bash scripts/install_ctf_tools.sh manual
```

Preview what would be installed (skips already-present packages):

```bash
bash scripts/install_ctf_tools.sh --dry-run all
```

Verify what's already installed:

```bash
bash scripts/install_ctf_tools.sh --verify
```

Use `--force` to reinstall everything regardless of what's already present. Install logs are saved to `~/.ctf-tools/`.

The full package lists now live in [scripts/install_ctf_tools.sh](scripts/install_ctf_tools.sh).

> [!TIP]
> The `pat` mode shallow-clones [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) into `~/.ctf-tools/PayloadsAllTheThings` and links it at `ctf-web/payloads/PayloadsAllTheThings`. Bulk payloads stay out of git; technique files reference `ctf-web/pat-reference.md` with a few exemplar payloads inline.

### On-demand (during challenges)

Each skill's `SKILL.md` has a **Prerequisites** section listing only the tools needed for that category. Install as you go when the agent encounters a missing tool.

## Skills

| Skill | Files | Description |
|-------|-------|-------------|
| **ctf-ai-ml** | 3 | Model weight perturbation negation, adversarial examples (FGSM, PGD, C&W), foolbox L1BasicIterativeAttack Keras evasion, hand-rolled Keras FGSM via K.gradients, prompt injection, LLM jailbreaking, model extraction, membership inference, neural network collision, LoRA adapter exploitation, gradient descent inversion, data poisoning, backdoor detection, token smuggling, context window manipulation |
| **ctf-web** | 22 | SQLi (blind boolean/time/error generators, second-order, WAF bypasses, EXIF metadata injection, keyword fragmentation bypass, MySQL column truncation, DNS record injection, ORDER BY CASE WHERE bypass, QR code input injection, double-keyword filter bypass), Burp Intruder parity via `python-requests.md` (sync, 30-worker `ThreadPoolExecutor`, 100-concurrency `httpx` async, generator streaming feeds, `async_fuzz.py` CLI fuzzer), PayloadsAllTheThings on-demand index (`pat-reference.md`), XSS (AngularJS sandbox escapes, DOM clobbering, CSP bypasses), SSTI (Jinja2, Twig, Go template FuncMap), SSRF (DNS rebinding, cloud metadata), XXE, file upload polyglots, deserialization (Java ysoserial, Python pickle, PHP), JWT (key confusion, dynamic length RSA parameters), OAuth/OIDC, prototype pollution |
| **ctf-pwn** | 18 | Buffer overflow, ROP chains, ret2csu, ret2vdso, vsyscall ROP PIE bypass, bad char XOR bypass, 5 runnable `pwntools==4.15.0` template scripts in `ctf-pwn/scripts/` with `yield` payload generators (ret2libc, SROP, shellcraft asm, format string write-size suites, seccomp ORW), heap exploitation (unlink, House of Force, largebin attack guide, glibc 2.39 tcache key protection + calloc behavior, House of Apple 2 + setcontext SUID variant, House of Tangerine/Emma/Water/Einherjar), kernel exploitation (io_uring `CVE-2024-0582`, CET Shadow Stack signal-frame bypass, KASLR, SMEP/SMAP, ret2usr, modprobe_path), format string, SROP with UTF-8 constraints |
| **ctf-crypto** | 19 | RSA (small e, common modulus, Wiener, Boneh-Durfee $d<N^{0.292}$, partial-$d$ exposure, Hastad broadcast, Hastad broadcast with linear padding Coppersmith, Coppersmith structured primes, Franklin-Reiter related message attack e=3, Manger, Manger OAEP timing, Williams $p+1$ + ECM chain, LSB binary search oracle, Fermat/consecutive primes, multi-prime, restricted-digit primes, p=q bypass, cube root CRT, phi multiple factoring, weak keygen base representation, gcd(e,phi)>1 exponent reduction, CRT fault attack, homomorphic decryption oracle bypass, small prime CRT decomposition, Montgomery timing, Bleichenbacher low-exponent forgery, e=1 bypass), AES (ECB byte-at-a-time, CBC bitflip + padding oracle, GCM nonce reuse forbidden attack, ChaCha20-Poly1305 nonce reuse, key-committing partitioning oracle), ECC (small subgroup, invalid curve 5 variants, Smart $p$-adic lift, MOV pairing, twist attacks, SIDH Castryck-Decru warning, CSIDH volcano walk, ECDSA nonce reuse, Ed25519 torsion), classic DH (trivial `g`, Pohlig-Hellman, Lim-Lee confinement), Lattices/PQC (fpylll Howgrave-Graham lattice, NTRU negacyclic basis, GGH CVP embedding, Mersenne AJPS small roots, BDD predicate, ML-KEM/Kyber flattening), PRNG/stream (PCG XSH-RR, xoroshiro/xoshiro, BBS parity, Henon/Arnold chaos, Spritz/VMPC/RC4A, Trivium cube attack) |
| **ctf-reverse** | 19 | Binary analysis, custom VMs (+ VM bytecode lifting to LLVM IR), WASM, RISC-V, Rust serde, Python bytecode, Unicorn CPU emulation guide (`unicorn-emulation.md`: hooks, mixed-mode 64→32 `retf` with XMM state preservation, MMIO peripherals, Keystone trace inversion), Go (GoReSym), Android APK/DEX/JNI, anti-debug, anti-VM, control flow flattening deobfuscation |
| **ctf-forensics** | 14 | Disk/memory forensics (GIMP raw memory dump visual inspection, Kyoto Cabinet hash DB forensics), RAID 5 XOR recovery, APFS snapshot recovery, Windows KAPE triage, Windows/Linux forensics, steganography (Arnold's Cat Map descrambling, MJPEG extra bytes after FFD9, high-res SSTV custom FM demodulation, EXIF zlib + triangular numbers LSB, PDF xref generation number covert channel, pixel-wise ECB deduplication image recovery), network captures, tcpdump, TLS/SSL keylog decryption, RDP session decryption via PKCS12 key extraction, USB HID drawing, USB HID keyboard capture decoding (+ arrow key navigation tracking), USB MIDI Launchpad traffic reconstruction, UART decode, serial UART data decoding from WAV audio, side-channel power analysi… |
| **ctf-osint** | 3 | Social media, geolocation, Google Lens cropped region search, reflected/mirrored text reading, Street View panorama matching, What3Words micro-landmark matching, Google Plus Codes, Baidu reverse image search, Overpass Turbo spatial queries, username enumeration, username metadata mining (postal codes), Strava fitness route OSINT, Google Maps photo verification, DNS recon, archive research, Google dorking (TBS image filters), Telegram bots, FEC filings, WHOIS investigation, music-themed landmark geolocation with key encoding, Shodan SSH fingerprint deanonymization, gaming platform OSINT (WoW/Steam/Minecraft character lookup), fake service banner detection via nmap fingerprinting, git commit author email mining for credential pivot, .DS_S… |
| **ctf-malware** | 3 | Obfuscated scripts, C2 traffic, custom crypto protocols, .NET malware, PyInstaller unpacking, PE analysis, sandbox evasion, anti-analysis (VM detection, timing evasion, API hashing, process injection), dynamic analysis (strace/ltrace, network monitoring, memory extraction), YARA rules, shellcode analysis, memory forensics (Volatility malfind, process injection), Poison Ivy RAT Camellia decryption, DarkComet RAT forensics (keylogger log recovery, registry persistence), Cobalt Strike beacon analysis (Malleable C2 detection, dissect.cobaltstrike config extraction), trojanized plugin custom alphabet C2 decoding, ARP spoof + TCP RST injection to capture IRC C2 credentials |
| **ctf-misc** | 12 | Pyjails (audit-hook trampolines across 4 families, Filter'd length-limit trampolines, full NFKC compatibility decomposition, modern filter trios, func_globals module chain, restricted charset number gen, class attribute persistence, name mangling + func_code.co_consts + __doc__ attribute access, f-string config injection via stored eval), bash jails (`BASH_ENV` vectors), encodings (two-pass `try_xor` + bytes-preserving `auto_decode`, base64→xor→zlib chains, QR polyglots, Brainfuck dual-interpreter equality jails, DTMF, Gray code, RTF custom tag extraction, SMS PDU decoding, RFC4042 UTF-9, pixel color binary encoding, TOPKEK binary encoding, MaxiCode 2D barcode decoding, DTMF audio + multi-tap T9 phone keypad, music note interval steganography), RF/SDR, DNS exploitation (+ round-robin A record enumeration), Unicode stego, floating-point tricks, game theory, commitment schemes, WASM, K8s, custom assembly sandbox escape, Lua sandbox escape (function name injection, table indexing bypass), Ruby sandbox escape via TracePoint.trace, cookie check… |
| **solve-challenge** | 0 | Orchestrator skill — analyzes challenge and delegates to category skills |
| **ctf-writeup** | 0 | Generates standardized submission-style writeups with metadata, solution steps, code, and lessons learned |

## Usage

Skills are loaded automatically based on context. You can also invoke the orchestrator directly:

```text
/solve-challenge <challenge description or URL>
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup and contribution guidelines.

## License

MIT
