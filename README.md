# ctf-skills

[![skills.sh](https://skills.sh/b/yuzu-octopus/ctf-skills)](https://skills.sh/yuzu-octopus/ctf-skills)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python: >=3.12](https://img.shields.io/badge/Python->=3.12-3776AB.svg?logo=python&logoColor=white)](pyproject.toml)

[Agent Skills](https://agentskills.io) for solving CTF challenges — web exploitation, binary pwn, cryptography, reverse engineering, forensics, OSINT, and more. Compatible with all AI agents supporting the Agent Skills specification, including [Claude Code](https://docs.anthropic.com/en/docs/claude-code), Codex, OpenCode, Cursor, and Gemini CLI.

> [!NOTE]
> This repository is an enhanced, modernized fork of [ljagiello/ctf-skills](https://github.com/ljagiello/ctf-skills) (upstream PR: [#86](https://github.com/ljagiello/ctf-skills/pull/86)). It replaces multi-gigabyte SageMath prerequisites with lean pure-Python libraries, incorporates 2024–2026 CTF techniques across all categories, provides standalone executable templates with streaming payload generators, integrates on-demand PayloadsAllTheThings wordlists, and passes a comprehensive 95-test verification suite.

---

## Why This Fork?

| Feature | Upstream (`ljagiello/ctf-skills`) | This Fork (`yuzu-octopus/ctf-skills`) |
|---|---|---|
| **Crypto Runtime** | Hard SageMath dependency (~2–6 GB install, fails in CI) | **100% Pure-Python default** (`fpylll`, `sympy`, `gmpy2`, `py_ecc`). Sage code preserved in `<details>` collapsed fallbacks. |
| **PQC & Modern Lattices** | Basic LWE notes | **NTRU lattices, GGH CVP embedding, Mersenne AJPS small roots, BDD with predicate, ML-KEM/Kyber negacyclic flattening**. |
| **Web Exploitation** | Static narrative notes | **Burp Intruder parity (`python-requests.md`)** with `ThreadPoolExecutor` (30 workers) and `httpx` async (100 concurrency), generator streaming feeds, and `async_fuzz.py`. |
| **Payload Lists** | No external wordlist integration | **[PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) on-demand shallow clone & index (`pat-reference.md`)** without repository bloat. |
| **Binary Exploitation** | Inline snippets only | **5 standalone runnable pwntools 4.15.0 templates** (`ctf-pwn/scripts/`) with `yield` generators for ret2libc, SROP, shellcraft, format strings, and seccomp ORW. |
| **Heap & Kernel Pwn** | Pre-2023 techniques | **glibc 2.39 tcache key protection + calloc changes, dedicated largebin attack guide, io_uring `CVE-2024-0582`, CET Shadow Stack signal-frame bypass, House of Tangerine**. |
| **Reverse Engineering** | Scattered Unicorn one-liners | **1313-line comprehensive Unicorn CPU emulation guide (`unicorn-emulation.md`)** with hooks, mixed-mode 64→32 `retf` with XMM0–15 state preservation, MMIO peripherals, and Keystone trace inversion. |
| **Misc & Pyjails** | Pre-2022 pyjails | **2024–2025 JailCTF coverage:** audit-hook trampolines (4 families), Filter'd length-limit trampolines, full NFKC compatibility decomposition, and modern filter trios (`impossible`/`one`/`primal`). |
| **Quality & CI** | Markdown-only syntax checks | **95 automated unit tests**, a 364-fence code verifier, and full compliance across all skills under `skill_security_auditor.py`. |

---

## Installation

### Install via Skills CLI (Recommended)

Install all 10 skills in the `ctf-skills` group at once:

```bash
npx skills add yuzu-octopus/ctf-skills --all
```

Or install with [Bun](https://bun.sh):

```bash
bunx skills add yuzu-octopus/ctf-skills --all
```

To install specific skills individually:

```bash
npx skills add yuzu-octopus/ctf-skills --skill ctf-crypto --skill ctf-pwn --skill ctf-web
```

To install to a specific AI coding agent:

```bash
npx skills add yuzu-octopus/ctf-skills --all -a claude-code
npx skills add yuzu-octopus/ctf-skills --all -a cursor
npx skills add yuzu-octopus/ctf-skills --all -a codex
```

### Grouping as a Pack (`ctf-skills`)

You can access or share this entire collection as a single unified pack:

1. **Repository Group (Automatic):** The `skills` CLI natively groups all skills under the repository slug `yuzu-octopus/ctf-skills`. Running `npx skills add yuzu-octopus/ctf-skills` displays an interactive selection menu of all CTF capabilities.
2. **Skills.sh Pack:** Visit [skills.sh/packs](https://skills.sh/packs) to bundle public skills from `yuzu-octopus/ctf-skills` into an unlisted custom pack named `ctf-skills` to generate an immediate install link:
   ```bash
   npx skills add https://skills.sh/p/<pack-id>
   ```

---

## Run with Friday Studio

Want these skills as part of an autonomous workflow with schedules, signals, and MCP tools? Load them into [Friday](https://hellofriday.ai/), the AI workspace runtime from [Tempest Labs](https://hellofriday.ai/).

Friday Studio loads skills into agent context on demand and executes them inside reproducible local workspaces. Everything runs locally on your machine with step-by-step auditing.

To add these skills to Friday Studio:

1. Install Friday from [hellofriday.ai](https://hellofriday.ai/) (macOS).
2. Open **Skills** in the Studio sidebar and click **+ Add**.
3. Import individual skills by reference (e.g. `yuzu-octopus/ctf-skills/ctf-web`), or upload this repository as a folder.
4. Reference them from any `workspace.yml`, or let agents load them automatically based on the challenge description.

See the [Friday Skills docs](https://docs.hellofriday.ai/core-concepts/skills) and the [Friday blog](https://blog.hellofriday.ai/) for more details.

---

## Environment Setup

Two setup strategies depending on your competition workflow:

### Pre-install (Recommended before competitions)

Use the central installer script to configure tools and dependencies:

```bash
bash scripts/install_ctf_tools.sh all
```

To install a specific subsystem:

```bash
bash scripts/install_ctf_tools.sh python   # Core Python libraries (fpylll, pwntools, sympy, etc.)
bash scripts/install_ctf_tools.sh pat      # PayloadsAllTheThings on-demand shallow clone
bash scripts/install_ctf_tools.sh apt      # Linux system packages (gdb, radare2, binutils, etc.)
bash scripts/install_ctf_tools.sh brew     # macOS Homebrew packages
bash scripts/install_ctf_tools.sh gems     # Ruby gems (one_gadget, seccomp-tools)
bash scripts/install_ctf_tools.sh go       # Go tools (ffuf)
bash scripts/install_ctf_tools.sh manual   # Display manual tool guides
```

Dry-run to preview actions without installing:

```bash
bash scripts/install_ctf_tools.sh --dry-run all
```

Verify installed tools and Python modules:

```bash
bash scripts/install_ctf_tools.sh --verify
```

> [!TIP]
> The `pat` mode shallow-clones [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) (~30 seconds) into `~/.ctf-tools/PayloadsAllTheThings` and creates a symlink to `ctf-web/payloads/PayloadsAllTheThings`. It is web-only and git-ignored, ensuring the main repository stays lightweight.

### On-demand (During challenges)

Each skill's `SKILL.md` contains a **Prerequisites** section with exact pinned versions. You can execute tools ephemerally without global pollution using `uv`:

```bash
# Example: Running the web fuzzer
uv run --with requests --with httpx python ctf-web/scripts/async_fuzz.py --help

# Example: Testing a crypto solver
uv run --with fpylll --with cysignals --with sympy python -c "from fpylll import IntegerMatrix, LLL; print('Lattice ready')"
```

---

## Skills Catalog

| Skill | Category | Detail Files | Description & Highlights |
|---|---|:---:|---|
| **ctf-crypto** | Cryptography | 18 | **Sage-free pure-Python cryptography.** RSA (Wiener, Boneh-Durfee $d<N^{0.292}$, partial-$d$ exposure, Hastad linear padding, Franklin-Reiter, Williams $p+1$, ECM, clean LSB binary search oracle), AES/AEAD (ChaCha20-Poly1305 nonce reuse tag forgery, GCM forbidden attack, partitioning oracles), ECC (5 invalid curve variants, Smart $p$-adic Newton lift, MOV pairing, twist attacks, SIDH Castryck-Decru warning, CSIDH volcano walk), Lattices/PQC (fpylll Howgrave-Graham lattice builder, NTRU negacyclic basis, GGH CVP embedding, Mersenne AJPS small roots, BDD with predicate, ML-KEM/Kyber flattening), PRNG (PCG XSL-RR, xoroshiro/xoshiro, BBS parity trap, Henon/Arnold chaos), stream ciphers (Spritz/VMPC/RC4A, Trivium cube attack). |
| **ctf-pwn** | Binary Exploitation | 18 | **Modern Linux & Windows binary exploitation.** 5 runnable `pwntools==4.15.0` template scripts in `ctf-pwn/scripts/` with `yield` payload generators (ret2libc, SROP with UTF-8 spanning, shellcraft asm, format string write-size suites, seccomp ORW). Heap exploitation (glibc 2.39 tcache key protection + calloc behavior, dedicated largebin attack guide, House of Apple 2 with setcontext SUID pivot, House of Tangerine/Emma/Water/Einherjar). Kernel exploitation (io_uring `CVE-2024-0582` PBUF_RING, CET Shadow Stack signal-frame bypass, KASLR, SMEP/SMAP, ret2usr, modprobe_path). |
| **ctf-web** | Web Exploitation | 22 | **Modern web application security & automation.** Burp Intruder parity (`python-requests.md`) with sync, 30-worker `ThreadPoolExecutor`, and 100-concurrency `httpx` async engines; streaming payload generators; CLI fuzzer (`async_fuzz.py`); PayloadsAllTheThings index (`pat-reference.md`). SQL injection (blind boolean/time/error generators, second-order, WAF bypasses), XSS (AngularJS sandbox escapes, DOM clobbering, CSP bypasses), SSTI (Jinja2, Twig, Go template FuncMap), SSRF (DNS rebinding, cloud metadata), XXE, file upload polyglots, deserialization (Java ysoserial, Python pickle, PHP), JWT (key confusion, dynamic length RSA parameters), OAuth/OIDC, and prototype pollution. |
| **ctf-reverse** | Reverse Engineering | 19 | **Static and dynamic binary analysis.** 1313-line Unicorn CPU emulation guide (`unicorn-emulation.md`) covering raw shellcode, execution hooks, mixed-mode 64→32 `retf` with XMM0–15 state preservation, firmware MMIO peripherals, and Keystone+Capstone trace inversion. Custom VM reversing and bytecode lifting to LLVM IR, WASM, RISC-V, Go (GoReSym), Rust, Python bytecode, Android APK/DEX/JNI, anti-debugging, anti-VM, and control flow flattening deobfuscation. |
| **ctf-misc** | Miscellaneous | 12 | **Jails, encodings, and esoteric challenges.** 2024–2025 JailCTF coverage: Python audit-hook trampolines across 4 families, Filter'd length-limit trampolines, full NFKC compatibility decomposition, and modern filter trios (`impossible`/`one`/`primal`). Encodings (base64→xor→zlib chains, binary-clean `auto_decode`, QR polyglots, Brainfuck dual-interpreter equality jails, DTMF, Gray code), bash jails (`BASH_ENV` vectors), game state solvers (Z3, WASM memory patching), RF/SDR, and DNS exfiltration. |
| **ctf-forensics** | Digital Forensics | 14 | Memory forensics with standardized Volatility 3 CLI (`vol`), disk image analysis (APFS, ext4, NTFS, RAID 5 reconstruction), packet capture analysis (Wireshark, tshark, TLS keylog decryption, USB HID keyboard/mouse decoding), steganography (LSB, Arnold cat map, spectrogram audio), firmware extraction, and event log triage. |
| **ctf-malware** | Malware Analysis | 3 | Static and dynamic analysis of obfuscated scripts, PE/.NET executables, Cobalt Strike beacon configuration extraction via `dissect.cobaltstrike`, C2 traffic protocol decryption, process injection detection, YARA rule authoring, and sandbox evasion analysis. |
| **ctf-ai-ml** | AI & Machine Learning | 3 | PyTorch 2.6+ model security (`weights_only=False` guidance), adversarial examples (FGSM, PGD with proper epsilon clamping), model inversion, neural network collisions, LoRA adapter exploitation, prompt injection, and LLM jailbreaking. |
| **ctf-osint** | Open Source Intelligence | 3 | Geolocation, social media investigations, Google Lens/Street View matching, What3Words, username enumeration across platforms, archive research, DNS historical records, and Shodan reconnaissance. |
| **solve-challenge** | Triage & Routing | 0 | Master orchestrator skill: analyzes challenge bundles, network endpoints, or file types and automatically routes execution to the appropriate category skill. |
| **ctf-writeup** | Writeup Generation | 0 | Automated generation of standardized, submission-style competition writeups with challenge metadata, solution steps, exploit scripts, and key insights. |

---

## Usage

Skills are loaded into agent context automatically based on task descriptions and tool invocations. You can also invoke the master orchestrator directly in your AI terminal:

```text
/solve-challenge <challenge description, file path, or connection info>
```

### Running Tests

Run the complete test suite across all categories:

```bash
uv run --with pytest --with requests --with httpx --with pwntools --with sympy --with gmpy2 --with fpylll --with cysignals --with pycryptodome --no-project python -m pytest tests/ -q
```

Validate all 364 code fences for syntax correctness:

```bash
uv run --no-project python scripts/verify_crypto_examples.py
```

Run the security auditor across skills:

```bash
for skill in ctf-crypto ctf-pwn ctf-web ctf-reverse ctf-misc ctf-forensics ctf-malware ctf-ai-ml ctf-osint; do
  uv run --no-project python scripts/skill_security_auditor.py "$skill" --strict --json
done
```
