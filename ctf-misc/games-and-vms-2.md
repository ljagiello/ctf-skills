# CTF Misc - Games, VMs & Constraint Solving (Part 2)

## Table of Contents
- [ML Model Weight Perturbation Negation (DiceCTF 2026)](#ml-model-weight-perturbation-negation-dicectf-2026)
- [Cookie Checkpoint Game Brute-Forcing (BYPASS CTF 2025)](#cookie-checkpoint-game-brute-forcing-bypass-ctf-2025)
- [Flask Session Cookie Game State Leakage (BYPASS CTF 2025)](#flask-session-cookie-game-state-leakage-bypass-ctf-2025)
- [WebSocket Game Manipulation + Cryptic Hint Decoding (BYPASS CTF 2025)](#websocket-game-manipulation--cryptic-hint-decoding-bypass-ctf-2025)
- [Server Time-Only Validation Bypass (BYPASS CTF 2025)](#server-time-only-validation-bypass-bypass-ctf-2025)
- [LoRA Adapter Weight Merging and Visualization (ApoorvCTF 2026)](#lora-adapter-weight-merging-and-visualization-apoorvctf-2026)
- [De Bruijn Sequence for Substring Coverage (BearCatCTF 2026)](#de-bruijn-sequence-for-substring-coverage-bearcatctf-2026)
- [Brainfuck Interpreter Instrumentation (BearCatCTF 2026)](#brainfuck-interpreter-instrumentation-bearcatctf-2026)
- [WASM Linear Memory Manipulation (BearCatCTF 2026)](#wasm-linear-memory-manipulation-bearcatctf-2026)
- [Neural Network Encoder Collision via Optimization (RootAccess2026)](#neural-network-encoder-collision-via-optimization-rootaccess2026)
- [ML Model Inversion via Gradient Descent (BSidesSF 2025)](#ml-model-inversion-via-gradient-descent-bsidessf-2025)
- [References](#references)

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

## Neural Network Encoder Collision via Optimization (RootAccess2026)

**Pattern (The AI Techbro):** Neural network encoder (e.g., 16D → 4D) replaces password hashing. Find a 16-character alphanumeric input whose encoder output is within distance threshold (e.g., 0.00025) of a target vector.

**Why it's exploitable:** 16D → 4D compression discards ~50+ bits of information, guaranteeing many collisions. Unlike cryptographic hashes, neural encoders have smooth loss landscapes amenable to gradient-free optimization.

```python
import torch
import numpy as np
import random

# Load the encoder model
encoder = Encoder()
encoder.load_state_dict(torch.load('encoder_weights.npz'))
encoder.eval()

target = torch.tensor([-8.175, -1.710, -0.700, 5.345])
CHARS = 'abcdefghijklmnopqrstuvwxyz0123456789'

def encode_string(s):
    return [(ord(c) - 80) / 40 for c in s]

def distance(password):
    inp = torch.tensor([encode_string(password)], dtype=torch.float32)
    with torch.no_grad():
        out = encoder(inp).squeeze()
    return torch.dist(out, target).item()

# Phase 1: Greedy local search (fast convergence)
def greedy_search(password):
    current = list(password)
    improved = True
    while improved:
        improved = False
        for pos in range(len(current)):
            best_char, best_dist = current[pos], distance(''.join(current))
            for c in CHARS:
                current[pos] = c
                d = distance(''.join(current))
                if d < best_dist:
                    best_dist, best_char, improved = d, c, True
            current[pos] = best_char
            if best_dist < 0.00025:
                return ''.join(current), best_dist
    return ''.join(current), distance(''.join(current))

# Phase 2: Simulated annealing (escape local minima)
def simulated_annealing(password, iters=10000):
    current = list(password)
    best = current[:]
    best_dist = distance(''.join(best))
    T_start, T_end = 0.3, 0.00005
    for i in range(iters):
        T = T_start * (T_end / T_start) ** (i / iters)
        neighbor = current[:]
        for _ in range(random.randint(1, 3)):
            neighbor[random.randint(0, len(neighbor)-1)] = random.choice(CHARS)
        d = distance(''.join(neighbor))
        if d < distance(''.join(current)) or random.random() < np.exp(-(d - distance(''.join(current))) / T):
            current = neighbor
            if d < best_dist:
                best, best_dist = neighbor[:], d
        if best_dist < 0.00025:
            break
    return ''.join(best), best_dist

# Combined: random restart + greedy + SA + greedy refinement
for _ in range(100):
    pw = ''.join(random.choices(CHARS, k=16))
    pw, d = greedy_search(pw)
    if d < 0.00025: break
    pw, d = simulated_annealing(pw)
    pw, d = greedy_search(pw)
    if d < 0.00025: break
```

**Key insight:** Dimensionality reduction (16D → 4D) guarantees collisions. Greedy search converges quickly for smooth loss surfaces; simulated annealing escapes local minima. Combined approach with random restarts finds solutions in seconds. This attack applies to any neural encoder used as a hash function.

**Detection:** Challenge provides a trained model file (`.npz`, `.pt`, `.h5`) and asks for an input matching a target output. Encoder architecture reduces dimensionality.

---

## ML Model Inversion via Gradient Descent (BSidesSF 2025)

Extract training images from an overfitted neural network classifier by optimizing inputs to maximize class activation:

```python
import tensorflow as tf
import numpy as np

def invert_model(model, target_class, input_shape=(64, 64, 1), steps=5000, lr=0.1):
    """Recover training image by maximizing target class activation"""
    # Start from random noise
    image = tf.Variable(tf.random.uniform(input_shape, 0, 1))

    for step in range(steps):
        with tf.GradientTape() as tape:
            prediction = model(tf.expand_dims(image, 0))
            loss = -prediction[0][target_class]  # Maximize target class

        gradients = tape.gradient(loss, image)
        image.assign_sub(lr * gradients)
        # Clip to valid pixel range
        image.assign(tf.clip_by_value(image, 0.0, 1.0))

    return image.numpy()

# Extract one image per class
for class_id in range(num_classes):
    recovered = invert_model(model, class_id)
    plt.imsave(f'class_{class_id}.png', recovered.squeeze(), cmap='gray')
```

**Key insight:** Overfitted models (~24M parameters for 4 classes) memorize training data almost exactly. Gradient descent on the input pixels converges to the memorized training image. Works best on models with high parameter-to-class ratios and greyscale inputs. For color images, optimize each channel independently or jointly.

**Detection signs:** Model file is unusually large relative to the task complexity; few output classes but many parameters.

---

## References
- DiceCTF 2026 "leadgate": ML weight perturbation negation for flag extraction
- BYPASS CTF 2025 "Signal from the Deck": Cookie checkpoint game brute-forcing
- BYPASS CTF 2025 "Hungry, Not Stupid": Flask cookie game state leakage
- BYPASS CTF 2025 "Maze of the Unseen": WebSocket teleportation + cryptic hints
- BYPASS CTF 2025 "Level Devil": Server time-only validation bypass
- ApoorvCTF 2026 "Hefty Secrets": LoRA adapter weight merging and bitmap visualization
- BearCatCTF 2026 "Brown's Revenge": De Bruijn sequence substring coverage
- BearCatCTF 2026 "Ghost Ship": Brainfuck instrumentation brute-force
- BearCatCTF 2026 "Dubious Doubloon": WASM linear memory state patching
- RootAccess2026 "The AI Techbro": Neural network encoder collision via greedy + simulated annealing
- BSidesSF 2025: ML model inversion via gradient descent for training data extraction

---

See also: [games-and-vms.md](games-and-vms.md) for WASM patching, Roblox reversing, PyInstaller, Z3, K8s RBAC, floating-point exploitation, custom assembly sandbox escape, and multi-phase crypto games.
