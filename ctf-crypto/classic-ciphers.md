# CTF Crypto - Classic Ciphers

## Table of Contents
- [Vigenere Cipher](#vigenere-cipher)
- [Atbash Cipher](#atbash-cipher)
- [Substitution Cipher with Rotating Wheel](#substitution-cipher-with-rotating-wheel)
- [Kasiski Examination for Key Length](#kasiski-examination-for-key-length)
- [XOR Variants](#xor-variants)
  - [Multi-Byte XOR Key Recovery via Frequency Analysis](#multi-byte-xor-key-recovery-via-frequency-analysis)
- [Deterministic OTP with Load-Balanced Backends (Pragyan 2026)](#deterministic-otp-with-load-balanced-backends-pragyan-2026)
- [Book Cipher](#book-cipher)

---

## Vigenere Cipher

**Known Plaintext Attack (most common in CTFs):**
```python
def vigenere_decrypt(ciphertext, key):
    result = []
    key_index = 0
    for c in ciphertext:
        if c.isalpha():
            shift = ord(key[key_index % len(key)].upper()) - ord('A')
            base = ord('A') if c.isupper() else ord('a')
            result.append(chr((ord(c) - base - shift) % 26 + base))
            key_index += 1
        else:
            result.append(c)
    return ''.join(result)

def derive_key(ciphertext, plaintext):
    """Derive key from known plaintext (e.g., flag format CCOI26{)"""
    key = []
    for c, p in zip(ciphertext, plaintext):
        if c.isalpha() and p.isalpha():
            c_val = ord(c.upper()) - ord('A')
            p_val = ord(p.upper()) - ord('A')
            key.append(chr((c_val - p_val) % 26 + ord('A')))
    return ''.join(key)
```

### Kasiski Examination for Key Length

When no known plaintext is available, determine the Vigenere key length using Kasiski examination: find repeated sequences in the ciphertext and compute the GCD of their distances.

```python
from math import gcd
from functools import reduce
from collections import Counter

def kasiski_examination(ciphertext, min_seq=3):
    """Find repeating sequences and compute likely key lengths."""
    ct = ''.join(c.upper() for c in ciphertext if c.isalpha())
    distances = []

    # Find repeated trigrams and their distances
    for seq_len in range(min_seq, 6):
        seen = {}
        for i in range(len(ct) - seq_len):
            seq = ct[i:i+seq_len]
            if seq in seen:
                for prev_pos in seen[seq]:
                    distances.append(i - prev_pos)
                seen[seq].append(i)
            else:
                seen[seq] = [i]

    # Key length is likely the GCD of distances
    if distances:
        key_len = reduce(gcd, distances)
        print(f"Likely key length: {key_len}")
        print(f"All distances: {sorted(set(distances))}")
        return key_len
    return None

def frequency_attack(ciphertext, key_length):
    """Break Vigenere by frequency analysis on each key-position group."""
    ct = [c.upper() for c in ciphertext if c.isalpha()]
    english_freq = [0.082,0.015,0.028,0.043,0.127,0.022,0.020,0.061,0.070,
                   0.002,0.008,0.040,0.024,0.067,0.075,0.019,0.001,0.060,
                   0.063,0.091,0.028,0.010,0.023,0.002,0.020,0.001]
    key = []

    for i in range(key_length):
        group = [ct[j] for j in range(i, len(ct), key_length)]
        # Try each shift, score by English letter frequency
        best_shift, best_score = 0, -1
        for shift in range(26):
            decrypted = [chr((ord(c) - ord('A') - shift) % 26 + ord('A')) for c in group]
            freq = Counter(decrypted)
            score = sum(freq.get(chr(j+65), 0) / len(group) * english_freq[j]
                       for j in range(26))
            if score > best_score:
                best_score = score
                best_shift = shift
        key.append(chr(best_shift + ord('A')))

    return ''.join(key)
```

**Key insight:** Repeated sequences in Vigenere ciphertext occur at distances that are multiples of the key length. The GCD of all such distances reveals the key length, after which each position becomes a simple Caesar cipher solvable by frequency analysis.

**When standard keys don't work:**
1. Key may not repeat - could be as long as message
2. Key derived from challenge theme (character names, phrases)
3. Key may have "padding" - repeated letters (IICCHHAA instead of ICHA)
4. Try guessing plaintext words from theme, derive full key

---

## Atbash Cipher

Simple substitution: A<->Z, B<->Y, C<->X, etc.

```python
def atbash(text):
    return ''.join(
        chr(ord('Z') - (ord(c.upper()) - ord('A'))) if c.isalpha() else c
        for c in text
    )
```

**Identification:** Challenge name hints ("Abashed" = Atbash), preserves spaces/punctuation, 1-to-1 substitution.

---

## Substitution Cipher with Rotating Wheel

**Pattern (Wheel of Mystery):** Physical cipher wheel with inner/outer alphabets.

**Automated solver:** Use [quipqiup.com](https://quipqiup.com/) for general substitution ciphers — it uses word pattern matching and language entropy to solve without knowing the key.

**Brute force all rotations:**
```python
outer = "ABCDEFGHIJKLMNOPQRSTUVWXYZ{}"
inner = "QNFUVWLEZYXPTKMR}ABJICOSDHG{"  # Given

for rotation in range(len(outer)):
    rotated = inner[rotation:] + inner[:rotation]
    mapping = {outer[i]: rotated[i] for i in range(len(outer))}
    decrypted = ''.join(mapping.get(c, c) for c in ciphertext)
    if decrypted.startswith("METACTF{"):
        print(decrypted)
```

---

## XOR Variants

### Multi-Byte XOR Key Recovery via Frequency Analysis

**Pattern:** Ciphertext XOR'd with a repeating multi-byte key. Key length unknown.

**Step 1 — Determine key length:** Try each candidate length, split ciphertext into groups by position modulo key length, score each group's byte frequency against English text (space = 0x20 is the most common byte).

**Step 2 — Recover each key byte:** For each position, brute-force all 256 byte values and select the one producing the most English-like decrypted text.

```python
from collections import Counter

def score_english(data):
    """Score how English-like a byte sequence is."""
    freq = Counter(data)
    # Space is the most common character in English text
    return freq.get(ord(' '), 0) + sum(freq.get(c, 0) for c in range(ord('a'), ord('z')+1))

def find_key_length(ciphertext, max_len=40):
    """Test key lengths by scoring single-byte XOR on each column."""
    best_len, best_score = 1, 0
    for kl in range(1, max_len + 1):
        total = 0
        for col in range(kl):
            group = ciphertext[col::kl]
            best_col_score = max(
                score_english(bytes(b ^ k for b in group))
                for k in range(256)
            )
            total += best_col_score
        if total > best_score:
            best_score = total
            best_len = kl
    return best_len

def recover_key(ciphertext, key_length):
    """Recover each key byte via frequency analysis."""
    key = []
    for col in range(key_length):
        group = ciphertext[col::key_length]
        best_k = max(range(256), key=lambda k: score_english(bytes(b ^ k for b in group)))
        key.append(best_k)
    return bytes(key)

ct = open('encrypted.bin', 'rb').read()
kl = find_key_length(ct)
key = recover_key(ct, kl)
print(f"Key ({kl} bytes): {key}")
print(bytes(c ^ key[i % len(key)] for i, c in enumerate(ct)))
```

**Key insight:** Multi-byte repeating XOR splits into `key_length` independent single-byte XOR problems. English text frequency (especially space = 0x20) reliably identifies correct key bytes. Works best with ciphertext longer than ~100 bytes.

### Cascade XOR (First-Byte Brute Force)

**Pattern (Shifty XOR):** Each byte XORed with previous ciphertext byte.

```python
# c[i] = p[i] ^ c[i-1] (or similar cascade)
# Brute force first byte, rest follows deterministically
for first_byte in range(256):
    flag = [first_byte]
    for i in range(1, len(ct)):
        flag.append(ct[i] ^ flag[i-1])
    if all(32 <= b < 127 for b in flag):
        print(bytes(flag))
```

### XOR with Rotation: Power-of-2 Bit Isolation (Pragyan 2026)

**Pattern (R0tnoT13):** Given `S XOR ROTR(S, k)` for multiple rotation offsets k, recover S.

**Key insight:** When ALL rotation offsets are powers of 2 (2, 4, 8, 16, 32, 64), even-indexed and odd-indexed bits NEVER mix across any frame. This reduces N-bit recovery to just 2 bits of brute force.

**Algorithm:**
1. Express every bit of S in terms of two unknowns (s_0 for even bits, s_1 for odd bits) using the k=2 frame
2. Only 4 candidate states -> try all, verify against all frames
3. XOR valid state with ciphertext -> plaintext

### Weak XOR Verification Brute Force (Pragyan 2026)

**Pattern (Dor4_Null5):** Verification XORs all comparison bytes into a single byte instead of checking each individually.

**Vulnerability:** Any fixed response has 1/256 probability of passing. With enough interaction budget (e.g., 4919 attempts), brute-force succeeds with ~256 expected attempts.

```python
for attempt in range(3000):
    r.sendlineafter(b"prompt: ", b"00" * 8)  # Fixed zero response
    result = r.recvline()
    if b"successful" in result:
        break
```

---

## Deterministic OTP with Load-Balanced Backends (Pragyan 2026)

**Pattern (DumCows):** Service encrypts data with deterministic keystream that resets per connection. Multiple backends with different keystreams behind a load balancer.

**Attack:**
1. Send known plaintext (e.g., 18 bytes of 'A'), XOR with ciphertext -> recover keystream
2. XOR keystream with target ciphertext -> decrypt secret
3. **Backend matching:** Must connect to same backend for keystream to match. Retry connections until patterns align.

```python
def recover_keystream(known, ciphertext):
    return bytes(k ^ c for k, c in zip(known, ciphertext))

def decrypt(keystream, target_ct):
    return bytes(k ^ c for k, c in zip(keystream, target_ct))
```

**Key insight:** When encryption is deterministic per connection with no nonce/IV, known-plaintext attack is trivial. The challenge is matching backends.

---

## OTP Key Reuse / Many-Time Pad XOR (BYPASS CTF 2025)

**Pattern (Once More Unto the Same Wind):** Two ciphertexts encrypted with the same OTP key. Known plaintext for one message enables recovery of the other.

**XOR property:** `C1 XOR C2 = P1 XOR P2` (key cancels). When one plaintext (P1) is known, recover the other: `P2 = C1 XOR C2 XOR P1`.

```python
from pwn import xor

c1 = bytes.fromhex("7713283f5e9979...")
c2 = bytes.fromhex("740b393f4c8b67...")

# If one plaintext is known (or guessable, e.g., padded 'A' chars)
known_plaintext = b"A" * len(c1)
flag = xor(xor(c1, c2), known_plaintext)
print(flag)
```

**When plaintext is unknown — crib dragging:**
```python
def crib_drag(c1, c2, crib, max_pos=None):
    """Slide known word across XOR of two ciphertexts."""
    xored = xor(c1[:min(len(c1), len(c2))], c2[:min(len(c1), len(c2))])
    for pos in range(len(xored) - len(crib)):
        candidate = xor(xored[pos:pos+len(crib)], crib)
        if all(32 <= b < 127 for b in candidate):
            print(f"pos {pos}: {candidate}")
```

**Key insight:** OTP (One-Time Pad) XOR encryption is only secure when the key is truly one-time. Reusing the key on two messages leaks `P1 XOR P2` — exploit with known plaintext or crib dragging.

---

## Book Cipher

**Pattern (Booking Key, Nullcon 2026):** Book cipher with "steps forward" encoding. Brute-force starting position with charset filtering reduces ~56k candidates to 3-4.

See [historical.md](historical.md) for full implementation.
