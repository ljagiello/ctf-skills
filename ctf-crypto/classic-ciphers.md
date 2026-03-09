# CTF Crypto - Classic Ciphers

## Table of Contents
- [Vigenere Cipher](#vigenere-cipher)
- [Atbash Cipher](#atbash-cipher)
- [Substitution Cipher with Rotating Wheel](#substitution-cipher-with-rotating-wheel)
- [XOR Variants](#xor-variants)
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
