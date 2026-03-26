# CTF Crypto - Modern Cipher Attacks (Continued)

Hash-based attacks, protocol-level exploits, and specialized cipher weaknesses. For core AES/CBC/padding oracle techniques, see [modern-ciphers.md](modern-ciphers.md). For stream cipher attacks (LFSR, RC4, XOR), see [stream-ciphers.md](stream-ciphers.md).

## Table of Contents
- [CRC32 Collision-Based Signature Forgery (iCTF 2013)](#crc32-collision-based-signature-forgery-ictf-2013)
- [Blum-Goldwasser Bit-Extension Oracle (PlaidCTF 2013)](#blum-goldwasser-bit-extension-oracle-plaidctf-2013)
- [Hash Length Extension Attack (PlaidCTF 2014)](#hash-length-extension-attack-plaidctf-2014)
- [Compression Oracle / CRIME-Style Attack (BCTF 2015)](#compression-oracle--crime-style-attack-bctf-2015)
- [Hash Function Time Reversal via Cycle Detection (BSidesSF 2025)](#hash-function-time-reversal-via-cycle-detection-bsidessf-2025)
- [OFB Mode with Invertible RNG Backward Decryption (BSidesSF 2026)](#ofb-mode-with-invertible-rng-backward-decryption-bsidessf-2026)
- [Weak Key Derivation via Public Key Hash XOR (BSidesSF 2026)](#weak-key-derivation-via-public-key-hash-xor-bsidessf-2026)
- [HMAC-CRC Linearity Attack (Boston Key Party 2016)](#hmac-crc-linearity-attack-boston-key-party-2016)
- [DES Weak Keys in OFB Mode (Boston Key Party 2016)](#des-weak-keys-in-ofb-mode-boston-key-party-2016)
- [SRP (Secure Remote Password) Protocol Bypass via Modular Arithmetic (ASIS CTF Finals 2016)](#srp-secure-remote-password-protocol-bypass-via-modular-arithmetic-asis-ctf-finals-2016)
- [Modified AES S-Box Brute-Force Recovery (H4ckIT CTF 2016)](#modified-aes-s-box-brute-force-recovery-h4ckit-ctf-2016)
- [Square Attack on Reduced-Round AES (0CTF 2016)](#square-attack-on-reduced-round-aes-0ctf-2016)

---

## CRC32 Collision-Based Signature Forgery (iCTF 2013)

**Pattern:** CRC32 is linear — appending 4 carefully chosen bytes to any message produces a target CRC32 value, enabling signature forgery without knowing the secret key.

**Key insight:** `CRC32(msg || secret)` is not a secure MAC. Given any signed response `(msg, sig)`, compute 4 suffix bytes that force `CRC32(forged_msg || suffix || secret) == target_sig`. The linearity of CRC32 means the suffix computation is deterministic and instant.

```python
import struct, binascii

def crc32_forge(data, target_crc):
    """Append 4 bytes to data so CRC32(data + suffix) == target_crc"""
    current = binascii.crc32(data) & 0xFFFFFFFF
    # CRC32 polynomial table lookup to find suffix bytes
    # that transform current CRC into target_crc
    suffix = b''
    crc = target_crc ^ 0xFFFFFFFF
    for _ in range(4):
        byte = (crc & 0xFF)
        crc = (crc >> 8)
        suffix = bytes([byte]) + suffix
    return data + suffix  # Simplified — full implementation requires polynomial division
```

**When to use:** Any protocol using CRC32 as a message authentication code (MAC). CRC32 is a checksum, not a cryptographic hash — it provides no integrity guarantees against adversarial modification.

---

## Blum-Goldwasser Bit-Extension Oracle (PlaidCTF 2013)

**Pattern:** Exploit a decryption oracle for Blum-Goldwasser-style encryption by extending ciphertext length by one bit per query to leak plaintext via parity.

**Key insight:** Extend ciphertext by one bit (L+1), shift ciphertext left (`c << 1`), and submit a modified `y` value. The oracle reveals the LSB (parity) of each decrypted chunk. The squaring sequence `y = pow(y, 2, N)` can be manipulated to produce valid extended ciphertexts the server hasn't seen.

```python
# Iterative plaintext recovery via bit-extension
for i in range(msg_length):
    extended_c = original_c << 1        # Shift ciphertext left by 1
    new_y = pow(original_y, 2, N)       # Advance squaring sequence
    response = oracle(extended_c, new_y, msg_length + 1)
    leaked_bit = response & 1           # LSB reveals one plaintext bit
    plaintext_bits.append(leaked_bit)
    original_y = new_y
```

**When to use:** Blum-Goldwasser or BBS-based (Blum Blum Shub) encryption with a decryption oracle that accepts variable-length ciphertexts. The parity leak accumulates one bit per query.

---

## Hash Length Extension Attack (PlaidCTF 2014)

**Pattern:** Server computes `hash(SECRET || user_data)` using MD5, SHA-1, or SHA-256 (Merkle-Damgard constructions). Given a valid hash and the original data, extend it with arbitrary appended data and compute a valid hash — without knowing the secret.

```bash
# Using HashPump (install: apt install hashpump)
hashpump --keylength 8 \
  --signature 'ef16c2bffbcf0b7567217f292f9c2a9a50885e01e002fa34db34c0bb916ed5c3' \
  --data 'original_data' \
  --additional ';admin=true'
# Outputs: new_signature and new_data (with padding bytes)
```

```python
# Python: hashpumpy
import hashpumpy
new_hash, new_data = hashpumpy.hashpump(
    original_hash, original_data, append_data, secret_length
)
```

**Key insight:** Merkle-Damgard hashes (MD5, SHA-1, SHA-256) process data in blocks, and the hash output IS the internal state. Given `H(secret || msg)`, you can compute `H(secret || msg || padding || extension)` without knowing `secret` — just initialize the hash state from the known output and continue hashing. Only HMAC (`H(K XOR opad || H(K XOR ipad || msg))`) is immune. If the secret length is unknown, try lengths 1-32.

---

## Compression Oracle / CRIME-Style Attack (BCTF 2015)

**Pattern:** Server compresses plaintext (LZW, zlib, etc.) before encrypting. By observing ciphertext length changes with chosen plaintexts, leak the unknown plaintext character-by-character.

```python
import base64

def oracle(plaintext):
    """Send chosen plaintext, get ciphertext length."""
    resp = send_to_server(plaintext)
    return len(base64.b64decode(resp))

# Baseline: empty input
base_len = oracle("")

# Recover secret byte-by-byte
known = ""
for pos in range(secret_length):
    for c in string.printable:
        candidate = known + c
        length = oracle(candidate)
        if length <= base_len + len(known):  # Compressed = match
            known += c
            break
```

**Key insight:** Compression algorithms (LZW, DEFLATE, zlib) replace repeated sequences with back-references. If `SALT + user_input` is compressed before encryption, sending input that matches part of the salt produces shorter ciphertext (the match compresses). This is the same class as CRIME (TLS), BREACH (HTTP), and HEIST attacks. The oracle is ciphertext length.

---

## Hash Function Time Reversal via Cycle Detection (BSidesSF 2025)

When a system uses iterated hashing as a "time" function (`state_t = H(state_{t-1})`), reverse time by exploiting the finite cycle structure:

1. **Detect cycle:** Use Floyd's tortoise-and-hare or Brent's algorithm to find cycle length L
2. **Compute backward steps:** To go from time T to earlier time T_goal: iterate forward `(L - (T - T_goal)) % L` steps

```python
import hashlib

def hash_step(state):
    return hashlib.md5(state).digest()[:8]  # Truncated hash

def find_cycle(start):
    """Brent's cycle detection: returns (cycle_length, start_of_cycle)"""
    power = lam = 1
    tortoise = start
    hare = hash_step(start)
    while tortoise != hare:
        if power == lam:
            tortoise = hare
            power *= 2
            lam = 0
        hare = hash_step(hare)
        lam += 1
    # lam = cycle length; find cycle start
    tortoise = hare = start
    for _ in range(lam):
        hare = hash_step(hare)
    mu = 0
    while tortoise != hare:
        tortoise = hash_step(tortoise)
        hare = hash_step(hare)
        mu += 1
    return lam, mu  # cycle_length, cycle_start_offset

# Reverse from T_known to T_goal
cycle_len, _ = find_cycle(known_state)
forward_steps = (cycle_len - (t_known - t_goal)) % cycle_len
state = known_state
for _ in range(forward_steps):
    state = hash_step(state)
# state is now the value at t_goal
```

**Key insight:** For truncated hashes (e.g., MD5 -> 64 bits), the expected cycle length is ~2^32, making cycle detection feasible. Going "backward" N steps is equivalent to going forward (cycle_length - N) steps. Assumes the target state is within the main cycle, not on a tail.

---

## OFB Mode with Invertible RNG Backward Decryption (BSidesSF 2026)

**Pattern (randcrypt):** A custom block cipher uses OFB (Output Feedback) mode with a homemade RNG as the keystream generator. The last plaintext block is known (zero padding), leaking one RNG state. If the RNG's state transition function is invertible (bijective), all previous states can be recovered by running the RNG backwards, decrypting the entire ciphertext from the end to the beginning.

```python
def rng_forward(state):
    """Custom RNG state transition (from challenge)."""
    # Example: linear congruential or reversible mixing
    return (state * A + B) % M

def rng_inverse(state):
    """Inverted RNG — recover previous state."""
    return ((state - B) * pow(A, -1, M)) % M

# Last block is zero-padded → ciphertext XOR 0 = keystream = RNG state
leaked_state = int.from_bytes(ciphertext_blocks[-2], 'big')

# Decrypt backwards
state = leaked_state
plaintext_blocks = []
for i in range(len(ciphertext_blocks) - 3, -1, -1):
    state = rng_inverse(state)
    pt = xor_bytes(ciphertext_blocks[i], state.to_bytes(block_size, 'big'))
    plaintext_blocks.insert(0, pt)
```

**Key insight:** OFB mode decouples encryption from the plaintext — the keystream is deterministic from the initial state. If ANY block's plaintext is known (padding, headers, magic bytes), the corresponding RNG state is leaked. An invertible RNG then reveals ALL states. Always check if the RNG transition function has a mathematical inverse.

**When to recognize:** Custom OFB/CTR mode with a non-standard PRNG. Look for: (1) XOR-based encryption, (2) a state-update function that's bijective (no information loss), (3) predictable plaintext in any block position. Files with known padding (PKCS#7 zero-fill, null-terminated strings) are ideal leak points.

---

## Weak Key Derivation via Public Key Hash XOR (BSidesSF 2026)

**Pattern (ran-somewhere):** Hybrid RSA+AES encryption where the AES key is derived as `SHA256(DER_encoded_public_key) XOR seed`, with the seed hardcoded or predictable. Since the public key is public, the AES key is fully recoverable without the RSA private key.

```python
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from hashlib import sha256

# Public key is available
pubkey = RSA.import_key(open("public.pem").read())
der_bytes = pubkey.export_key("DER")

# Seed from challenge (hardcoded/predictable)
seed = b'BSidesSFCTF2026!'

# Derive AES key the same way the encryptor did
key_hash = sha256(der_bytes).digest()
aes_key = bytes(a ^ b for a, b in zip(key_hash, seed.ljust(32, b'\x00')))

# Decrypt
ct = open("flag.enc", "rb").read()
iv, ct_body = ct[:16], ct[16:]
cipher = AES.new(aes_key, AES.MODE_CBC, iv)
plaintext = cipher.decrypt(ct_body)
```

**Key insight:** Key derivation that incorporates only public information (public keys, known constants) provides zero security regardless of the hash function used. The "hybrid" design creates a false sense of security — RSA protects nothing if the AES key doesn't depend on the RSA private key.

**When to recognize:** Challenge provides both a public key AND an encrypted file, but no private key or ciphertext for RSA. Look for key derivation code that hashes the public key, uses the public key's modulus/exponent as seed material, or XORs with a constant.

---

## HMAC-CRC Linearity Attack (Boston Key Party 2016)

**Pattern:** HMAC constructed with CRC as the hash function is completely broken because CRC is linear over GF(2). The key is directly recoverable from a single message-MAC pair via polynomial arithmetic over GF(2^64).

```python
# CRC is linear: CRC(a XOR b) = CRC(a) XOR CRC(b)
# HMAC-CRC(key, msg) = CRC(key_opad || CRC(key_ipad || msg))
# Rewrite as polynomial in GF(2): K = known_terms * inverse(x^(128+M) + x^128) mod CRC_POLY
```

**Key insight:** CRC's linearity over GF(2) means HMAC-CRC provides zero security. Always verify the underlying hash function is non-linear before trusting HMAC.

---

## DES Weak Keys in OFB Mode (Boston Key Party 2016)

**Pattern:** DES has 4 weak keys where `E(E(P,K),K) = P` (encryption is self-inverse). In OFB (Output Feedback) mode this causes the keystream to cycle with period 2: even blocks XOR with IV, odd blocks with E(IV,K). Reduces to a 16-byte repeating XOR key.

```python
# DES weak keys: 0x0000000000000000, 0xFFFFFFFFFFFFFFFF,
#                0xE1E1E1E1F0F0F0F0, 0x1E1E1E1E0F0F0F0F
# OFB with weak key: keystream = [IV, E(IV,K), IV, E(IV,K), ...]
# Recovery: try all 4 weak keys; or treat as 16-byte repeating XOR
```

**Key insight:** DES weak keys cause OFB keystream to cycle with period 2. When you see DES+OFB, always try the 4 weak keys first.

---

## SRP (Secure Remote Password) Protocol Bypass via Modular Arithmetic (ASIS CTF Finals 2016)

SRP implementations that only check `A != 0` and `A != N` can be bypassed by sending `A = 2*N`, causing the server to compute a zero session key.

```python
from hashlib import sha256
import hmac

# SRP protocol: server computes session key from A (client's public value)
# S = (A * v^u) ^ b mod N
# If A = 2*N: S = (2*N * v^u) ^ b mod N = 0 (since 2*N mod N = 0)

N = server_modulus
# Send A = 2*N (bypasses checks for A != 0 and A != N)
A_malicious = 2 * N

# Server computes S = 0, so session key K = SHA256(0)
K = sha256(b'\x00').digest()

# Now compute valid HMAC proof with known K
proof = hmac.new(K, salt, sha256).hexdigest()
```

**Key insight:** SRP implementations must validate `A % N != 0`, not just `A != 0` and `A != N`. Sending `A = k*N` for any integer k forces the shared secret to zero, allowing authentication without knowing the password.

---

## Modified AES S-Box Brute-Force Recovery (H4ckIT CTF 2016)

AES implementation with a custom S-Box created by swapping 3 elements of the standard S-Box. Brute-force all C(256,3) * 2 = 5,527,040 possible permutations.

```cpp
// Three elements swapped from standard AES S-Box
// Total permutations: C(256,3) * 2 = ~5.5 million (feasible to brute-force)
#include <openssl/aes.h>

void bruteforce_sbox(uint8_t ciphertext[], uint8_t key[], int ct_len) {
    uint8_t standard_sbox[256]; // standard AES S-Box
    // Try all 3-element swaps
    for (int i = 0; i < 256; i++)
        for (int j = i+1; j < 256; j++)
            for (int k = j+1; k < 256; k++) {
                // Swap pairs: (i,j), (i,k), (j,k)
                uint8_t sbox[256];
                memcpy(sbox, standard_sbox, 256);
                swap(sbox[i], sbox[j]); // try each 2-element swap from the triple
                // Decrypt and check for valid plaintext
                if (try_decrypt_with_sbox(sbox, ciphertext, key, ct_len))
                    return; // found it
            }
}
```

**Key insight:** When a custom AES S-Box differs from standard by only a few element swaps, the search space is small enough to brute-force. For 3 swapped elements: C(256,3) permutation groups times the swap combinations within each group.

---

## Square Attack on Reduced-Round AES (0CTF 2016)

**Pattern:** 4-round AES is vulnerable to the square (integral) attack. Choose 256 plaintexts differing in one byte (a "lambda set"). After 3 rounds, the XOR sum at any byte position equals 0. Guess one byte of the last round key and partially decrypt -- if XOR sum is 0, the guess is correct.

```python
# For each byte position in the last round key:
for candidate in range(256):
    xor_sum = 0
    for ct in ciphertexts:
        xor_sum ^= inv_sub_bytes(ct[pos] ^ candidate)
    if xor_sum == 0:
        key_byte = candidate  # correct guess
# Reduces 2^128 key recovery to ~16 * 256 = 4096 operations
```

**Key insight:** Integral cryptanalysis exploits the "balanced" property (XOR-sum = 0) that propagates through AES rounds. Effective against 4-round AES; 5+ rounds require more sophisticated variants.
