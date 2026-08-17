# CBC Padding Oracle (Vaudenay Attack)

## When this applies

- A service decrypts ciphertexts in **CBC mode with PKCS#7 padding** and the response distinguishes "valid padding" from "invalid padding" — different status codes, error messages, response times, or page bodies.
- Trigger keywords: "CBC", "padding error", "decryption error", "MAC error", "block cipher in CBC".
- You can submit modified ciphertexts and observe the oracle's verdict.

## Technique

Vaudenay's padding oracle: tamper one block at a time to make the decryption produce valid PKCS#7 padding (`\x01`, `\x02\x02`, etc.). Each successful tamper reveals one byte of the intermediate decryption state, which XORs with the previous ciphertext block to recover the plaintext byte.

## Steps

### 1. Identify two ciphertext blocks

Split the captured ciphertext into 16-byte blocks (or 8-byte for 3DES): `IV | C1 | C2 | ...`. Target block `Ci` reveals plaintext `Pi` once you know intermediate state `I_i = D_K(Ci)` — then `Pi = I_i XOR C_{i-1}`.

### 2. Recover one byte at a time, last-byte-first

For block `Ci` (target) and a forged block `C'`:

```
P' = D_K(Ci) XOR C'
```

We control `C'` and want `P'` to end with valid padding `\x01`. For each byte value `b ∈ [0, 256)`:

1. Set `C'[15] = b`, leave bytes 0..14 as random.
2. Submit `(C', Ci)` to the oracle.
3. If oracle says "valid padding", then `P'[15] = 0x01`, so `I_i[15] = b XOR 0x01`.

Edge case: two values `b` may produce valid padding (when the random bytes happen to form `\x02\x02`). Disambiguate by also flipping `C'[14]` — only the true `b` survives.

### 3. Extend to byte 14

Now you know `I_i[15]`. Set `C'[15] = I_i[15] XOR 0x02` to force `P'[15] = 0x02`. Brute-force `C'[14]` to make `P'[14] = 0x02` (valid padding `\x02\x02`). Recover `I_i[14]`.

Continue down to byte 0.

### 4. Recover full plaintext

`Pi[k] = I_i[k] XOR C_{i-1}[k]` (where `C_0 = IV`). Repeat for all blocks.

### 5. (Optional) Encrypt arbitrary plaintext

Once you can compute `D_K(C)` for any `C`: pick desired plaintext `P*`, choose `C*` (random), compute `I = D_K(C*)` via the oracle, set `C_{prev}* = I XOR P*`. The pair `(C_{prev}*, C*)` decrypts to `P*` — even without knowing the key.

## Verifying success

- Recovered plaintext matches expected format (PKCS#7 padding correct, JSON / cookie structure parses).
- Round-trip: build a fresh tampered ciphertext encoding a chosen plaintext (e.g. an admin cookie), submit, observe app accept it.

## Common pitfalls

- **Last-byte ambiguity.** If random `C'[14]` accidentally equals `0x02 XOR I_i[14]`, you get a false-positive `b`. Always verify by also flipping `C'[14]` and re-querying.
- **Bit-flipping vs padding oracle.** Bit-flipping (XOR plaintext bits without recovery) is a different attack — used when MAC is absent and you just want to flip a known plaintext bit (e.g. `user=admin`).
- **Rate limiting.** The attack needs ~256 × 16 = 4096 queries per block. Throttle to avoid bans; consider a single ciphertext target.
- **MAC-then-encrypt.** If the protocol does Encrypt-then-MAC, padding oracle is moot — MAC verification fails before padding is checked. Only Encrypt-then-NoMAC or MAC-then-Encrypt is vulnerable.
- **Timing oracle.** Sometimes the only signal is response time. Add timing measurements with multiple samples to denoise.

## Tools

- `padbuster` (Perl, classic) — `padbuster <URL> <ciphertext> <block_size>`.
- `python-paddingoracle` (Python library) — wraps the loop with a custom oracle callable.
- `bletchley` — Python toolkit with padding oracle + bit-flipping helpers.
- Hand-rolled in ~150 lines of Python; the algorithm is small.
