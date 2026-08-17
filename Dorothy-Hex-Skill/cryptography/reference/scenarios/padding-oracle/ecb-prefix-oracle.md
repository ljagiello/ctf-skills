# ECB Chosen-Prefix Oracle (Byte-at-a-Time Decryption)

## When this applies

- A service encrypts `prefix || user_input || secret` (or `secret || user_input` or `user_input || secret`) under **ECB mode** and returns the ciphertext.
- You control `user_input`; the rest is fixed across queries.
- Trigger keywords: "ECB", "session token includes user data", "echo encrypted".

## Technique

ECB encrypts each 16-byte (or 8-byte for DES) block independently and deterministically: identical plaintext blocks produce identical ciphertext blocks. By controlling alignment, you compare a ciphertext block produced from `<known-prefix> || X` against blocks containing `<known-prefix> || ?` for unknown `?`. Match reveals `?`.

## Steps

### 1. Confirm ECB

Send `user_input = "A"*64`. The ciphertext should contain repeated 16-byte blocks (the middle of "AAAA…AAAA" produces identical blocks under ECB). Look for any 32-byte run that's `X || X` in the output. CBC/CTR will not show this.

### 2. Determine block size

Send inputs of length `0, 1, 2, ...` and watch the ciphertext length. When it jumps by N bytes, N = block size (16 for AES, 8 for DES/3DES).

### 3. Determine prefix length

Send `"A"*N` for `N = 0..32`. Find the smallest `N` such that two consecutive ciphertext blocks become identical — those blocks correspond to the user-controlled region. Backtrack to find exact byte offset where prefix ends within a block.

### 4. Recover one secret byte at a time

Suppose prefix is empty (or padded to a block boundary) and the secret follows directly after our input.

**Setup**: Choose `N - 1` known bytes (e.g. `"A" * 15`). The 16-byte target block is `"AAAAAAAAAAAAAAA" + secret[0]`.

```python
known = b""
for _ in range(secret_length):
    pad = b"A" * (block_size - 1 - len(known) % block_size)
    target_block_idx = (len(pad) + len(known)) // block_size
    real_ct = oracle(pad)
    target = real_ct[target_block_idx*16 : (target_block_idx+1)*16]

    # build dictionary of "pad + known + b" for all b
    for b in range(256):
        probe = pad + known + bytes([b])
        ct = oracle(probe)
        if ct[target_block_idx*16:(target_block_idx+1)*16] == target:
            known += bytes([b])
            break
    else:
        break  # padding boundary or end of secret
```

256 oracle queries per secret byte × `secret_length` total.

### 5. Adjust for non-empty prefix

If the prefix is non-zero and unknown, prepend `(block_size - prefix_len % block_size)` filler bytes to align, then start aligned-block extraction one block later than otherwise.

## Verifying success

- Recovered secret has expected format (cookie structure, JSON, flag wrapper).
- Replay: send chosen plaintext + recovered secret as user input; ciphertext block alignment should match exactly.

## Common pitfalls

- **Prefix randomization.** If the prefix has a randomized component each request (random IV-equivalent), ECB attacks generally don't apply — confirm determinism first.
- **Padded plaintext.** Final block may include PKCS#7 padding bytes. Last byte recovery may grab `\x01` instead of the secret's last byte; stop when you hit a padding pattern.
- **Compression before encryption.** If the plaintext is gzipped before encryption, ECB block alignment is meaningless and you've found a CRIME-style attack instead.
- **Wrong alignment.** Off-by-one in `pad` length leaves the secret byte spanning two blocks. Verify by checking that all-A input produces a clean repeating block pattern.

## Tools

- Hand-rolled Python with `requests` — usually < 100 lines.
- `pycryptodome` only needed if you also need offline verification (encrypt-and-compare).
- For HTTP oracles: `mitmproxy` to capture/replay; `Burp Intruder` for the 256-value sweep per byte.
