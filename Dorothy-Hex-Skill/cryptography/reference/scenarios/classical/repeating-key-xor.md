# Repeating-Key XOR (Vigenère-style) Recovery

## When this applies

- Ciphertext produced by XOR-ing plaintext against a short key that cycles
  (`c[i] = p[i] XOR key[i mod L]`).
- Fingerprints: a "crypter" / "encrypt" script that loops a `key` string and
  XORs byte-by-byte; output stored as hex; a partial decrypt with a guessed key
  reveals a clean *prefix* then garbles (key shorter than you assumed).
- No key available, but plaintext is natural language or structured (JSON, PEM).

## Recovery without the key

### 1. Find the key length via Index of Coincidence

For each candidate length `L`, split ciphertext into `L` columns (`ct[i::L]`).
Each column is single-byte XOR, so its byte distribution matches the plaintext
language. Average IC per column peaks at the true `L` (and its multiples).

```python
from collections import Counter
def ic(b):
    n=len(b)
    if n<2: return 0
    c=Counter(b)
    return sum(v*(v-1) for v in c.values())/(n*(n-1))
scores=sorted(((sum(ic(ct[i::L]) for i in range(L))/L, L) for L in range(1,41)),reverse=True)
# English text IC ~0.066; random ~0.0039. Top score = key length (watch for 2x harmonics).
```

### 2. Break each column with frequency analysis

For each column independently, pick the key byte that maximises an English-like
score (space `0x20` is the single strongest signal in prose).

```python
def score(bs):
    s=0
    for c in bs:
        if c==0x20: s+=5
        elif 65<=c<=90 or 97<=c<=122: s+=3
        elif c in (10,13,46,44,39,33): s+=1
        elif not 32<=c<127: s-=5
    return s
key=bytes(max(range(256),key=lambda k:score(bytes(c^k for c in col))) for col in (ct[i::L] for i in range(L)))
pt=bytes(ct[i]^key[i%L] for i in range(len(ct)))
```

## Crib dragging (shortcut)

If a likely plaintext fragment is known (`"Hello"`, `"-----BEGIN"`, `"{"` for
JSON), XOR it against each ciphertext offset: `key_fragment = crib XOR ct[off:]`.
A readable/period-consistent fragment localises part of the key. A clean-prefix
decrypt that then garbles means the **real key is longer** than the crib —
re-run the IC step rather than trusting the short key.

## Notes

- The recovered key often turns out to be a meaningful word/phrase reused
  elsewhere (zip password, AES passphrase, credential). Try it as a secret.
- For binary plaintext (not prose), swap the frequency model for the expected
  byte distribution (e.g. high `0x00` count for structured/padded data).
