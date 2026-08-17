# Low Public Exponent — Hastad's Broadcast Attack and Cube Root

## When this applies

- RSA public exponent `e` is small (most commonly `e = 3`, sometimes `e = 5, 7`).
- Either: (a) a single ciphertext where `m^e < n` (no modular reduction), or (b) the same plaintext encrypted under several distinct moduli with the same small `e`.
- Trigger keywords: "e=3", "small public exponent", "Hastad", "broadcast", "cube root".

## Technique

**Direct cube root** (no broadcasting): if `m^3 < n`, then `c = m^3 mod n = m^3` over the integers. Take the integer cube root of `c`.

**Hastad's broadcast attack**: same plaintext `m` encrypted to `e` different recipients with moduli `n_1, ..., n_e`. Each `c_i = m^e mod n_i`. By CRT, recover `m^e mod (n_1·...·n_e)`. Since `m < min(n_i)`, `m^e < prod(n_i)`, so the CRT'd value equals `m^e` over the integers. Take the `e`-th root.

## Steps

### Direct cube root (single ciphertext)

```python
import gmpy2
c, e, n = ...
assert e <= 5
m, exact = gmpy2.iroot(gmpy2.mpz(c), e)
if exact:
    plaintext = int(m).to_bytes((int(m).bit_length()+7)//8, 'big')
```

If not exact, `m^e ≥ n` and modular reduction occurred — try Hastad if you have multiple ciphertexts, or Coppersmith stereotyped-message attack.

### Hastad CRT

```python
import gmpy2
from sympy.ntheory.modular import crt

# Need at least e ciphertexts under distinct n_i with same e
es = 3
ciphertexts = [c1, c2, c3]
moduli = [n1, n2, n3]

m_e, _ = crt(moduli, ciphertexts)        # m^3 mod (n1*n2*n3)
m, exact = gmpy2.iroot(gmpy2.mpz(m_e), es)
assert exact
plaintext = int(m).to_bytes(...)
```

### Padded broadcast (Hastad full)

If each ciphertext encrypts a *padded* version `m_i = a_i·m + b_i` with publicly known affine padding (e.g. timestamps), Hastad's full attack reduces to a Coppersmith small-roots polynomial:

```
sum(t_i * (a_i·x + b_i)^e) - sum(t_i · c_i) ≡ 0  (mod prod n_i)
```

where `t_i` are CRT coefficients. Use SageMath `small_roots`. See `scenarios/lattice/coppersmith-known-bits.md`.

## Verifying success

- For direct cube root: `gmpy2.iroot` returns `exact=True`, decoded bytes are printable / valid format.
- For Hastad: each ciphertext re-encrypts to itself: `pow(m, e, n_i) == c_i`.

## Common pitfalls

- **Padding.** Real RSA with PKCS#1 v1.5 / OAEP padding randomizes the plaintext; Hastad on raw ciphertext won't apply. Confirm "textbook RSA" (no random padding).
- **`m^e < n` matters.** A single 200-byte plaintext with 2048-bit modulus and `e=3` → cube root gives garbage (modular reduction occurred). Need multiple ciphertexts or to confirm size.
- **Distinct moduli for Hastad.** If two of the `n_i` share a factor, gcd them first (you've already factored both). Include only **coprime** moduli in CRT.
- **Number of samples.** Hastad needs exactly `e` samples for the basic attack; fewer fail the size bound, more is wasted.

## Tools

- `gmpy2` for `iroot` and big-integer arithmetic.
- `sympy.ntheory.modular.crt` or roll your own with `pow(x, -1, m)`.
- SageMath only when you need the padded-Hastad-via-Coppersmith variant.
