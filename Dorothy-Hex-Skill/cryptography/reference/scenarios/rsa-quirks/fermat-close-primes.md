# Fermat Factoring — Close Primes

## When this applies

- RSA modulus `n = p·q` where `p` and `q` are close in value (`|p - q|` is small, often `< n^0.25`).
- Common in poor key-generation that re-uses or slightly increments primes.
- Trigger keywords: "Fermat", "close primes", "Roca-style" (different attack but similar root cause), "BSAFE bug".

## Technique

If `p` and `q` are close, then `(p+q)/2` is close to `sqrt(n)`. Fermat factoring writes `n = a^2 - b^2 = (a-b)(a+b)` where `a = (p+q)/2`, `b = (q-p)/2`. Iterate `a` upward from `ceil(sqrt(n))` and check whether `a^2 - n` is a perfect square; when it is, `b = sqrt(a^2 - n)`, and `p = a - b`, `q = a + b`.

## Steps

### 1. Estimate closeness

If you suspect close primes, the gap is usually < 2^200 or so for 2048-bit `n`. Fermat with simple iteration finds primes within `2^256` gap in seconds; beyond that, use Coppersmith with hint or Pollard rho.

### 2. Run Fermat

```python
import gmpy2

def fermat(n, max_iter=10**7):
    a = gmpy2.isqrt(n) + 1
    for _ in range(max_iter):
        b2 = a*a - n
        b = gmpy2.isqrt(b2)
        if b*b == b2:
            return int(a - b), int(a + b)
        a += 1
    return None

p, q = fermat(n)
```

### 3. Decrypt

```python
phi = (p - 1) * (q - 1)
d = pow(e, -1, phi)
plaintext = pow(c, d, n)
```

## Verifying success

- `p * q == n`.
- Both factors are prime (`gmpy2.is_prime(p)`).
- Decryption produces structured plaintext.

## Common pitfalls

- **Primes not close.** If the gap is larger than `n^0.25`, Fermat takes longer than the heat death of the universe. Try Pollard rho, ECM, or check for other structure first.
- **Iteration limit.** With a 2048-bit `n` and gap `2^512`, you'd need `~2^256` iterations — infeasible. Use a Coppersmith-with-hint variant if you have any partial info.
- **n is square or higher power.** If `n = p^2`, then `n = a^2` directly: `a = sqrt(n)`, `b = 0`. The first iteration succeeds but with `b = 0`. Recognize and handle.
- **n has more than two factors.** If `n = p·q·r`, Fermat fails (or finds a misleading non-trivial factorization with composite components). Check `is_prime(p)` and `is_prime(q)`.

## Tools

- `gmpy2.isqrt` and integer arithmetic — pure Python.
- `yafu` — automated factoring with Fermat as one of several methods.
- `factordb.com` — quick check for known factorizations.
- For very tight close primes (when even Fermat is slow): Coppersmith small-roots with high-bits-of-`p` hint.
