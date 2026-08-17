# Python Bytecode Payload — Marshal, Lambda Layers, Multi-Stage XOR

## When this applies

- A delivered file contains base64-encoded marshalled CPython code, often nested.
- Common carriers: ML-model SavedModels (Keras `.keras` ZIPs with a `Lambda` layer), Python pickles with `__reduce__` returning `marshal.loads`, `.pyc` files with stripped magic, AsyncSSH/Jupyter notebooks embedding `compile()` blobs.
- Trigger keywords: "Lambda layer", `marshal.loads`, `co_consts`, `dis.dis`, "pickle deserialization", "RCE on load".
- Goal: recover what the payload computes — flag, key, side-effect — without executing it.

## Recognition

- A 3-element list `[<base64 string>, None, None]` inside a Keras Lambda's `config.function` is the canonical marshalled-codeobject form.
- `.keras` files unzipped reveal `metadata.json`, `config.json`, `model.weights.h5`. Search `config.json` for any `"function":` field.
- `pickle` files: `STACK_GLOBAL` opcode pointing at `marshal.loads` followed by a `BINBYTES` blob.
- `.pyc` first 16 bytes: `magic(4) | bitfield(4) | timestamp(4) | size(4)`. The magic identifies the CPython minor (e.g., `0xCB0D0D0A` → 3.12, `0x550D0D0A` → 3.13).

## Steps

### 1. Triage statically — never load

```python
import zipfile, base64, json, marshal, dis
zf = zipfile.ZipFile("target.keras")
cfg = json.loads(zf.read("config.json"))
# Walk cfg['config']['layers'] for class_name == 'Lambda'
fn  = lambda_layer["config"]["function"]
co  = marshal.loads(base64.b64decode(fn[0]))
dis.dis(co)
```

Do **not** call `keras.models.load_model(..., safe_mode=False)` — equivalent to `exec` of attacker-controlled bytecode.

### 2. Match the Python minor

`marshal.loads` raises `ValueError: bad marshal data (unknown type code)` *or* `dis.dis` raises `IndexError: tuple index out of range` when run from a CPython minor newer than the one that produced the dump. Read the magic, install the matching interpreter (`pyenv`, `uv python install 3.12`), re-run.

### 3. Read the algorithm without executing it

`co_consts`, `co_names`, `co_varnames`, plus `dis.dis(co)` are enough to reconstruct the original Python by hand:

```python
print("CONSTS:", co.co_consts)
print("NAMES:",  co.co_names)
print("VARS:",   co.co_varnames)
dis.dis(co)
```

Map `LOAD_CONST i` → `co.co_consts[i]`, `LOAD_GLOBAL i` → `co.co_names[i>>1]` (Python ≥3.11 has the LSB flag), `STORE_FAST i` → `co.co_varnames[i]`. The bytecode is deterministic; reconstruct opcode-stable Python and discard the dis output.

### 4. Peel nested stages

Common pattern: outer code reads `co_consts[N]` (a long `tuple[int]`), XORs it under a key, `marshal.loads` again, then `exec`. Detection heuristic: any code object whose disassembly contains a long integer-tuple constant adjacent to `marshal.loads` / `exec` calls is likely an encrypted next-stage payload.

Recover the key, then:

```python
inner_blob   = bytes(co.co_consts[N])
inner_marsh  = bytes(b ^ key[i % len(key)] for i, b in enumerate(inner_blob))
inner_co     = marshal.loads(inner_marsh)
dis.dis(inner_co)
```

Repeat until the payload is plain.

### 5. Where the key may live

- A literal `bytes` constant inside `co_consts` — rare, easy.
- Derived from the file itself: `SHA1(content_of_some_member)[:N]` — check `co_names` for `hashlib`, `sha1`, `sha256`.
- **Weight-keyed**: ML-model payloads often derive `random.Random(seed=u32_le(SHA1(weights_of_layer_X)[:4])).randbytes(N)` — the key lives in the model weights, not the code.
- Imported attribute that is itself bytecode — recurse.

For weight-keyed payloads, try every weight tensor in the file as a candidate key source. Match layers by *class + units + inbound graph*, not by config-name — Keras renames same-class layers on save (e.g., the Dense named `foo` in `config.json` may serialize to `layers/dense/vars/{0,1}` in `model.weights.h5` due to alphabetic / insertion-order normalization).

### 6. Recover the secret

A common payload shape: compute a value from local state (weights, file metadata, etc.) and `return x` unchanged from the wrapper. The secret never escapes during real inference / unpickling — only static analysis recovers it. Inspect every tensor / constant the payload touches; the secret is usually one XOR or one slice away.

## Anti-Patterns

- Calling `keras.models.load_model(..., safe_mode=False)`, `pickle.loads`, or `exec(marshal.loads(...))` on attacker-controlled blobs.
- Running `dis` from a Python minor newer than the marshal dump's magic header.
- Looking only at the outer code's literals — long `tuple[int]` constants are the next stage in disguise.
- Matching ML-model layers by their `config.json` name when reading from the H5 store.

## Cross-references

- ML-model triage angle: [../../../../ai-threat-testing/reference/malicious-keras-model-triage.md](../../../../ai-threat-testing/reference/malicious-keras-model-triage.md).
- Existing string / dispatcher scenarios: [string-obfuscation.md](string-obfuscation.md), [hash-dispatcher-chain.md](hash-dispatcher-chain.md).
