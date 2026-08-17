# Malicious Keras Model Triage

## When this applies

- A `.keras`, `.h5`, or `SavedModel` artifact arrives without provenance and you must decide whether loading it is safe.
- A vendored ML model file ships in a firmware blob, container layer, or HuggingFace mirror with no signed checksum.
- LLM05-Supply-Chain assessments where models flow in from third parties and are loaded into production with `safe_mode=False`.

## Recognition

- A `.keras` file is a ZIP. Unzip it: expect `metadata.json`, `config.json`, `model.weights.h5`. Anything else (bare `.py`, extra blobs) is suspicious.
- In `config.json`, walk every layer with `class_name == "Lambda"`. Its `config.function` field of shape `[<base64 string>, None, None]` is a marshalled CPython code object — attacker-controlled bytecode that runs the moment you call `keras.models.load_model(..., safe_mode=False)`.
- Other red flags: `class_name == "Custom>..."` referencing a module not in the standard Keras tree; `metadata.json` claiming a Keras version different from what `model.weights.h5` was saved by; `config.json` referencing custom_objects that aren't bundled.

## Static triage workflow

```python
import zipfile, json, base64, marshal, dis

zf  = zipfile.ZipFile("model.keras")
cfg = json.loads(zf.read("config.json"))

for layer in cfg["config"]["layers"]:
    if layer["class_name"] == "Lambda":
        fn = layer["config"]["function"]
        co = marshal.loads(base64.b64decode(fn[0]))
        dis.dis(co)
        print("CONSTS:", co.co_consts)
        print("NAMES:",  co.co_names)
```

Match the disassembling Python's minor to the marshal magic header (first 4 bytes of the decoded blob) — `0xCB0D0D0A` ≈ Python 3.12, etc. Newer interpreters raise `IndexError: tuple index out of range` on older marshal dumps.

Reconstruct the algorithm from `co_consts`/`co_names`/`co_varnames` triples plus the `dis` listing — opcode-stable Python without ever calling `exec`. See [../../reverse-engineering/reference/scenarios/obfuscation/python-bytecode-payload.md](../../reverse-engineering/reference/scenarios/obfuscation/python-bytecode-payload.md) for the multi-stage peeling pattern (XOR-encrypted next-stage payloads embedded in long `tuple[int]` constants).

## Weight-keyed payloads

Real-world malicious models hide the decryption key in the weights, not the code:

```text
seed = u32_le(SHA1(weights_of_some_layer)[:4])
key  = random.Random(seed).randbytes(N)
inner_marshal = bytes(b ^ key[i % N] for i,b in enumerate(co_consts[k]))
exec(marshal.loads(inner_marshal), namespace)
```

Detection heuristic: any Lambda whose disassembly shows a long `tuple[int]` constant adjacent to `marshal.loads` / `exec` calls. Try every weight tensor in the file as the key source. Static scanners that only inspect the Lambda code blob's literals will miss this — the key is in the model.

## Keras H5 layer-name remapping

`config.json` names like `seed_dense` and `payload_dense` may be stored at `layers/dense/vars/{0,1}` and `layers/dense_1/vars/{0,1}` in `model.weights.h5` due to Keras' alphabetic + insertion-order normalization. Match by *class + units + inbound graph*, not by config-name, when reading weights for triage:

```python
import h5py
with h5py.File("model.weights.h5") as h:
    def walk(g, path=""):
        for k, v in g.items():
            p = f"{path}/{k}"
            if isinstance(v, h5py.Dataset): print(p, v.shape, v.dtype)
            else: walk(v, p)
    walk(h)
```

## Hidden-secret patterns

Many malicious payloads compute a value (flag, key, exfiltrated string) from local state and `return x` unchanged from the wrapper, so real inference never emits the secret. Inspect every tensor / constant the disassembled payload touches:

- Float32 bias vectors interpreted as `(bias * 255.0).astype(uint8).tobytes()` then XOR'd with the same weight-derived key.
- Int8 conv-kernel quantization rounded to printable ASCII.
- Constant blobs in `co_consts` decoded with the SHA-derived key.

## Anti-Patterns

- Calling `keras.models.load_model(..., safe_mode=False)` on an unverified model — RCE-equivalent.
- Calling `model.predict(x)` to "see what the model does" before static triage — the side effect runs during `load_model`, before `predict` is ever reached.
- Looking only at `config.function`'s literals — the key lives in the weights, the next stage lives behind XOR.
- Identifying weight datasets by their `config.json` name when reading from the H5 store.
- Skipping `metadata.json` — a Keras-version mismatch with what `model.weights.h5` was saved by often signals tampering.

## Cross-references

- Bytecode-level peeling, key recovery, opcode-stable decompilation: [../../reverse-engineering/reference/scenarios/obfuscation/python-bytecode-payload.md](../../reverse-engineering/reference/scenarios/obfuscation/python-bytecode-payload.md).
- Broader supply-chain context (provenance, signatures, sandboxing): [llm05-supply-chain.md](llm05-supply-chain.md).
