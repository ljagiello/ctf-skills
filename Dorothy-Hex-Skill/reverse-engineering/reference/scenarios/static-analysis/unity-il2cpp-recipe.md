# Unity IL2CPP Reverse Engineering Recipe

Compiled-AOT Unity games (Windows/Android/iOS) ship as IL2CPP: C# is transpiled to C++ then compiled to a single native module (`GameAssembly.dll` / `libil2cpp.so`) plus a metadata blob (`global-metadata.dat`). The metadata + native binary together hold all type/method info — you can reconstruct a "Dummy" managed assembly that loads in dnSpy/ILSpy.

## Identify
- Path contains `<Game>_Data/il2cpp_data/Metadata/global-metadata.dat` → IL2CPP.
- Metadata magic: `AF 1B B1 FA` little-endian (`0xFAB11BAF`) at offset 0.
- Metadata version at offset 4: 24 (Unity 2018), 27 (2019), 29 (2020-2022), 31+ (2023+).
- `Application.dataPath` / `Application.streamingAssetsPath` symbols visible in the dumped C++ assembly.

## Dump (Il2CppDumper)
```
git clone --depth 1 https://github.com/Perfare/Il2CppDumper.git
cd Il2CppDumper
# .NET 9 only? Edit csproj target framework:
sed -i.bak 's/<TargetFrameworks>net6.0;net8.0<\/TargetFrameworks>/<TargetFrameworks>net9.0<\/TargetFrameworks>/' Il2CppDumper/Il2CppDumper.csproj
dotnet build -c Release
dotnet bin/Release/net9.0/Il2CppDumper.dll <Game_Data>/../GameAssembly.dll <Game_Data>/il2cpp_data/Metadata/global-metadata.dat /out/
```

Outputs (in `/out/`):
- `dump.cs` — full decompiled C# with RVA/Offset/VA comments per method
- `DummyDll/Assembly-CSharp.dll` — load in dnSpy/ILSpy for inspection
- `script.json` — method → address mapping (ScriptMethod), type → addr (ScriptMetadata), string literal slots (ScriptString)
- `stringliteral.json` — all string literals with their data-section addresses
- `il2cpp.h` — C struct definitions for the runtime types

## Locate game-specific code
The decompile contains thousands of UnityEngine / mscorlib classes. The actual game code is in the **last few hundred classes** (Assembly-CSharp namespace). Filter:
```
grep -nE "^public class .* : MonoBehaviour" dump.cs | tail -40
grep -nE "^public class (FlagPole|Player|GameManager|Enemy|Item)" dump.cs
```

## Resolve runtime references in native disasm
The compiled C++ resolves managed types/methods via global pointer tables at boot. In disasm you see `mov rcx, qword [0x180c2d910]` — these are slots populated by IL2CPP runtime. Resolve via:

```python
import json
script = json.load(open('script.json'))
md = {e['Address']: e for e in script['ScriptMetadata']}      # TypeInfo slots
mm = {e['Address']: e for e in script['ScriptMetadataMethod']}# MethodInfo slots
ss = {e['Address']: e for e in script['ScriptString']}        # String literals
# Address is VA on Windows (e.g., 0x180c2d910)
print(md.get(0x180c2d910) or mm.get(0x180c2d910) or ss.get(0x180c2d910))
```

For function calls (`call 0x180337230`):
```python
sm = {e['Address']: e for e in script['ScriptMethod']}
# Address is VA (Windows base 0x180000000)
print(sm.get(0x180337230))   # → System.String$$Concat
```

## Common flag-check shapes

### MD5-of-file integrity gate (anti-tamper)
A method that:
1. `MD5.Create()` 
2. `File.OpenRead(Application.dataPath + "/some/file.dll")`
3. `ComputeHash` → `BitConverter.ToString().Replace("-","").ToLower()`
4. Compares to `this.<field> + "<hex_suffix>"`

→ Compute MD5 of the referenced file; the field value is the prefix that makes `prefix + suffix == md5_lower`. This is **not the flag** but the anti-tamper protection. Flag is elsewhere (runtime UI display, secondary native call).

### Hardcoded flag XORed at startup
Look for `<PrivateImplementationDetails>` class with `__StaticArrayInitTypeSize=N` static arrays — these are raw bytes embedded in metadata. Find references to them in code and trace XOR transformations.

### TextAsset extraction
For flags stored as Unity TextAssets:
```python
import UnityPy
env = UnityPy.load('sharedassets0.assets')
for obj in env.objects:
    if obj.type.name == 'TextAsset':
        d = obj.read()
        print(d.m_Name, d.m_Script)
```

## Common pitfalls
- Hardcoded string literals in disasm appear as `qword [0x180cXXXXX]` — DON'T mistake them for typeinfo. Use stringliteral.json.
- Compiler-generated iterator classes `<MethodName>d__N::MoveNext` contain the actual coroutine logic, NOT the named method. The named method just instantiates the iterator.
- `DummyDll/Assembly-CSharp.dll` has only method signatures, no IL bodies. The bodies live in native code at the listed VA.
- `Application.dataPath` is `<exe>_Data/`. Anti-tamper checks compute paths relative to this.

## Dynamic analysis (when static is insufficient)
- **Frida**: hook `UnityEngine.UI.Text::set_text` and `TMPro.TMP_Text::set_text` to capture every UI string set at runtime. On Windows, attach with `frida -p <pid>` after launch.
- **dnSpy** (Windows): debug the dumped DummyDll mapped to running process for breakpoint-level inspection.
- **MelonLoader / BepInEx**: code injection frameworks that let you hook Update() in C# directly.
- **Memory dump**: process snapshot then `strings` + `grep HTB{` — finds runtime-built flags.

## When the flag is built at runtime by native code
If the C# wraps `extern` functions that build the flag from internal state (linked lists, RNG-seeded XOR), static analysis alone is insufficient. Required:
- Run the binary to completion in the legitimate path (no tamper, no debugger detected).
- Hook the final string assignment (UI Text set / Debug.Log / Console).
- OR fully emulate the native code path (Unicorn / qiling) — only feasible if state is deterministic.

## Flag as sprite-letter layout (off-camera Canvas)

Some Unity CTFs encode the flag as a row of GameObjects inside a Canvas, each holding a SpriteRenderer pointing to a single-character glyph sprite. The Canvas may be:
- World Space at a far X (deliberately off-camera) — flag is **static data** in `level0`, never rendered in-game.
- Hidden via `SetActive(false)` on all children, activated only when a win condition fires.

### Detection
1. `grep` IL2CPP dump for `GameObject.Find("<name>")` strings and trace their references.
2. Examine Canvas hierarchy in `level0` with UnityPy:
   ```python
   import UnityPy
   env = UnityPy.load('level0')
   for o in env.objects:
       if o.type.name == 'GameObject':
           d = o.read()
           # Look for canvas-ish names (e.g., short hash-y names with many children)
           if d.m_Name and len([c for c in d.m_Components]) >= 2:
               # check if has Canvas component
               for c in d.m_Components:
                   cp = c.m_PathID if hasattr(c,'m_PathID') else c.path_id
                   ot = {obj.path_id: obj for obj in env.objects}[cp].type.name
                   if ot == 'Canvas':
                       print(f"Canvas GO '{d.m_Name}' children={len([x for x in d.m_Components if x])}")
   ```

### Extraction
1. **Map sprites to characters**: extract each sprite as a PNG, manually identify the glyph.
   ```python
   import UnityPy, os
   env = UnityPy.load('sharedassets0.assets')
   os.makedirs('/tmp/sprites', exist_ok=True)
   for o in env.objects:
       if o.type.name == 'Sprite':
           s = o.read()
           try: s.image.save(f'/tmp/sprites/{o.path_id}_{s.m_Name}.png')
           except Exception: pass
   ```
2. **Compute world positions of all letter-sprite GameObjects**:
   ```python
   parents = {}  # child rt -> parent rt
   for o in env.objects:
       if o.type.name in ('Transform','RectTransform'):
           rt = o.read()
           for c in rt.m_Children:
               parents[c.m_PathID if hasattr(c,'m_PathID') else c.path_id] = o.path_id
   def world(pid, objs):
       rt = objs[pid].read()
       x, y = rt.m_LocalPosition.x, rt.m_LocalPosition.y
       if pid in parents:
           px, py = world(parents[pid], objs)
           return (x+px, y+py)
       return (x, y)
   ```
3. **Sort by world X**, concatenate sprite-character mapping — that's the flag.
4. **Don't forget grandchildren** — some letters may be nested inside parent letter GameObjects (active=True while parent is inactive — they only render when parent is activated by win logic, but the *layout* shows where they slot in).

### Pitfalls
- Canvas can be in World Space (`m_RenderMode==2`); positions are then in Unity units (typically 100ppu), not pixels.
- Letters with descenders (g, p, q, y, _) sit at slightly lower Y than baseline letters — group by Y-bin if you need to identify row.
- Capital vs lowercase distinction comes from sprite *height*: capitals match ascenders (h≈115), lowercase no-descender letters are shorter (h≈86).
- Overlapping sprites at same X may indicate one *replaces* the other based on game state. Either is plausible; submit both.

### Semantic-insertion trap (anti-static-extraction)
World-X ordering of all letter-sprites can be **deliberately misleading**. The challenge author may place active grandchildren at world-X positions that do NOT spell the intended word — only *semantic* insertion (at positions that complete English / leet phrases) yields the flag. Signs you're in this trap:
- Sorted reading is gibberish or near-gibberish (e.g., `serMU0de`, `Cht34`).
- Active grandchildren spell an obvious word-fragment when inserted at natural word boundaries (e.g., active `U`, `h`, `t` + base `serM0de`, `C34` → `UserM0de`, `Ch34t`).
- The game theme (anti-cheat, integrity check) hints at the intended phrase.

**Resolution strategy**: enumerate thematic candidates by inserting active grandchildren at every plausible English-word-completion position, then validate against an offline oracle (see below) before submitting.

### Validation: writeup-decrypt oracle
Many CTF writeups are AES-encrypted on creator blogs with the flag as password (CryptoJS `AES.encrypt`, OpenSSL EVP_BytesToKey, MD5-derived key+IV). Use as offline brute-force oracle to avoid HTB rate-limit / lockout:

```python
# /tmp/test_decrypt.py
import base64
from Crypto.Cipher import AES
from Crypto.Hash import MD5

CIPHERTEXT_B64 = "U2FsdGVkX1..."   # from `data-encrypted-message` attribute or staticrypt blob

def evp_bytes_to_key(pw, salt, klen=32, ivlen=16):
    dt, out = b"", b""
    while len(out) < klen + ivlen:
        dt = MD5.new(dt + pw + salt).digest()
        out += dt
    return out[:klen], out[klen:klen+ivlen]

def try_decrypt(pw):
    if isinstance(pw, str): pw = pw.encode()
    raw = base64.b64decode(CIPHERTEXT_B64)
    assert raw[:8] == b"Salted__"
    key, iv = evp_bytes_to_key(pw, raw[8:16])
    return AES.new(key, AES.MODE_CBC, iv).decrypt(raw[16:])

def is_plaintext(b):
    try: return b.decode("utf-8").isprintable()
    except: return False
```

A correct candidate decrypts to readable Markdown/HTML; wrong candidates produce random bytes. Batch-test 10-50 candidates per second locally.

### Case study: StayInTheBoxCorp (HTB 579)
- Naïve world-X sort of 31 inactive direct children + 5 active grandchildren of Canvas `f3`: `HTB{0v3rcom1ng_W34k_serMU0de_4nt1Cht34}` (wrong).
- Semantic insertion of grandchildren `_`, `_`, `U`, `h`, `t` at English-completing positions: `HTB{0v3rcom1ng_W34k_UserM0de_4nt1Ch34t}` ("Overcoming Weak UserMode AntiCheat") — accepted.
- Validated via writeup-oracle before HTB submission.
- Intended solve path per writeup: MelonLoader + UnityExplorer IL2CPP to disable obstacle `DoQ` GameObject in-game and walk to the flag display.
