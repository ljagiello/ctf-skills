# CTF Reverse - MBA Simplification with msynth

## MBA Simplification with msynth

Mixed Boolean-Arithmetic (MBA) obfuscation rewrites simple operations (e.g. `x + y`) as tangled combinations of bitwise and arithmetic ops. Typical MBA shape in decompiler output:

```c
// MBA-obfuscated addition — spot the (x ^ y) + 2 * (x & y) pattern
out = (x ^ y) + 2 * (x & y);   // == x + y
```

**Key insight:** `(x ^ y) + 2*(x & y) == x + y` — the XOR carries the sum bits without carry, the AND-shifted term restores the carry. Detection heuristic: decompiler output mixing `^`, `&`, `|` with `+`, `*` and small constants (especially `* 2`) on the same variables is MBA until proven otherwise.

### Install

```bash
uv pip install "msynth @ git+https://github.com/mrphrazer/msynth.git" z3-solver
uv pip install "miasm @ git+https://github.com/cea-sec/miasm.git@1dc5fa9"
```

> Note: msynth is not on PyPI (`uv pip install msynth` fails with "not found in the package registry") — install from the git URL. Pin miasm to commit `1dc5fa9`: the PyPI miasm release imports the long-dead `imp` module and breaks on Python 3.12+. Smoke test: `python -c "from msynth import Simplifier, Synthesizer"`.

### Simplifier Path (Oracle Lookup)

The `Simplifier` looks up unified subexpressions in a precomputed oracle of I/O equivalence classes. The oracle is not shipped ready-made: the msynth checkout's `database/` directory holds a `3_variables_constants_7_nodes.txt.zip` expression table (1,293,020 combinations), and you build the oracle from it (10+ minutes) or fetch the precomputed `oracle.pickle` linked from the msynth README:

```bash
git clone https://github.com/mrphrazer/msynth.git
unzip -d msynth/database -q msynth/database/3_variables_constants_7_nodes.txt.zip
python msynth/scripts/gen_oracle.py msynth/database/3_variables_constants_7_nodes.txt oracle.pickle
```

```python
from pathlib import Path
from msynth import Simplifier, parse_infix_expr

simp = Simplifier(oracle_path=Path("oracle.pickle"))
out = simp.simplify(parse_infix_expr("(x ^ y) + 2*(x & y)"))
print(out)  # x + y
```
With `oracle_path=None` the oracle branch always misses and only SimBA rewriting applies — still useful for light MBA, but the oracle carries most of the load on hard inputs.

### Synthesizer Path (From-Scratch Search)

Without an oracle, `Synthesizer(use_smir=True).simplify` searches candidate rewrites from scratch via `iterated_local_search`. Slower (seconds to minutes per expression) and stochastic — a hard MBA ran 61 s unchanged in prior smoke testing, so budget time and retries:

```python
from msynth import Synthesizer, parse_infix_expr

orig = parse_infix_expr("(x ^ y) + 2*(x & y)")
out = Synthesizer(use_smir=True).simplify(orig, num_samples=10, timeout=60)
print(out)  # x + y (observed in 0.9 s on this input)
```

### Equivalence Check (Mandatory)

Never trust a simplifier blindly — synthesis is stochastic and a wrong "simplification" silently breaks the solve. Evaluate both sides on N random 64-bit inputs, assert equality, and treat any mismatch as synthesis failure (retry with a longer timeout or fall back to manual analysis):

```python
import random
import z3
from miasm.ir.translators.z3_ir import TranslatorZ3

def check_equivalent(a, b, n=2000, seed=0xC7F):
    """Random differential test over 64-bit inputs. Returns True iff all N agree."""
    rng = random.Random(seed)
    names = sorted({str(x) for x in a.get_r()} | {str(x) for x in b.get_r()})
    t = TranslatorZ3()
    za, zb = t.from_expr(a), t.from_expr(b)
    zvars = {v: z3.BitVec(v, 64) for v in names}
    for _ in range(n):
        sub = [(zvars[v], z3.BitVecVal(rng.getrandbits(64), 64)) for v in names]
        va = z3.simplify(z3.substitute(za, *sub)).as_long() & (1 << 64) - 1
        vb = z3.simplify(z3.substitute(zb, *sub)).as_long() & (1 << 64) - 1
        if va != vb:
            return False
    return True

assert check_equivalent(orig, out, n=2000), "synthesis failure: outputs differ"
```

### Miasm Integration

msynth expressions are miasm `Expr` objects, so results plug directly into miasm-based tooling such as `miasm/expression/simplifications.py` (`ExpressionSimplifier` / `expr_simp`) for further reduction or SMT-backed reasoning.

### Ecosystem Map

- msynth — <https://github.com/mrphrazer/msynth>
- GAMBA: "Automated MBA Deobfuscation" (<https://arxiv.org/abs/2209.06335>) and follow-up (<https://arxiv.org/abs/2305.06763>)
- SiMBA (simplifier inside msynth's default pipeline) and mba-blast/Arybo — consult only if citable for the target at hand
