# Obfuscated Client-Side JS — Deobfuscation for Hidden Endpoints

## When this applies

A target page ships a JS bundle that looks like one of:

- JSFuck — `[(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+...]` — only `[]()!+` characters.
- Self-decoding eval/Function payloads — `eval(function(p,a,c,k,e,d){...})` (packer.js) or `Function("return …")()`.
- WASM-string-table lookups, base64/hex pre-images that are decoded at runtime.

You suspect the bundle hides API routes, default credentials, debug flags, or feature gates that are not visible in network traffic until the JS executes.

## Technique

The shortest path to the decoded source is to let the program decode itself, but intercept the final step that would execute the result. Replacing `Function`, `eval`, or `Function.prototype.constructor` with a logging stub yields the post-decode source. Static deobfuscation tools (`jsfuck-decoder`, `de4js`) work for simple variants but fail on layered or self-rewriting payloads.

## Steps

1. Identify the obfuscated bundle and its load site:

   ```bash
   curl -sk "${BASE}/" | grep -oE 'src=["'\'']/[^"'\'']+\.js["'\'']'
   curl -sk "${BASE}/static/app.js" -o recon/raw/app.js
   wc -c recon/raw/app.js                # JSFuck blobs are megabytes of `[]()!+`
   head -c 200 recon/raw/app.js
   ```

2. Fingerprint the obfuscation:

   ```bash
   # JSFuck — characters are restricted to []()!+
   tr -d '[]()!+' < recon/raw/app.js | wc -c   # near-zero = JSFuck
   # Packer — leading "eval(function(p,a,c,k,e,d){"
   grep -c "eval(function(p,a,c,k,e,d)" recon/raw/app.js
   # Function-constructor wrapper — string passed to Function(...) returned
   grep -c "Function(" recon/raw/app.js
   ```

3. Intercept the executor in Node. The key idea: every self-decoding payload eventually feeds a string to `Function`, `eval`, or `setTimeout(string,…)`. Stub them out and dump the string.

   ```bash
   cat > /tmp/dump.js <<'EOF'
   // Hijack the bound Function constructor and eval — JSFuck resolves to
   // (function(){…})() via Function.prototype.constructor("…")() at the end.
   const orig = Function;
   global.Function = function (...a) {
     console.log("=== Function called with ===");
     console.log(a.join("|"));
     // Return a no-op so the program does not actually execute.
     return function () {};
   };
   global.eval = (src) => { console.log("=== eval called with ==="); console.log(src); };
   require("fs").readFileSync(process.argv[2], "utf8");  // load + run
   eval(require("fs").readFileSync(process.argv[2], "utf8"));
   EOF
   node /tmp/dump.js recon/raw/app.js > recon/raw/app_decoded.raw 2>&1
   ```

   Sandboxed alternative — run inside `vm` to prevent file/network side effects:

   ```bash
   cat > /tmp/dump-vm.js <<'EOF'
   const vm = require("vm");
   const ctx = vm.createContext({
     console,
     Function: function (...a) { console.log(a.join("|")); return () => {}; },
     eval: (s) => { console.log(s); },
   });
   vm.runInContext(require("fs").readFileSync(process.argv[2], "utf8"), ctx, { timeout: 5000 });
   EOF
   node /tmp/dump-vm.js recon/raw/app.js > recon/raw/app_decoded.raw 2>&1
   ```

4. Post-process the dumped source. JSFuck-decoded output is often re-escaped as octal sequences (`\101\160`) or hex (`\x41\x70`); decode in Python:

   ```python
   # recon/decode_escapes.py
   import re, sys, codecs
   src = open(sys.argv[1]).read()
   # Resolve octal \nnn and hex \xnn first (JS string literal escape syntax)
   src = codecs.decode(src.encode("latin-1", errors="ignore"), "unicode_escape")
   open(sys.argv[2], "w").write(src)
   ```

   ```bash
   python3 recon/decode_escapes.py recon/raw/app_decoded.raw recon/inventory/app_decoded.js
   ```

5. Mine the decoded source for endpoints, secrets, and feature flags:

   ```bash
   grep -hoE '"/(api|v[0-9]+|admin|internal)/[A-Za-z0-9_/{}.-]+"' recon/inventory/app_decoded.js | sort -u
   grep -hoE '(fetch|axios\.(get|post|put|delete))\(["`][^"`]+["`]' recon/inventory/app_decoded.js | sort -u
   grep -hiE '(api[_-]?key|secret|token|bearer|password)\s*[:=]\s*["`][^"`]+' recon/inventory/app_decoded.js
   ```

   Treat any discovered route as a follow-up target for [api-endpoint-discovery.md](api-endpoint-discovery.md) — re-walk methods, parameters, and auth.

## Verifying success

- `recon/inventory/app_decoded.js` parses as valid JS (no `[]()!+`-only artefacts).
- Endpoints surface in `grep` that were absent from `recon/raw/api-routes.txt` produced by network observation alone.
- Re-loading the page with the original JS replaced by the dumped version produces equivalent behaviour in DevTools.

## Common pitfalls

- Running the bundle in plain Node without intercepting `Function`/`eval` actually executes the obfuscated code — including any fetch-based beacon or DOM mutation it intended. Always stub before invoking.
- Some payloads wrap the decoded JS in a second `Function("return …")()` layer. Iterate: intercept, log, re-feed the logged string back through the stub.
- JSFuck output occasionally contains the literal `\` characters as part of a regexp or template string — applying `unicode_escape` corrupts those. Compare lengths before/after and review diffs for regex literals.
- `eval` patches in the browser are easier to set in DevTools Sources panel via a Function Override; Node interception is preferred for unattended automation.

## Tools

- `node` — interpreter for interception stub.
- Python `codecs.decode(..., "unicode_escape")` — hex/octal escape resolution.
- `de4js`, `jsfuck-decoder` — try these first; fall back to interception when they choke.
- DevTools Sources → "Format Pretty Print" + breakpoint on `Function`/`eval` for interactive triage.
- `jsluice`, `linkfinder` — endpoint extraction after deobfuscation.
