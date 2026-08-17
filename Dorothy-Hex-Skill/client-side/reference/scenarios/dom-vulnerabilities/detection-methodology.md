# DOM Vulnerabilities — Detection Methodology

## When this applies

You're auditing a client-side codebase for DOM-based vulnerabilities — manual code review, static analysis, dynamic scanning, or a mix. Goal is to systematically discover sources, sinks, and untrusted data flows before any payload crafting.

## Technique

Layer four detection approaches: (1) manual code review with grep patterns, (2) browser DevTools inspection, (3) SAST/static analysis tools, (4) dynamic scanning with Burp Scanner / OWASP ZAP / DOM Invader.

## Steps

### Manual Code Review

**Look for dangerous sinks:**
```bash
# Search JavaScript files
grep -r "innerHTML" *.js
grep -r "document.write" *.js
grep -r "eval(" *.js
grep -r "Function(" *.js
grep -r "\.html(" *.js
grep -r "\.attr(" *.js
```

**Look for attacker-controllable sources:**
```bash
grep -r "location.search" *.js
grep -r "location.hash" *.js
grep -r "location.href" *.js
grep -r "document.referrer" *.js
grep -r "postMessage" *.js
```

**Trace data flow:**
1. Find source (e.g., `location.search`)
2. Follow variable through code
3. Check if it reaches sink without sanitization
4. Verify context and exploitability

### Browser DevTools

**1. Network tab:**
- Monitor AJAX requests
- Check if sensitive data sent to external domains
- Verify XSS execution

**2. Console tab:**
- Test payloads interactively
- Check for JavaScript errors
- Verify object properties

**3. Sources/Debugger:**
- Set breakpoints on dangerous sinks
- Step through code execution
- Inspect variable values

**4. Elements tab:**
- Inspect rendered DOM
- Verify payload injection
- Check computed styles

### Static Analysis Tools

**ESLint with security plugins:**
```bash
npm install --save-dev eslint-plugin-security
```

```json
{
  "plugins": ["security"],
  "extends": ["plugin:security/recommended"]
}
```

**Semgrep rules:**
```yaml
rules:
  - id: dom-xss-innerHTML
    pattern: $X.innerHTML = $SOURCE
    message: Potential DOM XSS via innerHTML
    severity: WARNING
```

**Other static scanners:** NodeJsScan, Retire.js, Snyk Code, CodeQL.

### Dynamic Analysis

**Burp Suite Scanner:**
- Automatically crawls and scans
- Detects DOM-based vulnerabilities
- Provides PoC payloads

**OWASP ZAP:**
- Active scanning for DOM XSS
- Spider for JavaScript analysis
- DOM XSS detection

**DOM Invader (Burp Suite):**
- Automatic source/sink detection
- Prototype pollution scanning
- Gadget discovery
- One-click exploitation

## Verifying success

- Grep results enumerate all candidate source/sink locations.
- DevTools breakpoints fire on suspect sinks during normal app use, confirming runtime reach.
- SAST output reports concrete findings with file/line references.
- Dynamic scan results trigger expected canaries (DOM Invader injects unique strings; check Sinks panel).

## Common pitfalls

1. **Bundled / minified JS hides sources** — ungzip and use sourcemaps before grep, or run grep on the bundle and check for variable aliases.
2. **Indirect data flow** — `var x = location.search; var y = x; sink(y)` — single-grep misses the alias chain.
3. **Lazy-loaded scripts** — sinks defined in code that loads after a user interaction. Trigger the relevant flow before inspecting.
4. **DOM Invader misses framework-encapsulated sinks** — React/Vue/Angular's `dangerouslySetInnerHTML` etc. may not be flagged. Manually grep for these patterns.
5. **Static scanners flood with false positives** — tune rule sensitivity; require both source and sink in the same data flow.

## Tools

- **`grep` / `ripgrep`** — pattern search
- **DOM Invader (Burp Pro)** — automatic source/sink detection
- **Burp Scanner / OWASP ZAP** — dynamic scanning
- **`eslint-plugin-security`** — JS lint
- **Semgrep / CodeQL** — pattern-based SAST
- **Browser DevTools Sources panel** — runtime breakpoints
- **Sourcemap-aware grep** — `grep` against the original source after unbundling

## Related

- `prevention-best-practices.md` — remediation guidance after detection
