# Client-Side Vulnerability Principles

Decision tree across the three primary client-side vulnerability classes covered in `scenarios/`: **XSS exploitation patterns**, **prototype pollution**, and **DOM-based vulnerabilities** (DOM XSS, postMessage, DOM clobbering).

## When to suspect each class

### XSS Exploitation Patterns (`scenarios/xss/`)

You already have an XSS sink (reflected, stored, or DOM-based) and need to maximize impact. Suspect when:
- Pentest report needs a working PoC (cookie theft, account takeover, CSRF chain).
- Bug bounty submission requires demonstrating realistic harm beyond `alert(1)`.
- Red team engagement: pivoting from a website foothold to internal network or session takeover.

Triage by goal:
- Steal session → `xss/cookie-theft.md` or `xss/session-hijacking.md`.
- Capture credentials → `xss/password-capture.md` or `xss/phishing-attacks.md`.
- Bypass CSRF → `xss/csrf-via-xss.md`.
- Long-term monitoring → `xss/keylogging.md`.
- Modify page or scam visitors → `xss/defacement.md`, `xss/phishing-attacks.md`.
- Persistent control → `xss/beef-integration.md`.
- Internal recon → `xss/internal-network-scanning.md`.
- Bulk data theft → `xss/data-exfiltration.md`.

### Prototype Pollution (`scenarios/prototype-pollution/`)

The application unsafely merges user-controlled keys into objects. Suspect when:
- JSON endpoints accept arbitrary nested objects.
- URL parsing uses `deparam`, jQuery `$.extend`, lodash `_.merge` (especially older versions).
- Recursive merge / config object loading patterns are visible in JS source.
- Server-side: Node.js / Express / Fastify with `body-parser` or custom JSON merge middleware.

Workflow:
1. **Detect** → `prototype-pollution/detection.md` (URL `__proto__[x]=1`, JSON `"json spaces": 10`).
2. **Find a gadget** → `prototype-pollution/gadget-discovery.md`.
3. **Exploit** → `prototype-pollution/client-side-pollution.md` (XSS) or `prototype-pollution/server-side-pollution.md` (privilege escalation, RCE).
4. **Bypass filters** → `prototype-pollution/bypass-techniques.md`.
5. **Tooling** → `prototype-pollution/testing-tools.md`.
6. **Remediate** → `prototype-pollution/prevention.md`.

### DOM Vulnerabilities (`scenarios/dom-vulnerabilities/`)

JavaScript reads attacker-controllable data and uses it in dangerous ways without server involvement. Suspect when:
- Single-page app, heavy client-side JS, no server-side reflection.
- URL fragment (`location.hash`) or query (`location.search`) drives UI state.
- `postMessage` listeners or third-party widgets present.
- Sanitizer in front of user-generated HTML (DOMPurify, HTMLJanitor) — DOM clobbering may bypass.

Triage by sink:
- `document.write()` → `dom-vulnerabilities/document-write-sink.md`.
- `innerHTML` / `outerHTML` → `dom-vulnerabilities/innerhtml-sink.md`.
- jQuery `$()`, `.attr()`, hashchange → `dom-vulnerabilities/jquery-sinks.md`.
- AngularJS expression interpolation → `dom-vulnerabilities/angularjs-injection.md`.
- `postMessage` handler → `dom-vulnerabilities/postmessage-vulnerabilities.md`.
- `window.x` clobbering for XSS → `dom-vulnerabilities/dom-clobbering-globals.md`.
- Sanitizer-internal clobbering → `dom-vulnerabilities/dom-clobbering-sanitizer-bypass.md`.
- Pollution + DOM gadget → `dom-vulnerabilities/prototype-pollution-dom.md` (and the dedicated `prototype-pollution/` directory for broader coverage).
- Filter / WAF blocks payload → `dom-vulnerabilities/waf-filter-bypass.md`.
- Chain with CSRF / clickjacking / exfil → `dom-vulnerabilities/exfiltration-and-chaining.md`.
- Detection methodology → `dom-vulnerabilities/detection-methodology.md`.
- Prevention guidance → `dom-vulnerabilities/prevention-best-practices.md`.
- Tooling → `dom-vulnerabilities/tools-and-automation.md`.

## Decision tree

```
Is there a usable XSS sink already?
├─ Yes → scenarios/xss/* — pick by impact goal
│   ├─ steal cookies/session → cookie-theft.md / session-hijacking.md
│   ├─ capture creds → password-capture.md / phishing-attacks.md
│   ├─ bypass CSRF → csrf-via-xss.md
│   ├─ keylog → keylogging.md
│   ├─ deface / page tamper → defacement.md
│   ├─ post-exploit framework → beef-integration.md
│   ├─ internal recon → internal-network-scanning.md
│   └─ bulk content theft → data-exfiltration.md
│
└─ No → enumerate sources/sinks first
    │
    ├─ JS reads URL/hash/postMessage and writes to dangerous sink?
    │   → scenarios/dom-vulnerabilities/dom-xss-fundamentals.md
    │   → pick sink-specific scenario (document-write / innerhtml / jquery / angularjs / postmessage)
    │
    ├─ JS unsafely merges user-controlled keys into objects?
    │   → scenarios/prototype-pollution/detection.md
    │   → if confirmed: gadget-discovery.md → client-side or server-side exploit
    │
    └─ Sanitizer-allowed HTML can override JS globals?
        → scenarios/dom-vulnerabilities/dom-clobbering-globals.md (window-global pattern)
        → scenarios/dom-vulnerabilities/dom-clobbering-sanitizer-bypass.md (defeat sanitizer loops)
```

## Cross-cutting tips

- **Source code first**: read bundled JS (de-minify with sourcemaps if available) before crafting payloads. Knowing the exact sink saves dozens of failed payloads.
- **DOM Invader is your friend**: the Burp Pro feature auto-detects sources, sinks, prototype pollution, and DOM clobbering. Run it against any client-side target before manual work.
- **CSP changes the game**: `script-src 'self'` blocks `data:` URIs; `'unsafe-inline'` allows them. Read the policy before choosing payload type.
- **Verify with browser, not just response**: DOM XSS may not appear in HTTP responses. Headless browser (Playwright) eval is needed for at-scale detection.
- **Chain ladder**: simple `alert(1)` → cookie theft → CSRF chain → privilege escalation. Always show the highest-impact PoC the engagement scope permits.
- **Remediation**: every scenario file lists prevention pointers. For codebase-wide hardening, see `dom-vulnerabilities/prevention-best-practices.md` and `prototype-pollution/prevention.md`.

## Reference shortcuts

Single-file resources outside the scenarios tree (in `reference/` root):
- `dom-xss-quickstart.md`, `dom-xss-advanced.md` — sink/source quick reference
- `prototype-pollution-quickstart.md`, `prototype-pollution-resources.md` — quickstart and curated resource list
- `xss-bypass-techniques.md` — WAF/filter bypass corpus
- `cors-quickstart.md`, `cors-cheat-sheet.md` — CORS misconfiguration
- `csrf-quickstart.md` — CSRF testing
- `clickjacking-quickstart.md`, `clickjacking-cheat-sheet.md` — UI redress

See `INDEX.md` for the full catalog.
