# Client-Side Reference INDEX

Catalog of all reference files. See `client-side-principles.md` for the cross-class decision tree.

## Principles

| File | Purpose |
|------|---------|
| `client-side-principles.md` | When to suspect each vuln class; decision tree across XSS / pp / DOM |

## Single-file references (root of `reference/`)

| File | Purpose |
|------|---------|
| `clickjacking-cheat-sheet.md` | UI redress / clickjacking payloads and detection |
| `clickjacking-quickstart.md` | Clickjacking quick start workflow |
| `cors-cheat-sheet.md` | CORS misconfiguration patterns and exploitation |
| `cors-quickstart.md` | CORS testing quick start |
| `csrf-quickstart.md` | CSRF testing methodology and PoC patterns |
| `dom-xss-advanced.md` | Advanced DOM XSS sinks and source aliases |
| `dom-xss-quickstart.md` | DOM XSS quick start workflow |
| `prototype-pollution-quickstart.md` | Prototype pollution quick start |
| `prototype-pollution-resources.md` | Curated PP research, tools, CVEs, and reading list |
| `xss-bypass-techniques.md` | WAF / filter bypass payload corpus |

## Scenarios — XSS Exploitation Patterns (`scenarios/xss/`)

| File | Goal |
|------|------|
| `cookie-theft.md` | Steal `document.cookie` → impersonate victim |
| `password-capture.md` | Autofill abuse + fake login overlay → credential capture |
| `csrf-via-xss.md` | Read CSRF token via DOM → submit state-changing request |
| `keylogging.md` | Buffer keystrokes → batch exfiltrate (sendBeacon) |
| `defacement.md` | Page replacement, link hijack, payment-form swap |
| `beef-integration.md` | Hook victim browser → BeEF post-exploitation modules |
| `internal-network-scanning.md` | Image-timing port scan + service fingerprint via fetch |
| `session-hijacking.md` | Scrape cookies + localStorage + sessionStorage → replay |
| `data-exfiltration.md` | DOM walk, form/meta/script harvest → bulk JSON exfil |
| `phishing-attacks.md` | Fake OAuth / re-auth overlay → credential theft |

## Scenarios — Prototype Pollution (`scenarios/prototype-pollution/`)

| File | Topic |
|------|------|
| `detection.md` | Client- and server-side detection (URL `__proto__[x]`, JSON spaces, status code, property reflection) |
| `client-side-pollution.md` | Browser-side pollution + XSS gadgets (`transport_url`, eval) |
| `server-side-pollution.md` | Node.js privilege escalation, RCE via `execArgv` / template engines / Mongoose |
| `gadget-discovery.md` | Find exploitable property-check patterns; common client-side and server-side gadgets |
| `bypass-techniques.md` | Filter evasion (non-recursive replace, case, Unicode, alt access); WAF bypass |
| `testing-tools.md` | cURL, Burp Repeater/Intruder, DOM Invader, Collaborator workflows |
| `prevention.md` | Allowlist merging, freezing prototypes, `Object.create(null)`, `Map`, security headers |

## Scenarios — DOM Vulnerabilities (`scenarios/dom-vulnerabilities/`)

| File | Topic |
|------|------|
| `dom-xss-fundamentals.md` | Sources, sinks, four contexts (HTML / attribute / JS string / URL) |
| `document-write-sink.md` | `document.write()` exploitation incl. `<select>` breakout |
| `innerhtml-sink.md` | `innerHTML` exploitation (event handlers since `<script>` doesn't execute) |
| `jquery-sinks.md` | `$()` selector, `.attr('href', javascript:...)`, hashchange `$(...)` patterns |
| `angularjs-injection.md` | AngularJS 1.x expression injection (`{{$on.constructor(...)()}}`) |
| `postmessage-vulnerabilities.md` | Web message handlers without origin validation; flawed `indexOf` checks; JSON-parse + iframe.src |
| `prototype-pollution-dom.md` | DOM XSS via client-side prototype pollution (transport_url, eval gadgets) |
| `dom-clobbering-globals.md` | Clobber `window.*` to override JS defaults → XSS via `cid:`, `data:` |
| `dom-clobbering-sanitizer-bypass.md` | Clobber `node.attributes` to defeat HTMLJanitor / sanitize-html loops |
| `waf-filter-bypass.md` | Encoding tricks, tag/attr variations, keyword splits, context breakouts |
| `exfiltration-and-chaining.md` | Chain DOM XSS with CSRF / clickjacking / prototype pollution; exfiltration channels |
| `detection-methodology.md` | Manual code review + DevTools + SAST + dynamic scanning workflow |
| `prevention-best-practices.md` | Input validation, encoding, safe APIs, CSP, sanitization, framework patterns |
| `tools-and-automation.md` | DOM Invader, XSS Hunter, DalFox, XSStrike, Nuclei templates, custom JS scanners |
