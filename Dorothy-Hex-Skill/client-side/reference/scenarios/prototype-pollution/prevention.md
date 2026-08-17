# Prototype Pollution — Prevention and Hardening

## When this applies

You're advising on remediation, hardening a Node.js / browser-side codebase, or writing a defense recommendation in a pentest report. Includes safe coding patterns, framework-specific protections, and security headers.

## Technique

Five defense layers:
1. **Allowlist property keys** when merging user input.
2. **Use prototype-less objects** (`Object.create(null)`) or `Map`.
3. **Freeze prototypes** (`Object.freeze(Object.prototype)`) globally.
4. **Validate JSON structure** before deserializing into runtime objects.
5. **CSP + Trusted Types** to mitigate downstream XSS gadgets.

## Steps

### JavaScript / Node.js

```javascript
// 1. Sanitize property keys (Allowlist)
const ALLOWED_PROPERTIES = ['name', 'email', 'address', 'city', 'postcode'];

function safeAssign(target, source) {
    for (const key of ALLOWED_PROPERTIES) {
        if (source.hasOwnProperty(key)) {
            target[key] = source[key];
        }
    }
    return target;
}

// 2. Sanitize property keys (Blocklist - less secure)
function isPrototypePollutionKey(key) {
    return ['__proto__', 'constructor', 'prototype'].includes(key);
}

function safeMerge(target, source) {
    for (const key in source) {
        if (source.hasOwnProperty(key) && !isPrototypePollutionKey(key)) {
            if (typeof source[key] === 'object' && source[key] !== null) {
                target[key] = safeMerge(target[key] || {}, source[key]);
            } else {
                target[key] = source[key];
            }
        }
    }
    return target;
}

// 3. Use objects without prototypes
function createSafeConfig(defaults = {}) {
    const config = Object.create(null);
    return Object.assign(config, defaults);
}

// Usage
const config = createSafeConfig({
    apiUrl: '/api',
    timeout: 5000
});

// 4. Freeze prototypes (global protection)
Object.freeze(Object.prototype);
Object.freeze(Array.prototype);
Object.freeze(Function.prototype);

// 5. Use Map instead of objects
const config = new Map();
config.set('apiUrl', '/api');
config.set('timeout', 5000);
// Map.get() only accesses direct properties

// 6. Express middleware for protection
const express = require('express');
const app = express();

app.use((req, res, next) => {
    function checkObject(obj, path = '') {
        if (typeof obj !== 'object' || obj === null) return;

        for (const key in obj) {
            if (['__proto__', 'constructor', 'prototype'].includes(key)) {
                console.error(`[SECURITY] PP attempt detected: ${path}.${key}`);
                return res.status(400).json({
                    error: 'Invalid input detected'
                });
            }

            if (typeof obj[key] === 'object') {
                checkObject(obj[key], `${path}.${key}`);
            }
        }
    }

    checkObject(req.body);
    checkObject(req.query);
    next();
});

// 7. Secure JSON parsing
const secureJsonParse = require('secure-json-parse');

app.use(express.json({
    verify: (req, res, buf) => {
        try {
            secureJsonParse(buf.toString());
        } catch (e) {
            throw new Error('Invalid JSON structure');
        }
    }
}));

// 8. Lodash safe merge
const _ = require('lodash');

_.mergeWith(target, source, (objValue, srcValue, key) => {
    // Block prototype pollution keys
    if (['__proto__', 'constructor', 'prototype'].includes(key)) {
        return objValue; // Don't merge
    }
});
```

### Python / Flask

```python
from flask import Flask, request, jsonify
import json

app = Flask(__name__)

# Middleware to check for prototype pollution attempts
@app.before_request
def check_prototype_pollution():
    BLOCKED_KEYS = ['__proto__', 'constructor', 'prototype']

    def check_dict(d, path=''):
        if not isinstance(d, dict):
            return True

        for key, value in d.items():
            if key in BLOCKED_KEYS:
                return False, f"Blocked key detected: {path}.{key}"

            if isinstance(value, dict):
                result, msg = check_dict(value, f"{path}.{key}")
                if not result:
                    return result, msg

        return True, None

    if request.is_json:
        result, msg = check_dict(request.json)
        if not result:
            return jsonify({'error': 'Invalid input'}), 400

# Safe property assignment
def safe_update(target, source, allowed_keys):
    """Only update allowed keys"""
    for key in allowed_keys:
        if key in source:
            target[key] = source[key]
    return target

# Usage
@app.route('/api/update', methods=['POST'])
def update_user():
    data = request.json
    user = {}

    # Allowlist approach
    ALLOWED_KEYS = ['name', 'email', 'address']
    safe_update(user, data, ALLOWED_KEYS)

    return jsonify(user)
```

### React / TypeScript

```typescript
// Type-safe configuration
interface SafeConfig {
    apiUrl: string;
    timeout: number;
    headers?: Record<string, string>;
}

// Sanitization function
function sanitizeObject<T>(obj: unknown, allowedKeys: (keyof T)[]): Partial<T> {
    if (typeof obj !== 'object' || obj === null) {
        return {};
    }

    const sanitized: Partial<T> = {};
    const BLOCKED_KEYS = ['__proto__', 'constructor', 'prototype'];

    for (const key of allowedKeys) {
        const strKey = String(key);
        if (BLOCKED_KEYS.includes(strKey)) {
            continue;
        }

        if (key in obj) {
            sanitized[key] = (obj as any)[key];
        }
    }

    return sanitized;
}

// Usage in component
function MyComponent(props: any) {
    const safeConfig = sanitizeObject<SafeConfig>(
        props.config,
        ['apiUrl', 'timeout', 'headers']
    );

    return <div>{/* Use safeConfig */}</div>;
}

// Server Action protection
'use server'

export async function updateUser(formData: FormData) {
    const ALLOWED_FIELDS = ['name', 'email', 'address'] as const;

    const data: Record<string, string> = {};
    for (const field of ALLOWED_FIELDS) {
        const value = formData.get(field);
        if (value && typeof value === 'string') {
            data[field] = value;
        }
    }

    // data is now safe from prototype pollution
    await db.users.update(data);
}
```

### Security Headers

```http
# Content Security Policy (mitigates client-side PP XSS)
Content-Security-Policy:
    default-src 'self';
    script-src 'self' 'nonce-RANDOM';
    object-src 'none';
    base-uri 'self';
    require-trusted-types-for 'script';

# Additional headers
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Referrer-Policy: no-referrer
Permissions-Policy: geolocation=(), microphone=(), camera=()
```

## Verifying success

- After mitigation, pollution payloads return 400 (or are silently dropped) and `Object.prototype.<key>` remains untouched.
- Allowlist tests: send extra fields → server only persists the allowlisted ones.
- `Object.freeze(Object.prototype)` test: `Object.prototype.test = '1'` throws in strict mode (or silently fails in non-strict).
- CSP test: `data:,alert(1)` script-src payload is blocked by CSP report or runtime error.

## Common pitfalls

1. **Allowlist incomplete** — newly added fields require manual update. Prefer schema validation libraries (`ajv`, `zod`, `joi`).
2. **Blocklist misses `__proto__.__proto__` chain** — recursive check is required to catch nested pollution.
3. **`Object.freeze(Object.prototype)` breaks third-party libs** — some libraries assign to `Object.prototype` legitimately. Test thoroughly before deploying.
4. **`secure-json-parse` doesn't catch URL parameter pollution** — middleware must also sanitize `req.query`.
5. **CSP `'unsafe-eval'` defeats Trusted Types** — incompatible directives. Audit existing CSP before tightening.

## Tools

- **`secure-json-parse`** — npm package; throws on `__proto__` keys
- **`ajv` / `zod` / `joi`** — schema validation; reject unexpected keys
- **`lodash.mergeWith`** — safe deep merge with customizer
- **ESLint plugin `security`** — flags risky merge patterns
- **CSP Evaluator (Google)** — score CSP strictness
- **NodeGoat / DVWA / Juice Shop** — practice safe-vs-unsafe patterns
