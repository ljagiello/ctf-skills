# Prototype Pollution — Gadget Discovery

## When this applies

Pollution is confirmed (`Object.prototype.<key>` is settable). To weaponize, you need a *gadget* — code that reads a property which is normally undefined, falls through to the polluted prototype value, and uses it in a dangerous sink. Without a gadget, pollution is impact-less.

## Technique

Search the codebase (or runtime calls) for patterns where a property check `if (config.x)` reaches a sink. Common sinks: `script.src`, `eval`, `Function`, `innerHTML`, `setTimeout` string form, `child_process` options, template-engine internals.

## Steps

### Common Client-Side Gadgets

```javascript
// Script src manipulation
config.transport_url → script.src → XSS

// fetch() options
config.url → fetch(config.url) → SSRF
config.headers → fetch(url, {headers: config.headers}) → Header injection

// jQuery AJAX
config.url → $.ajax({url: config.url}) → SSRF
config.dataType → $.ajax({dataType: config.dataType}) → Script execution

// setTimeout/setInterval
config.callback → setTimeout(config.callback, 0) → Code execution
config.hitCallback → setTimeout(config.hitCallback, 0) → Code execution

// eval() sinks
config.code → eval(config.code) → Code execution
config.expression → Function(config.expression)() → Code execution

// DOM manipulation
config.html → element.innerHTML = config.html → XSS
config.template → element.innerHTML = template(config.template) → XSS

// Object.defineProperty bypass
descriptor.value → Object.defineProperty(obj, 'prop', descriptor) → Property injection
```

### Common Server-Side Gadgets

```javascript
// Authorization checks
user.isAdmin → if (user.isAdmin) { grantAccess(); }
options.authenticated → if (options.authenticated) { proceed(); }

// Configuration options
config.debug → if (config.debug) { exposeInternals(); }
options.bypassSecurity → if (!options.bypassSecurity) { checkAuth(); }

// Feature flags
features.premiumAccess → if (features.premiumAccess) { allowFeature(); }

// Process spawning (RCE)
options.execArgv → fork(script, [], {execArgv: options.execArgv})
options.shell → execSync(cmd, {shell: options.shell})
options.input → execSync(cmd, {input: options.input})

// JSON serialization
config['json spaces'] → JSON.stringify(data, null, config['json spaces'])

// HTTP responses
error.status → res.status(error.status).json({...})
```

### Manual Discovery — Search Patterns

```bash
# Look for property checks that fall through to prototype
grep -rE 'if\s*\(\s*\w+\.\w+\s*\)' src/

# Look for default-value patterns
grep -rE '\w+\s*\|\|\s*\w+' src/

# Look for sink-adjacent property reads
grep -rE 'innerHTML\s*=' src/
grep -rE 'eval\s*\(' src/
grep -rE 'script\.src\s*=' src/
grep -rE 'child_process' src/
```

### Vulnerable Code Patterns

```javascript
// Property existence checks
if (obj.property) { dangerous_sink(obj.property); }

// Default value patterns
let value = obj.property || default_value;

// Config object patterns
let config = loadConfig(); // May be empty object
if (config.feature) { enableFeature(); }

// Options patterns
function execute(options) {
    options = options || {};
    if (options.callback) eval(options.callback);
}
```

### Automated Detection with DOM Invader

1. **Enable DOM Invader**
2. **Scan for sources** — Identifies pollution vectors
3. **Scan for gadgets** — Finds exploitable properties
4. **Auto-exploit** — Generates working payloads

## Verifying success

- Polluting `Object.prototype.<gadget-key>` causes the candidate code path to behave as if the property were set on the original object.
- After exploitation, observable side-effect occurs (alert fires, command executes, response differs).
- Removing the pollution (`delete Object.prototype.<key>`) restores baseline behavior — confirms causation.

## Common pitfalls

1. **Property is always shadowed** — if every code path sets the property explicitly before reading, prototype lookup never happens. Look for paths where the property is *absent* (error handlers, default-config edges, fresh-object code).
2. **Strict equality `=== undefined`** — `if (obj.prop !== undefined)` still fires on prototype properties. `if (Object.hasOwn(obj, 'prop'))` does not.
3. **`Object.create(null)` defeats the gadget** — the prototype-less object skips your `__proto__`. Look elsewhere.
4. **Type mismatch** — gadget expects `function`, you polluted with string. Gadget expects array, you polluted with object. Read the gadget code carefully.
5. **Minified code hides gadgets** — DOM Invader may miss them. Use sourcemaps or readable npm versions during recon.

## Tools

- **DOM Invader** — automated client-side gadget discovery
- **PP Gadgets Finder (Doyensec / Burp BApp Store)** — server-side gadget DB
- **`Dasty`** — dynamic taint analysis pipeline (research tool, paper at arXiv:2311.03919)
- **`silent-spring`** — Node.js RCE-via-SSPP gadget framework
- **`BlackFan/client-side-prototype-pollution`** — community CSPP gadget collection
- **`yuske/server-side-prototype-pollution`** — community SSPP gadget DB
- **DevTools Sources panel + breakpoints on suspect sinks** — manually trace property reads
