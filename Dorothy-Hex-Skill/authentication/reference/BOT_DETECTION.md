# Bot Detection Evasion

Quick reference for testing bot-detection systems and behavioral biometrics during authorized assessments.

## Detection technologies

| Category | Examples |
|---|---|
| Behavioral biometrics | Mouse movement patterns, keystroke dynamics, scroll behavior, touch gestures |
| Browser fingerprinting | Canvas, WebGL, font enumeration, AudioContext, Battery API |
| Automation detection | `navigator.webdriver`, headless Chrome flags, missing browser features |
| Network analysis | TLS JA3 fingerprint, TCP options, IP reputation, DNS patterns |
| AI/ML scoring | Combined signals → risk score → block / challenge / allow |

Common services: PerimeterX, DataDome, Akamai Bot Manager, Cloudflare Bot Management, Imperva, Distil.

## Detection identification

```bash
# Inspect HTTP headers / cookies
curl -sv https://target/ 2>&1 | grep -iE 'cf-|x-px-|datadome|akam|imperva'

# Look for fingerprinting JS
curl -s https://target/ | grep -iE 'fingerprint|canvas\.|webgl|audiocontext|webdriver'

# Common loader URLs
# /pxhd, /pxc, /captcha, /antibot, /datadome, /_dd, /_pxhd
```

## Evasion technique 1: Behavioral biometrics simulation

### Mouse movement (Bezier curves)

Bots move in straight lines. Real users:
- Curved paths (Bezier interpolation).
- Variable speed (acceleration / deceleration).
- Slight overshooting / correction.

```python
from playwright.async_api import async_playwright
import math, random

async def human_mouse_to(page, x, y):
    start = await page.evaluate("""() => ({x: window.mouseX || 0, y: window.mouseY || 0})""")
    steps = random.randint(20, 50)
    for i in range(steps):
        t = i / steps
        # Bezier curve through midpoint with slight randomness
        mx = start['x'] + (x - start['x']) * (3*t*t - 2*t*t*t) + random.uniform(-2, 2)
        my = start['y'] + (y - start['y']) * (3*t*t - 2*t*t*t) + random.uniform(-2, 2)
        await page.mouse.move(mx, my)
        await page.wait_for_timeout(random.randint(8, 25))
```

### Keystroke dynamics

```python
async def human_type(page, selector, text):
    await page.click(selector)
    for char in text:
        await page.keyboard.type(char)
        # Real typing: 50-200ms between keystrokes; longer pauses on words
        delay = random.gauss(120, 40)
        if char == ' ':
            delay += random.uniform(0, 200)   # word-end pause
        await page.wait_for_timeout(int(max(40, delay)))
```

### Scroll behavior

Real users: variable speed, occasional pauses, wheel deltas, NOT smooth fixed-rate scrolling.

```python
async def human_scroll(page, total_distance):
    remaining = total_distance
    while remaining > 0:
        delta = random.randint(50, 150)
        await page.mouse.wheel(0, delta)
        remaining -= delta
        await page.wait_for_timeout(random.randint(80, 300))
```

## Evasion technique 2: Browser fingerprint randomization

### Canvas fingerprinting

Inject noise into `getImageData`:

```javascript
const original = HTMLCanvasElement.prototype.toDataURL;
HTMLCanvasElement.prototype.toDataURL = function(type) {
    const ctx = this.getContext('2d');
    const data = ctx.getImageData(0, 0, this.width, this.height);
    for (let i = 0; i < data.data.length; i++) {
        data.data[i] = data.data[i] ^ (Math.floor(Math.random() * 4));
    }
    ctx.putImageData(data, 0, 0);
    return original.apply(this, arguments);
};
```

### WebGL fingerprinting

Patch `getParameter` to return generic GPU vendor / renderer.

```javascript
const getParameter = WebGLRenderingContext.prototype.getParameter;
WebGLRenderingContext.prototype.getParameter = function(parameter) {
    if (parameter === 37445) return "Intel Inc.";
    if (parameter === 37446) return "Intel(R) UHD Graphics 630";
    return getParameter.apply(this, [parameter]);
};
```

### User-Agent rotation

Use realistic recent UAs from Chrome / Firefox / Safari:

```python
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:122.0) Gecko/20100101 Firefox/122.0",
]
```

Match other headers (Accept-Language, Sec-CH-UA-*) to declared UA.

## Evasion technique 3: WebDriver detection evasion

```javascript
// Hide navigator.webdriver
Object.defineProperty(navigator, 'webdriver', {get: () => undefined});

// Spoof plugins (real browsers have plugins)
Object.defineProperty(navigator, 'plugins', {
    get: () => [{name:'Chrome PDF Plugin'},{name:'Chrome PDF Viewer'}]
});

// Spoof languages
Object.defineProperty(navigator, 'languages', {get: () => ['en-US','en']});

// Hide automation flags in Chrome
delete window.chrome.runtime.onConnect;
```

Use `playwright-stealth` / `puppeteer-extra-plugin-stealth` for production-grade patches.

## Evasion 4-5: Timing & request patterns

Real users hover before click (50-500ms), read pages (1-30s), interact slower on first visit. Random `await page.wait_for_timeout(random.randint(500, 3000))` before clicks. Vary UA / Accept-Language / referrer / cookie sets across requests.

## Playwright stealth + detection testing

```python
browser = await p.chromium.launch(
    headless=False,
    args=['--disable-blink-features=AutomationControlled','--no-sandbox'])
context = await browser.new_context(
    user_agent="Mozilla/5.0 ...",
    viewport={'width':1920,'height':1080},
    locale='en-US', timezone_id='America/New_York')
await context.add_init_script(
    "Object.defineProperty(navigator,'webdriver',{get:()=>undefined});")
```

Or use `playwright-extra` + `playwright-stealth-plugin` (Node).

Detection probes (run on target site):
```javascript
navigator.webdriver        // undefined = clean
window.chrome              // present in real Chrome
window.outerHeight === 0   // 0 = headless leak
```

## Common triggers / tools / checklist

**Triggers:** `navigator.webdriver === true`, headless UA, missing plugins/languages, identical mouse paths, sub-50ms keystrokes, identical TLS JA3, missing Sec-CH-UA-* headers, datacenter IP.

**Tools:**
- Playwright + playwright-stealth.
- Puppeteer-extra + puppeteer-extra-plugin-stealth.
- Selenium-stealth, undetected-chromedriver.
- curl-impersonate (TLS JA3 mimicry).
- Bright Data / Smartproxy (residential IPs).

**Checklist:**
- Mouse / keystroke / scroll randomization.
- Canvas / WebGL noise; UA matched with other headers; TLS JA3 mimicry.
- Hide `navigator.webdriver`; spoof plugins / languages.
- Variable request timing; realistic Referer; cookie persistence.

## References

- Akamai Bot Manager / DataDome / Imperva docs.
- OWASP Automated Threats handbook.
