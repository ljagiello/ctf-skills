# API Reference: Container Image Hardening Audit

## Libraries Used

| Library | Purpose |
|---------|---------|
| `subprocess` | Execute Trivy, Docker, and hadolint CLI commands |
| `json` | Parse vulnerability scan and inspection results |
| `re` | Analyze Dockerfile instructions |
| `pathlib` | Handle Dockerfile and image paths |

## Installation

```bash
# Trivy vulnerability scanner
curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin

# Hadolint Dockerfile linter
wget -O /usr/local/bin/hadolint https://github.com/hadolint/hadolint/releases/latest/download/hadolint-Linux-x86_64
chmod +x /usr/local/bin/hadolint

# Docker CLI (already installed in most environments)
```

## Trivy Image Scanning

### Scan Image for Vulnerabilities
```python
import subprocess
import json

def scan_image(image_name, severity="CRITICAL,HIGH"):
    cmd = [
        "trivy", "image",
        "--format", "json",
        "--severity", severity,
        "--exit-code", "0",
        image_name,
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    return json.loads(result.stdout) if result.stdout else {}
```

### Scan for Secrets in Image
```python
def scan_secrets(image_name):
    cmd = [
        "trivy", "image",
        "--format", "json",
        "--scanners", "secret",
        image_name,
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    return json.loads(result.stdout) if result.stdout else {}
```

### Scan for Misconfigurations
```python
def scan_misconfig(image_name):
    cmd = [
        "trivy", "image",
        "--format", "json",
        "--scanners", "misconfig",
        image_name,
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    return json.loads(result.stdout) if result.stdout else {}
```

## Docker Image Inspection

### Inspect Image Metadata
```python
def inspect_image(image_name):
    cmd = ["docker", "inspect", image_name]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    data = json.loads(result.stdout)[0]
    config = data.get("Config", {})
    return {
        "image": image_name,
        "user": config.get("User", "root"),
        "exposed_ports": list(config.get("ExposedPorts", {}).keys()),
        "env_vars": config.get("Env", []),
        "entrypoint": config.get("Entrypoint"),
        "cmd": config.get("Cmd"),
        "labels": config.get("Labels", {}),
        "layers": len(data.get("RootFS", {}).get("Layers", [])),
        "size_mb": round(data.get("Size", 0) / 1048576, 1),
    }
```

### Check for Root User
```python
def check_non_root(image_name):
    inspection = inspect_image(image_name)
    user = inspection["user"]
    return {
        "image": image_name,
        "runs_as_root": user in ("", "root", "0"),
        "user": user or "root (default)",
        "severity": "high" if user in ("", "root", "0") else "pass",
    }
```

## Hadolint Dockerfile Linting

```python
def lint_dockerfile(dockerfile_path):
    cmd = [
        "hadolint",
        "--format", "json",
        str(dockerfile_path),
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    findings = json.loads(result.stdout) if result.stdout else []
    return [
        {
            "line": f["line"],
            "code": f["code"],
            "level": f["level"],
            "message": f["message"],
        }
        for f in findings
    ]
```

## Hardening Checks

### Common Dockerfile Issues
```python
def audit_dockerfile(dockerfile_path):
    findings = []
    with open(dockerfile_path) as f:
        lines = f.readlines()

    has_user = False
    has_healthcheck = False

    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.startswith("USER") and stripped.split()[-1] not in ("root", "0"):
            has_user = True
        if stripped.startswith("HEALTHCHECK"):
            has_healthcheck = True
        if stripped.startswith("FROM") and ":latest" in stripped:
            findings.append({
                "line": i, "severity": "medium",
                "issue": "Using :latest tag — pin specific version",
            })
        if "ADD" in stripped and ("http://" in stripped or "https://" in stripped):
            findings.append({
                "line": i, "severity": "high",
                "issue": "ADD with remote URL — use COPY + curl for verification",
            })

    if not has_user:
        findings.append({"line": 0, "severity": "high", "issue": "No USER instruction — runs as root"})
    if not has_healthcheck:
        findings.append({"line": 0, "severity": "low", "issue": "No HEALTHCHECK instruction"})

    return findings
```

## Output Format

```json
{
  "image": "myapp:v1.2.3",
  "vulnerabilities": {
    "critical": 2,
    "high": 8,
    "medium": 15,
    "low": 23
  },
  "runs_as_root": false,
  "size_mb": 142.5,
  "layers": 12,
  "dockerfile_issues": 3,
  "secrets_found": 0,
  "findings": [
    {
      "type": "vulnerability",
      "package": "openssl",
      "installed": "3.0.2",
      "fixed": "3.0.13",
      "severity": "CRITICAL",
      "cve": "CVE-2024-0727"
    }
  ]
}
```
