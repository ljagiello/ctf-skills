# API Reference: Semgrep Custom SAST Rules

## Libraries Used

| Library | Purpose |
|---------|---------|
| `subprocess` | Execute semgrep CLI scans |
| `json` | Parse semgrep JSON output |
| `yaml` | Read and write custom Semgrep rule files |
| `pathlib` | Handle source code and rule file paths |

## Installation

```bash
# Python package
pip install semgrep

# Homebrew (macOS)
brew install semgrep

# Docker
docker pull semgrep/semgrep:latest
```

## CLI Reference

### Core Commands

```bash
# Scan with auto-detected rules
semgrep scan --config auto --json --output results.json /path/to/code

# Scan with specific rulesets from Semgrep Registry
semgrep scan --config p/python --config p/owasp-top-ten /path/to/code

# Scan with a custom rule file
semgrep scan --config my-rules.yaml /path/to/code

# Scan with multiple configs
semgrep scan --config p/security-audit --config ./custom-rules/ /path/to/code
```

### Key CLI Flags

| Flag | Description |
|------|-------------|
| `--config`, `-c` | Rule source: registry key, YAML file, or directory |
| `--json` | Output results in JSON format |
| `--sarif` | Output in SARIF format (for CI/CD integration) |
| `--output`, `-o` | Write results to file |
| `--severity` | Filter by severity: `INFO`, `WARNING`, `ERROR` |
| `--include` | Only scan files matching glob pattern |
| `--exclude` | Skip files matching glob pattern |
| `--lang` | Restrict scan to specific language |
| `--max-target-bytes` | Skip files larger than N bytes |
| `--timeout` | Per-rule timeout in seconds (default: 5) |
| `--jobs`, `-j` | Number of parallel jobs |
| `--verbose`, `-v` | Show detailed scan progress |
| `--metrics off` | Disable anonymous metrics |

## Custom Rule Syntax

### Basic Pattern Rule
```yaml
rules:
  - id: hardcoded-password
    pattern: password = "..."
    message: "Hardcoded password detected — use environment variables"
    languages: [python]
    severity: ERROR
    metadata:
      cwe: ["CWE-798: Use of Hard-coded Credentials"]
      owasp: ["A07:2021 - Identification and Authentication Failures"]
```

### Pattern Operators
```yaml
rules:
  - id: sql-injection-format-string
    patterns:
      - pattern: |
          cursor.execute($QUERY % ...)
      - pattern-not: |
          cursor.execute("..." % ())
    message: "SQL injection via string formatting — use parameterized queries"
    languages: [python]
    severity: ERROR

  - id: unsafe-deserialization
    pattern-either:
      - pattern: pickle.loads(...)
      - pattern: pickle.load(...)
      - pattern: yaml.load(..., Loader=yaml.Loader)
      - pattern: yaml.unsafe_load(...)
    message: "Unsafe deserialization — may allow remote code execution"
    languages: [python]
    severity: ERROR

  - id: missing-timeout-requests
    patterns:
      - pattern: requests.$METHOD(...)
      - pattern-not: requests.$METHOD(..., timeout=..., ...)
    message: "HTTP request without timeout — may hang indefinitely"
    languages: [python]
    severity: WARNING
```

### Metavariable Patterns
```yaml
rules:
  - id: eval-user-input
    patterns:
      - pattern: |
          $INPUT = request.$METHOD(...)
          ...
          eval($INPUT)
    message: "User input passed to eval() — command injection risk"
    languages: [python]
    severity: ERROR
```

## Python Integration

```python
import subprocess
import json

def run_semgrep(target_path, config="auto", severity=None):
    cmd = [
        "semgrep", "scan",
        "--config", config,
        "--json",
        "--metrics", "off",
        str(target_path),
    ]
    if severity:
        cmd.extend(["--severity", severity])

    result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
    output = json.loads(result.stdout)
    return output.get("results", [])

def summarize_findings(results):
    by_severity = {"ERROR": [], "WARNING": [], "INFO": []}
    for r in results:
        sev = r.get("extra", {}).get("severity", "INFO")
        by_severity[sev].append({
            "rule": r["check_id"],
            "file": r["path"],
            "line": r["start"]["line"],
            "message": r["extra"]["message"],
        })
    return by_severity
```

## Semgrep Registry Rule Packs

| Pack | Description |
|------|-------------|
| `p/python` | Python-specific security and correctness rules |
| `p/javascript` | JavaScript/TypeScript rules |
| `p/owasp-top-ten` | OWASP Top 10 vulnerability patterns |
| `p/security-audit` | Broad security audit rules across languages |
| `p/secrets` | Secret and credential detection |
| `p/ci` | Rules optimized for CI/CD pipelines |
| `p/docker` | Dockerfile security best practices |
| `p/terraform` | Terraform IaC security rules |

## Output Format

```json
{
  "results": [
    {
      "check_id": "python.lang.security.audit.eval-detected",
      "path": "app/views.py",
      "start": {"line": 42, "col": 5},
      "end": {"line": 42, "col": 28},
      "extra": {
        "message": "Detected eval() usage — avoid with untrusted input",
        "severity": "ERROR",
        "metadata": {
          "cwe": ["CWE-95"],
          "owasp": ["A03:2021 - Injection"]
        }
      }
    }
  ],
  "errors": [],
  "stats": {
    "findings": 3,
    "errors": 0,
    "total_time": 2.45
  }
}
```
