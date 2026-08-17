# API Reference: Gitleaks Secret Scanning

## Libraries Used

| Library | Purpose |
|---------|---------|
| `subprocess` | Execute gitleaks CLI commands |
| `json` | Parse gitleaks JSON report output |
| `pathlib` | Handle repository and report file paths |
| `os` | Read `GITLEAKS_CONFIG` environment variable |

## Installation

```bash
# Install gitleaks binary
# macOS
brew install gitleaks

# Linux
curl -sSfL https://github.com/gitleaks/gitleaks/releases/latest/download/gitleaks_linux_x64 -o gitleaks
chmod +x gitleaks && sudo mv gitleaks /usr/local/bin/

# Docker
docker pull ghcr.io/gitleaks/gitleaks:latest
```

## CLI Commands

### Scan a Git Repository
```bash
gitleaks git --source=/path/to/repo --report-format=json --report-path=results.json
```

### Scan a Directory (Non-Git)
```bash
gitleaks dir --source=/path/to/code --report-format=json --report-path=results.json
```

### Scan from stdin
```bash
echo "aws_secret_access_key=AKIAIOSFODNN7EXAMPLE" | gitleaks stdin
```

### Key CLI Flags

| Flag | Description |
|------|-------------|
| `--source` | Path to repository or directory to scan |
| `--config`, `-c` | Path to custom gitleaks.toml config |
| `--report-format`, `-f` | Output format: `json`, `csv`, `junit`, `sarif` |
| `--report-path`, `-r` | Path to write the report file |
| `--baseline-path` | Ignore known findings from baseline file |
| `--exit-code` | Exit code when leaks found (default: 1) |
| `--redact` | Redact secrets in output (percent: 0-100) |
| `--verbose`, `-v` | Show verbose scan output |
| `--no-git` | Treat source as plain directory |
| `--log-level` | Log level: trace, debug, info, warn, error |
| `--max-target-megabytes` | Skip files larger than this size |

## Custom Configuration (.gitleaks.toml)

```toml
title = "Custom Gitleaks Config"

[extend]
useDefault = true  # Extend the default ruleset

[[rules]]
id = "custom-internal-token"
description = "Internal API token pattern"
regex = '''(?i)internal[_-]?token\s*[:=]\s*['"]?([a-zA-Z0-9]{32,})'''
tags = ["internal", "token"]
keywords = ["internal_token", "internal-token"]

[[rules]]
id = "custom-db-password"
description = "Database password in config"
regex = '''(?i)(db|database|mysql|postgres)[_-]?pass(word)?\s*[:=]\s*['"]?[^\s'"]{8,}'''
tags = ["database", "password"]

[rules.allowlist]
paths = ['''test/.*''', '''mock/.*''']
regexTarget = "line"
regexes = ['''(?i)example|placeholder|changeme|test''']

[[allowlist.paths]]
regex = '''vendor/.*'''

[[allowlist.commits]]
sha = "abc123def456"
```

## Python Integration

### Run Gitleaks and Parse Results
```python
import subprocess
import json
from pathlib import Path

def scan_repository(repo_path, config_path=None):
    cmd = [
        "gitleaks", "git",
        "--source", str(repo_path),
        "--report-format", "json",
        "--report-path", "/tmp/gitleaks-report.json",
        "--exit-code", "0",
    ]
    if config_path:
        cmd.extend(["--config", str(config_path)])

    result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

    report_path = Path("/tmp/gitleaks-report.json")
    if report_path.exists():
        with open(report_path) as f:
            findings = json.load(f)
        return findings
    return []
```

### Categorize Findings by Severity
```python
HIGH_SEVERITY_RULES = {
    "aws-access-key", "aws-secret-key", "gcp-api-key",
    "github-pat", "private-key", "generic-api-key",
}

def categorize_findings(findings):
    high, medium, low = [], [], []
    for f in findings:
        rule = f.get("RuleID", "")
        if rule in HIGH_SEVERITY_RULES:
            high.append(f)
        elif "password" in rule or "token" in rule:
            medium.append(f)
        else:
            low.append(f)
    return {"high": high, "medium": medium, "low": low}
```

## GitHub Actions Integration

```yaml
name: Gitleaks Secret Scan
on: [push, pull_request]
jobs:
  gitleaks:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - uses: gitleaks/gitleaks-action@v2
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

## Output Format

```json
[
  {
    "Description": "Detected a Generic API Key",
    "StartLine": 42,
    "EndLine": 42,
    "StartColumn": 15,
    "EndColumn": 55,
    "Match": "REDACTED",
    "Secret": "REDACTED",
    "File": "config/settings.py",
    "Commit": "a1b2c3d4e5f6",
    "Author": "developer@example.com",
    "Date": "2025-01-15T10:30:00Z",
    "RuleID": "generic-api-key",
    "Tags": ["api", "key"],
    "Fingerprint": "a1b2c3d4:config/settings.py:generic-api-key:42"
  }
]
```
