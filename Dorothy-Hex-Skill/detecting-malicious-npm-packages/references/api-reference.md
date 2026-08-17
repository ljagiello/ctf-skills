# API and Command Reference

## GuardDog (DataDog/guarddog)

Install: `pip install guarddog`  |  Docker: `ghcr.io/datadog/guarddog`

### Subcommands
| Command | Description |
|---------|-------------|
| `guarddog npm scan <pkg>` | Scan latest version from registry. |
| `guarddog npm scan <pkg> --version X.Y.Z` | Scan a specific version. |
| `guarddog npm scan <path.tgz \| dir>` | Scan a local tarball or extracted directory. |
| `guarddog npm verify <package.json>` | Scan every dependency in a manifest. |
| `guarddog pypi scan <pkg>` | Same for PyPI. |
| `guarddog go scan <module>` / `guarddog go verify go.mod` | Go modules. |
| `guarddog rubygems scan <gem>` | RubyGems. |

### Common flags
| Flag | Description |
|------|-------------|
| `--output-format=json` | Machine-readable JSON. |
| `--output-format=sarif` | SARIF for GitHub code scanning. |
| `--rules <rule>` (repeatable) | Run only the named rule(s). |
| `--exclude-rules <rule>` | Exclude the named rule(s). |
| `--log-level debug` | Verbose diagnostics. |

### Key npm heuristics
| Rule | Detects |
|------|---------|
| `npm-install-script` | preinstall/install/postinstall lifecycle scripts. |
| `npm-serialize-environment` | Exfiltration of environment variables. |
| `npm-exec-base64` | eval of base64-decoded payloads. |
| `npm-silent-process-execution` | Silent child-process execution. |
| `npm-obfuscation` | Common obfuscation patterns. |
| `shady-links` | Suspicious URLs in code. |
| `typosquatting` | Name similar to a popular package. |
| `potentially_compromised_email_domain` | Maintainer email on a lapsed domain. |

## OSV-Scanner

| Command | Description |
|---------|-------------|
| `osv-scanner --lockfile=package-lock.json` | Match pinned versions to OSV advisories incl. `MAL-` malicious entries. |
| `osv-scanner -r <dir>` | Recursively scan a directory. |
| `osv-scanner --format json` | JSON output. |

## npm acquisition (no execution)

| Command | Description |
|---------|-------------|
| `npm pack <pkg>@<ver>` | Download tarball without installing. |
| `npm view <pkg>@<ver> dist.tarball` | Print the tarball URL. |
| `npm install --ignore-scripts` | Install while skipping lifecycle scripts. |
| `jq '.scripts' package/package.json` | List lifecycle hooks. |
