# API and Command Reference

## confused (visma-prodsec/confused)

Install: `go install github.com/visma-prodsec/confused@latest`

Syntax: `confused [-l LANGUAGE] [-s SECURE_NAMESPACES] [-v] MANIFEST`

| Flag | Values / Example | Description |
|------|------------------|-------------|
| `-l` | `npm` (default), `pip`, `mvn`, `composer`, `rubygems` | Selects the package ecosystem / manifest type. |
| `-s` | `'@acme/*,@acme-internal/*'` | Comma-separated known-secure namespaces; supports `*` wildcards. Suppresses false positives. |
| `-v` | (flag) | Verbose output; prints every registry lookup. |

Manifest mapping: `npm`→`package.json`, `pip`→`requirements.txt`, `mvn`→`pom.xml`, `composer`→`composer.json`, `rubygems`→`Gemfile.lock`.

## OWASP dep-scan

Install: `pip install owasp-depscan`

| Argument | Example | Description |
|----------|---------|-------------|
| `--src` | `--src $PWD` | Path to source repo (or container image). |
| `--reports-dir` | `--reports-dir ./reports` | Output directory for JSON/HTML reports. |
| `--private-ns` | `--private-ns acme,@acme` | Comma-separated private namespaces to check for confusion exposure. |
| `--risk-audit` | (flag) | Deep package risk audit (npm/pypi): takeover, typosquat, maintenance risk. |
| `-t` / `--type` | `-t nodejs` | Restrict to a project type. |

## Public registry probe endpoints (claimability check)

| Registry | Endpoint | 404 means |
|----------|----------|-----------|
| npm | `https://registry.npmjs.org/<name>` (URL-encode `/` in scopes as `%2f`) | Name unregistered / claimable. |
| PyPI | `https://pypi.org/pypi/<name>/json` | Project name free. |
| Maven Central | `https://search.maven.org/solrsearch/select?q=g:<group>+AND+a:<artifact>` (empty `response.numFound`) | Coordinate not published. |
| RubyGems | `https://rubygems.org/api/v1/gems/<name>.json` | Gem not published. |

## Remediation config keys

| Ecosystem | File | Key |
|-----------|------|-----|
| npm | `.npmrc` | `@scope:registry=<private-url>`, top-level `registry=` |
| pip | `pyproject.toml` / `pip.conf` | `index-url` (avoid `extra-index-url` for internal pkgs) |
| Maven | `~/.m2/settings.xml` | `<mirror><mirrorOf>*</mirrorOf>` |
| Composer | `composer.json` | `repositories` + `"packagist.org": false` |
