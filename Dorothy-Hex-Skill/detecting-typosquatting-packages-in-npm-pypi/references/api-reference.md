# API Reference: Typosquatting Detection Agent for npm and PyPI

## Overview

Detects typosquatting attacks in npm and PyPI package registries by generating candidate typosquat names using string manipulation techniques, querying registry APIs to check which candidates exist, and scoring each against multiple heuristic signals including Levenshtein distance, publish date recency, download count disparity, author mismatch, and version count. Produces risk-scored reports for security review.

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| requests | >=2.28 | HTTP requests to PyPI and npm registry APIs |
| python-Levenshtein | >=0.21 | Fast Levenshtein distance computation (optional; pure-Python fallback included) |
| rapidfuzz | >=3.0 | Alternative fast string distance library (optional) |

## CLI Usage

```bash
# Scan for typosquats of a single PyPI package
python agent.py scan requests --registry pypi

# Scan for typosquats of an npm package
python agent.py scan express --registry npm

# Scan with limited candidate count
python agent.py scan numpy --registry pypi --max-candidates 50

# Scan all dependencies in a requirements file
python agent.py scan-file requirements.txt --registry pypi

# Scan all dependencies in a package.json
python agent.py scan-file package.json --registry npm

# Check a specific candidate against a target
python agent.py check reqeusts requests --registry pypi

# Generate typosquat candidates without querying registries
python agent.py generate requests

# Custom output path
python agent.py scan flask --registry pypi --output flask_typosquat_report.json
```

## Arguments

| Argument | Required | Description |
|----------|----------|-------------|
| `command` | Yes | Subcommand: `scan`, `scan-file`, `check`, `generate` |
| `package` | For scan/generate | Target package name to analyze |
| `file` | For scan-file | Path to requirements.txt, package.json, or similar |
| `candidate` | For check | Candidate package name to evaluate |
| `target` | For check | Legitimate target package name to compare against |
| `--registry` | No | Registry to scan: `pypi` or `npm` (default: `pypi`) |
| `--max-candidates` | No | Maximum number of candidates to check per package |
| `--output` | No | Output report path (default: `typosquat_report.json`) |

## Key Functions

### `generate_typosquat_candidates(name)`
Generates potential typosquat variants using character omission, transposition, duplication, QWERTY keyboard-adjacent substitution, separator manipulation, and common prefix/suffix combosquatting. Returns a sorted list of unique candidate strings.

### `query_pypi_package(name, delay)`
Queries `GET https://pypi.org/pypi/<name>/json` and parses name, version, author, summary, version count, and first/latest upload timestamps from the response. Returns `None` for non-existent packages (HTTP 404).

### `query_npm_package(name, delay)`
Queries `GET https://registry.npmjs.org/<name>` and parses name, description, maintainers, version count, created/modified timestamps, license, and repository URL. Handles HTTP 429 rate limiting with exponential backoff.

### `get_pypi_downloads(name)`
Queries `https://pypistats.org/api/packages/<name>/recent` to retrieve last-week download count for download disparity analysis.

### `get_npm_downloads(name)`
Queries `https://api.npmjs.org/downloads/point/last-week/<name>` to retrieve last-week download count.

### `compute_suspicion_score(candidate_meta, target_meta, target_name, registry)`
Computes a weighted suspicion score (0-100) combining six signals: Levenshtein distance (up to 40pts), publish recency (up to 15pts), download ratio (up to 15pts), different author (10pts), low version count (5pts), and missing repository URL (5pts). Returns the score and a signal breakdown dictionary.

### `classify_risk(score)`
Maps composite score to risk level: HIGH (>=70), MEDIUM (40-69), LOW (<40).

### `scan_package(target_name, registry, max_candidates)`
End-to-end scan: fetches target metadata, generates candidates, queries registry for each, scores existing candidates, and returns ranked results sorted by descending score.

### `scan_dependency_file(filepath, registry, max_candidates_per_pkg)`
Parses a dependency file (requirements.txt, package.json, Pipfile), extracts package names, and runs `scan_package` for each. Returns aggregated results with high/medium/low summary counts.

### `normalize_pypi_name(name)`
Normalizes PyPI package names per PEP 503: replaces hyphens, underscores, and periods with a single hyphen and lowercases the result.

## Registry API Endpoints Used

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `https://pypi.org/pypi/<name>/json` | GET | PyPI package metadata (info, releases, URLs) |
| `https://registry.npmjs.org/<name>` | GET | npm package metadata (versions, time, maintainers) |
| `https://pypistats.org/api/packages/<name>/recent` | GET | PyPI download statistics |
| `https://api.npmjs.org/downloads/point/last-week/<name>` | GET | npm download statistics |

## Scoring Weights

| Signal | Condition | Points |
|--------|-----------|--------|
| Levenshtein distance | Distance = 1 | 40 |
| Levenshtein distance | Distance = 2 | 25 |
| Levenshtein distance | Distance = 3 | 10 |
| Publish recency | Created <= 90 days ago | 15 |
| Publish recency | Created <= 180 days ago | 8 |
| Download ratio | candidate/target < 0.001 | 15 |
| Download ratio | candidate/target < 0.01 | 8 |
| Author mismatch | Different author/maintainer | 10 |
| Version count | <= 2 versions | 5 |
| Repository URL | Missing | 5 |
