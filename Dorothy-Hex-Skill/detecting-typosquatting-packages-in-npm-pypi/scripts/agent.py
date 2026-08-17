#!/usr/bin/env python3
"""Typosquatting Detection Agent - Detects typosquatting packages in npm and PyPI
registries using Levenshtein distance analysis, publish date heuristics, and
download count anomalies."""

import json
import logging
import argparse
import re
import time
from datetime import datetime, timezone
from pathlib import Path

import requests

try:
    from Levenshtein import distance as levenshtein_distance
except ImportError:
    # Fallback pure-Python Levenshtein implementation
    def levenshtein_distance(s1, s2):
        if len(s1) < len(s2):
            return levenshtein_distance(s2, s1)
        if len(s2) == 0:
            return len(s1)
        prev_row = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            curr_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = prev_row[j + 1] + 1
                deletions = curr_row[j] + 1
                substitutions = prev_row[j] + (c1 != c2)
                curr_row.append(min(insertions, deletions, substitutions))
            prev_row = curr_row
        return prev_row[-1]


logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

PYPI_API = "https://pypi.org/pypi/{}/json"
NPM_API = "https://registry.npmjs.org/{}"
NPM_DOWNLOADS_API = "https://api.npmjs.org/downloads/point/last-week/{}"
PYPISTATS_API = "https://pypistats.org/api/packages/{}/recent"

SESSION = requests.Session()
SESSION.headers.update({"Accept": "application/json", "User-Agent": "typosquat-detector/1.0"})


def normalize_pypi_name(name):
    """Normalize a PyPI package name per PEP 503."""
    return re.sub(r"[-_.]+", "-", name).lower()


def generate_typosquat_candidates(name):
    """Generate potential typosquat variants of a package name.

    Produces candidates via character omission, transposition, insertion,
    substitution (keyboard-adjacent), and separator manipulation.
    """
    candidates = set()
    lower_name = name.lower()

    # Character omission: remove each character one at a time
    for i in range(len(lower_name)):
        candidate = lower_name[:i] + lower_name[i + 1:]
        if candidate and candidate != lower_name:
            candidates.add(candidate)

    # Character transposition: swap adjacent characters
    for i in range(len(lower_name) - 1):
        chars = list(lower_name)
        chars[i], chars[i + 1] = chars[i + 1], chars[i]
        candidate = "".join(chars)
        if candidate != lower_name:
            candidates.add(candidate)

    # Character duplication: double each character
    for i in range(len(lower_name)):
        candidate = lower_name[:i] + lower_name[i] + lower_name[i:]
        if candidate != lower_name:
            candidates.add(candidate)

    # Keyboard-adjacent substitution (QWERTY layout)
    qwerty_neighbors = {
        "q": "wa", "w": "qeas", "e": "wrds", "r": "etfs", "t": "ryg",
        "y": "tuh", "u": "yij", "i": "uok", "o": "ipl", "p": "ol",
        "a": "qwsz", "s": "wedxza", "d": "erfcxs", "f": "rtgvcd",
        "g": "tyhbvf", "h": "yujng", "j": "uikmh", "k": "ioljm",
        "l": "opk", "z": "asx", "x": "zsdc", "c": "xdfv", "v": "cfgb",
        "b": "vghn", "n": "bhjm", "m": "njk",
    }
    for i, ch in enumerate(lower_name):
        for neighbor in qwerty_neighbors.get(ch, ""):
            candidate = lower_name[:i] + neighbor + lower_name[i + 1:]
            if candidate != lower_name:
                candidates.add(candidate)

    # Separator manipulation for hyphenated/underscored names
    if "-" in lower_name or "_" in lower_name:
        candidates.add(lower_name.replace("-", "").replace("_", ""))
        candidates.add(lower_name.replace("-", "_"))
        candidates.add(lower_name.replace("_", "-"))
        candidates.add(lower_name.replace("-", "--"))

    # Common prefix/suffix combosquatting
    for affix in ["python-", "py-", "-python", "-py", "-lib", "-sdk", "2", "3"]:
        if affix.startswith("-"):
            candidates.add(lower_name + affix)
        else:
            candidates.add(affix + lower_name)

    # Remove the original name if present
    candidates.discard(lower_name)
    candidates.discard(name)

    return sorted(candidates)


def query_pypi_package(name, delay=0.5):
    """Query the PyPI JSON API for package metadata.

    Returns parsed metadata or None if the package does not exist.
    """
    url = PYPI_API.format(name)
    try:
        time.sleep(delay)
        resp = SESSION.get(url, timeout=15)
        if resp.status_code == 404:
            return None
        resp.raise_for_status()
        data = resp.json()
        info = data.get("info", {})
        releases = data.get("releases", {})

        # Find first and latest upload times
        upload_times = []
        for version_files in releases.values():
            for f in version_files:
                if f.get("upload_time_iso_8601"):
                    upload_times.append(f["upload_time_iso_8601"])

        first_upload = min(upload_times) if upload_times else None
        latest_upload = max(upload_times) if upload_times else None

        return {
            "registry": "pypi",
            "name": info.get("name", name),
            "version": info.get("version"),
            "author": info.get("author"),
            "author_email": info.get("author_email"),
            "summary": info.get("summary"),
            "home_page": info.get("home_page"),
            "project_url": info.get("project_url"),
            "requires_python": info.get("requires_python"),
            "license": info.get("license"),
            "version_count": len(releases),
            "first_upload": first_upload,
            "latest_upload": latest_upload,
            "exists": True,
        }
    except requests.RequestException as e:
        logger.warning("PyPI query failed for %s: %s", name, e)
        return None


def query_npm_package(name, delay=0.5):
    """Query the npm registry API for package metadata.

    Returns parsed metadata or None if the package does not exist.
    """
    url = NPM_API.format(name)
    try:
        time.sleep(delay)
        resp = SESSION.get(url, timeout=15)
        if resp.status_code == 404:
            return None
        if resp.status_code == 429:
            logger.warning("npm rate limited, waiting 10 seconds")
            time.sleep(10)
            resp = SESSION.get(url, timeout=15)
        resp.raise_for_status()
        data = resp.json()
        time_info = data.get("time", {})
        maintainers = data.get("maintainers", [])

        return {
            "registry": "npm",
            "name": data.get("name", name),
            "description": data.get("description"),
            "dist_tags_latest": data.get("dist-tags", {}).get("latest"),
            "created": time_info.get("created"),
            "modified": time_info.get("modified"),
            "maintainers": [m.get("name") for m in maintainers],
            "version_count": len(data.get("versions", {})),
            "license": data.get("license"),
            "homepage": data.get("homepage"),
            "repository": data.get("repository", {}).get("url") if isinstance(data.get("repository"), dict) else data.get("repository"),
            "exists": True,
        }
    except requests.RequestException as e:
        logger.warning("npm query failed for %s: %s", name, e)
        return None


def get_pypi_downloads(name):
    """Get recent download stats for a PyPI package from pypistats.org."""
    url = PYPISTATS_API.format(name)
    try:
        resp = SESSION.get(url, timeout=10)
        if resp.status_code != 200:
            return None
        data = resp.json().get("data", {})
        return data.get("last_week", 0)
    except requests.RequestException:
        return None


def get_npm_downloads(name):
    """Get last-week download count for an npm package."""
    url = NPM_DOWNLOADS_API.format(name)
    try:
        resp = SESSION.get(url, timeout=10)
        if resp.status_code != 200:
            return None
        return resp.json().get("downloads", 0)
    except requests.RequestException:
        return None


def compute_suspicion_score(candidate_meta, target_meta, target_name, registry):
    """Compute a weighted suspicion score for a candidate typosquat package.

    Signals:
    - Levenshtein distance (1 = 40pts, 2 = 25pts, 3 = 10pts)
    - Publish recency: created within 90 days = 15pts
    - Download ratio: candidate/target < 0.001 = 15pts
    - Different author/maintainer = 10pts
    - Low version count (<=2) = 5pts
    - No repository URL = 5pts
    """
    score = 0
    signals = {}
    candidate_name = candidate_meta.get("name", "")

    # Levenshtein distance
    if registry == "pypi":
        dist = levenshtein_distance(
            normalize_pypi_name(candidate_name),
            normalize_pypi_name(target_name),
        )
    else:
        dist = levenshtein_distance(candidate_name.lower(), target_name.lower())

    signals["levenshtein_distance"] = dist
    if dist == 1:
        score += 40
    elif dist == 2:
        score += 25
    elif dist == 3:
        score += 10

    # Publish recency
    now = datetime.now(timezone.utc)
    first_publish = candidate_meta.get("first_upload") or candidate_meta.get("created")
    if first_publish:
        try:
            if isinstance(first_publish, str):
                first_dt = datetime.fromisoformat(first_publish.replace("Z", "+00:00"))
            else:
                first_dt = first_publish
            days_old = (now - first_dt).days
            signals["days_since_first_publish"] = days_old
            if days_old <= 90:
                score += 15
            elif days_old <= 180:
                score += 8
        except (ValueError, TypeError):
            pass

    # Download disparity
    if registry == "pypi":
        candidate_dl = get_pypi_downloads(candidate_name)
        target_dl = get_pypi_downloads(target_name)
    else:
        candidate_dl = get_npm_downloads(candidate_name)
        target_dl = get_npm_downloads(target_name)

    signals["candidate_downloads_weekly"] = candidate_dl
    signals["target_downloads_weekly"] = target_dl
    if candidate_dl is not None and target_dl and target_dl > 0:
        ratio = candidate_dl / target_dl
        signals["download_ratio"] = round(ratio, 6)
        if ratio < 0.001:
            score += 15
        elif ratio < 0.01:
            score += 8

    # Author comparison
    if registry == "pypi":
        candidate_author = (candidate_meta.get("author") or "").lower().strip()
        target_author = (target_meta.get("author") or "").lower().strip()
    else:
        candidate_author = set(m.lower() for m in (candidate_meta.get("maintainers") or []))
        target_author = set(m.lower() for m in (target_meta.get("maintainers") or []))

    if candidate_author and target_author and candidate_author != target_author:
        score += 10
        signals["different_author"] = True
    else:
        signals["different_author"] = False

    # Version count
    version_count = candidate_meta.get("version_count", 0)
    signals["version_count"] = version_count
    if version_count <= 2:
        score += 5

    # Repository URL presence
    repo = candidate_meta.get("home_page") or candidate_meta.get("homepage") or candidate_meta.get("repository")
    signals["has_repository"] = bool(repo)
    if not repo:
        score += 5

    signals["total_score"] = score
    return score, signals


def classify_risk(score):
    """Classify risk level based on composite score."""
    if score >= 70:
        return "HIGH"
    elif score >= 40:
        return "MEDIUM"
    else:
        return "LOW"


def scan_package(target_name, registry="pypi", max_candidates=None):
    """Scan for typosquat candidates of a target package.

    Generates candidates, checks which exist in the registry, scores them,
    and returns ranked results.
    """
    logger.info("Scanning for typosquats of '%s' on %s", target_name, registry)

    # Fetch target package metadata
    if registry == "pypi":
        target_meta = query_pypi_package(target_name, delay=0.2)
    else:
        target_meta = query_npm_package(target_name, delay=0.2)

    if not target_meta:
        logger.warning("Target package '%s' not found on %s", target_name, registry)
        return {"target": target_name, "registry": registry, "error": "Target package not found"}

    # Generate candidates
    candidates = generate_typosquat_candidates(target_name)
    if max_candidates:
        candidates = candidates[:max_candidates]
    logger.info("Generated %d typosquat candidates for '%s'", len(candidates), target_name)

    # Query registry for each candidate
    results = []
    for i, candidate in enumerate(candidates):
        if registry == "pypi":
            meta = query_pypi_package(candidate, delay=0.3)
        else:
            meta = query_npm_package(candidate, delay=0.3)

        if meta and meta.get("exists"):
            score, signals = compute_suspicion_score(
                meta, target_meta, target_name, registry
            )
            risk = classify_risk(score)
            results.append({
                "candidate": candidate,
                "target": target_name,
                "registry": registry,
                "score": score,
                "risk": risk,
                "signals": signals,
                "metadata": meta,
            })
            logger.info(
                "  [%s] %s (score=%d, lev=%d)",
                risk, candidate, score, signals.get("levenshtein_distance", -1),
            )

        if (i + 1) % 50 == 0:
            logger.info("  Progress: %d/%d candidates checked", i + 1, len(candidates))

    # Sort by score descending
    results.sort(key=lambda r: r["score"], reverse=True)

    return {
        "target": target_name,
        "registry": registry,
        "target_metadata": target_meta,
        "candidates_generated": len(candidates),
        "candidates_found": len(results),
        "results": results,
    }


def scan_dependency_file(filepath, registry="pypi", max_candidates_per_pkg=None):
    """Scan all dependencies in a requirements file or package.json."""
    filepath = Path(filepath)
    if not filepath.exists():
        return {"error": f"File not found: {filepath}"}

    content = filepath.read_text()
    packages = []

    if filepath.name in ("requirements.txt", "requirements.in"):
        for line in content.splitlines():
            line = line.strip()
            if line and not line.startswith("#") and not line.startswith("-"):
                pkg = re.split(r"[><=!~\[]", line)[0].strip()
                if pkg:
                    packages.append(pkg)
    elif filepath.name == "package.json":
        try:
            pkg_json = json.loads(content)
            for dep_key in ("dependencies", "devDependencies", "peerDependencies"):
                packages.extend(pkg_json.get(dep_key, {}).keys())
        except json.JSONDecodeError as e:
            return {"error": f"Invalid JSON: {e}"}
    elif filepath.name in ("Pipfile",):
        for line in content.splitlines():
            line = line.strip()
            if "=" in line and not line.startswith("[") and not line.startswith("#"):
                pkg = line.split("=")[0].strip().strip('"')
                if pkg and not pkg.startswith("["):
                    packages.append(pkg)
    else:
        # Generic: one package per line
        for line in content.splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                packages.append(line.split()[0])

    packages = list(dict.fromkeys(packages))  # deduplicate preserving order
    logger.info("Found %d packages in %s", len(packages), filepath)

    all_results = {
        "file": str(filepath),
        "registry": registry,
        "packages_scanned": len(packages),
        "scan_results": [],
        "summary": {"high": 0, "medium": 0, "low": 0},
    }

    for pkg in packages:
        result = scan_package(pkg, registry, max_candidates_per_pkg)
        all_results["scan_results"].append(result)
        for r in result.get("results", []):
            risk = r.get("risk", "LOW").lower()
            all_results["summary"][risk] = all_results["summary"].get(risk, 0) + 1

    return all_results


def generate_report(data, output_path):
    """Write scan results to a JSON report file."""
    report = {
        "report_generated": datetime.now(timezone.utc).isoformat(),
        **data,
    }
    with open(output_path, "w") as f:
        json.dump(report, f, indent=2, default=str)
    logger.info("Report written to %s", output_path)


def main():
    parser = argparse.ArgumentParser(
        description="Typosquatting Detection Agent for npm and PyPI"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # scan single package
    scan_p = sub.add_parser("scan", help="Scan for typosquats of a single package")
    scan_p.add_argument("package", help="Target package name to scan for typosquats")
    scan_p.add_argument("--registry", choices=["pypi", "npm"], default="pypi",
                        help="Package registry to scan (default: pypi)")
    scan_p.add_argument("--max-candidates", type=int, help="Limit candidates to check")

    # scan dependency file
    file_p = sub.add_parser("scan-file", help="Scan dependencies from a file")
    file_p.add_argument("file", help="Path to requirements.txt, package.json, etc.")
    file_p.add_argument("--registry", choices=["pypi", "npm"], default="pypi",
                        help="Package registry to scan (default: pypi)")
    file_p.add_argument("--max-candidates", type=int, help="Limit candidates per package")

    # check single candidate
    check_p = sub.add_parser("check", help="Check a specific package name against a target")
    check_p.add_argument("candidate", help="Candidate package name to check")
    check_p.add_argument("target", help="Legitimate target package name")
    check_p.add_argument("--registry", choices=["pypi", "npm"], default="pypi")

    # generate candidates only (no registry queries)
    gen_p = sub.add_parser("generate", help="Generate typosquat candidates without querying registry")
    gen_p.add_argument("package", help="Package name to generate candidates for")

    parser.add_argument("--output", default="typosquat_report.json", help="Output report path")
    args = parser.parse_args()

    result = {}

    if args.command == "scan":
        result = scan_package(args.package, args.registry, args.max_candidates)

    elif args.command == "scan-file":
        result = scan_dependency_file(args.file, args.registry, args.max_candidates)

    elif args.command == "check":
        if args.registry == "pypi":
            candidate_meta = query_pypi_package(args.candidate)
            target_meta = query_pypi_package(args.target)
        else:
            candidate_meta = query_npm_package(args.candidate)
            target_meta = query_npm_package(args.target)

        if not candidate_meta:
            result = {"candidate": args.candidate, "exists": False, "risk": "NONE"}
        elif not target_meta:
            result = {"error": f"Target package '{args.target}' not found"}
        else:
            score, signals = compute_suspicion_score(
                candidate_meta, target_meta, args.target, args.registry
            )
            result = {
                "candidate": args.candidate,
                "target": args.target,
                "registry": args.registry,
                "score": score,
                "risk": classify_risk(score),
                "signals": signals,
                "candidate_metadata": candidate_meta,
                "target_metadata": target_meta,
            }

    elif args.command == "generate":
        candidates = generate_typosquat_candidates(args.package)
        result = {
            "package": args.package,
            "candidate_count": len(candidates),
            "candidates": candidates,
        }

    print(json.dumps(result, indent=2, default=str))
    generate_report(result, args.output)


if __name__ == "__main__":
    main()
