#!/usr/bin/env python3
"""
Dependency confusion detection helper.

Scans a source tree for package manifests, extracts declared dependency names,
and checks each against the corresponding PUBLIC registry. A dependency that
resolves on the public registry while being intended as private is a
substitution candidate; a name that 404s is defensively claimable.

Supports: npm (package.json), PyPI (requirements.txt), RubyGems (Gemfile.lock).
Optionally shells out to `confused` if it is installed for cross-validation.

Authorized defensive / authorized-testing use only.
"""
import argparse
import fnmatch
import json
import re
import shutil
import subprocess
import sys
import urllib.parse
import urllib.request
from pathlib import Path

REGISTRY = {
    "npm": "https://registry.npmjs.org/{name}",
    "pip": "https://pypi.org/pypi/{name}/json",
    "rubygems": "https://rubygems.org/api/v1/gems/{name}.json",
}
MANIFEST = {"npm": "package.json", "pip": "requirements.txt", "rubygems": "Gemfile.lock"}


def http_status(url: str, timeout: int = 15) -> int:
    req = urllib.request.Request(url, headers={"User-Agent": "depconf-agent/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.getcode()
    except urllib.error.HTTPError as exc:
        return exc.code
    except Exception as exc:  # noqa: BLE001 - network errors are reported, not fatal
        print(f"[warn] lookup failed for {url}: {exc}", file=sys.stderr)
        return -1


def parse_npm(path: Path) -> list[str]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        print(f"[warn] cannot parse {path}: {exc}", file=sys.stderr)
        return []
    names: set[str] = set()
    for key in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
        names.update((data.get(key) or {}).keys())
    return sorted(names)


def parse_pip(path: Path) -> list[str]:
    names: set[str] = set()
    try:
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith(("#", "-", "git+", "http")):
                continue
            m = re.match(r"^([A-Za-z0-9._-]+)", line)
            if m:
                names.add(m.group(1))
    except OSError as exc:
        print(f"[warn] cannot read {path}: {exc}", file=sys.stderr)
    return sorted(names)


def parse_rubygems(path: Path) -> list[str]:
    names: set[str] = set()
    try:
        for line in path.read_text(encoding="utf-8").splitlines():
            m = re.match(r"^\s{4}([a-z0-9_-]+) \(", line)
            if m:
                names.add(m.group(1))
    except OSError as exc:
        print(f"[warn] cannot read {path}: {exc}", file=sys.stderr)
    return sorted(names)


PARSERS = {"npm": parse_npm, "pip": parse_pip, "rubygems": parse_rubygems}


def encode_name(eco: str, name: str) -> str:
    # npm scoped packages must URL-encode the slash
    if eco == "npm" and name.startswith("@"):
        return urllib.parse.quote(name, safe="@")
    return urllib.parse.quote(name, safe="")


def is_secure(name: str, patterns: list[str]) -> bool:
    return any(fnmatch.fnmatch(name, p) for p in patterns)


def run_confused(eco: str, manifest: Path, secure: str) -> str | None:
    if not shutil.which("confused"):
        return None
    cmd = ["confused", "-l", eco]
    if secure:
        cmd += ["-s", secure]
    cmd.append(str(manifest))
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        return out.stdout + out.stderr
    except (subprocess.SubprocessError, OSError) as exc:
        print(f"[warn] confused failed: {exc}", file=sys.stderr)
        return None


def main() -> int:
    ap = argparse.ArgumentParser(description="Dependency confusion detector")
    ap.add_argument("--path", default=".", help="Root path to scan")
    ap.add_argument("--ecosystem", choices=list(REGISTRY), required=True)
    ap.add_argument("--secure-namespaces", default="", help="Comma-separated glob patterns")
    ap.add_argument("--output", help="Write JSON report to this file")
    args = ap.parse_args()

    eco = args.ecosystem
    root = Path(args.path)
    if not root.exists():
        print(f"[error] path not found: {root}", file=sys.stderr)
        return 2
    secure = [p.strip() for p in args.secure_namespaces.split(",") if p.strip()]

    manifests = [p for p in root.rglob(MANIFEST[eco]) if "node_modules" not in p.parts]
    if not manifests:
        print(f"[info] no {MANIFEST[eco]} found under {root}")
        return 0

    findings = []
    for manifest in manifests:
        names = PARSERS[eco](manifest)
        for name in names:
            if is_secure(name, secure):
                continue
            status = http_status(REGISTRY[eco].format(name=encode_name(eco, name)))
            verdict = (
                "CLAIMABLE (404 on public registry)" if status == 404
                else "present on public registry" if status == 200
                else f"unknown (HTTP {status})"
            )
            if status != 200:
                findings.append(
                    {"manifest": str(manifest), "name": name, "status": status, "verdict": verdict}
                )
                print(f"[!] {name}  ->  {verdict}  ({manifest})")

        cf = run_confused(eco, manifest, args.secure_namespaces)
        if cf:
            print(f"--- confused output for {manifest} ---\n{cf}")

    report = {"ecosystem": eco, "root": str(root), "findings": findings}
    if args.output:
        Path(args.output).write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(f"[+] report written to {args.output}")
    print(f"[+] {len(findings)} confusion candidate(s) across {len(manifests)} manifest(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
