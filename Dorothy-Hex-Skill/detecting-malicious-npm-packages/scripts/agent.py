#!/usr/bin/env python3
"""
Malicious npm package triage helper.

Orchestrates GuardDog static scanning, lifecycle-script inspection, and IOC
extraction for a single npm package (by name@version) or a local tarball, and
emits a structured verdict report.

WARNING: download with scripts disabled and run only in an isolated, disposable
environment with no production credentials. Defensive / authorized use only.
"""
import argparse
import json
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
from pathlib import Path

URL_RE = re.compile(r"https?://[A-Za-z0-9./?=_%:&#-]+")
SUSPECT_RE = re.compile(
    r"child_process|\bexec\s*\(|\bspawn\b|\beval\s*\(|Buffer\.from\([^)]*base64|process\.env",
    re.IGNORECASE,
)
HIGH_SIGNAL_RULES = [
    "npm-install-script",
    "npm-serialize-environment",
    "npm-exec-base64",
    "npm-silent-process-execution",
    "npm-obfuscation",
    "shady-links",
    "typosquatting",
]


def run(cmd: list[str], timeout: int = 600) -> tuple[int, str, str]:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout, p.stderr
    except FileNotFoundError:
        return 127, "", f"command not found: {cmd[0]}"
    except subprocess.SubprocessError as exc:
        return 1, "", f"subprocess error: {exc}"


def guarddog_scan(target: str, version: str | None) -> dict:
    if not shutil.which("guarddog"):
        return {"error": "guarddog not installed (pip install guarddog)"}
    cmd = ["guarddog", "npm", "scan", target, "--output-format=json"]
    if version:
        cmd += ["--version", version]
    for rule in HIGH_SIGNAL_RULES:
        cmd += ["--rules", rule]
    rc, out, err = run(cmd)
    try:
        return {"returncode": rc, "result": json.loads(out)} if out.strip() else {"returncode": rc, "stderr": err}
    except json.JSONDecodeError:
        return {"returncode": rc, "raw": out, "stderr": err}


def download_tarball(name: str, version: str | None, dest: Path) -> Path | None:
    spec = f"{name}@{version}" if version else name
    rc, out, err = run(["npm", "view", spec, "dist.tarball"])
    if rc != 0 or not out.strip():
        print(f"[warn] could not resolve tarball for {spec}: {err}", file=sys.stderr)
        return None
    url = out.strip().splitlines()[-1]
    tgz = dest / "package.tgz"
    try:
        urllib.request.urlretrieve(url, tgz)  # noqa: S310 - registry URL from npm
        return tgz
    except Exception as exc:  # noqa: BLE001
        print(f"[warn] download failed: {exc}", file=sys.stderr)
        return None


def inspect_tarball(tgz: Path, workdir: Path) -> dict:
    findings = {"lifecycle_scripts": {}, "suspicious_lines": [], "urls": []}
    extract = workdir / "package"
    try:
        with tarfile.open(tgz, "r:gz") as tf:
            members = [m for m in tf.getmembers() if not m.name.startswith(("/", ".."))]
            tf.extractall(extract, members=members)  # noqa: S202 - path-checked members
    except (tarfile.TarError, OSError) as exc:
        findings["error"] = f"extract failed: {exc}"
        return findings

    pkg_json = next(extract.rglob("package.json"), None)
    if pkg_json:
        try:
            data = json.loads(pkg_json.read_text(encoding="utf-8"))
            findings["lifecycle_scripts"] = {
                k: v for k, v in (data.get("scripts") or {}).items()
                if k in ("preinstall", "install", "postinstall")
            }
        except (json.JSONDecodeError, OSError):
            pass

    for src in extract.rglob("*.js"):
        try:
            text = src.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for m in SUSPECT_RE.finditer(text):
            findings["suspicious_lines"].append({"file": str(src.relative_to(extract)), "match": m.group(0)})
        findings["urls"].extend(URL_RE.findall(text))
    findings["urls"] = sorted(set(findings["urls"]))[:50]
    findings["suspicious_lines"] = findings["suspicious_lines"][:50]
    return findings


def verdict(gd: dict, insp: dict) -> str:
    score = 0
    res = gd.get("result")
    if isinstance(res, dict):
        for v in res.get("results", res).values() if isinstance(res.get("results", res), dict) else []:
            if v:
                score += 2
    if insp.get("lifecycle_scripts"):
        score += 2
    score += min(len(insp.get("suspicious_lines", [])), 5)
    if score >= 6:
        return "MALICIOUS (high confidence)"
    if score >= 2:
        return "SUSPICIOUS (manual review required)"
    return "benign (no strong indicators)"


def main() -> int:
    ap = argparse.ArgumentParser(description="npm malicious package triage")
    ap.add_argument("--package", help="npm package name")
    ap.add_argument("--version", help="specific version")
    ap.add_argument("--tarball", help="path to a local .tgz instead of downloading")
    ap.add_argument("--output", help="write JSON report")
    args = ap.parse_args()

    if not args.package and not args.tarball:
        ap.error("provide --package or --tarball")

    report: dict = {"package": args.package, "version": args.version}
    with tempfile.TemporaryDirectory() as td:
        work = Path(td)
        if args.tarball:
            tgz = Path(args.tarball)
            report["guarddog"] = (
                guarddog_scan(str(tgz), None) if shutil.which("guarddog") else {"error": "no guarddog"}
            )
        else:
            report["guarddog"] = guarddog_scan(args.package, args.version)
            tgz = download_tarball(args.package, args.version, work)

        report["inspection"] = inspect_tarball(tgz, work) if tgz and tgz.exists() else {"error": "no tarball"}

    report["verdict"] = verdict(report["guarddog"], report["inspection"])
    print(f"[+] verdict: {report['verdict']}")
    if report["inspection"].get("lifecycle_scripts"):
        print(f"[!] install scripts present: {report['inspection']['lifecycle_scripts']}")
    if report["inspection"].get("urls"):
        print(f"[i] {len(report['inspection']['urls'])} URL(s) found in source")

    if args.output:
        Path(args.output).write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(f"[+] report written to {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
