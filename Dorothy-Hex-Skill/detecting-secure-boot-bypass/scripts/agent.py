#!/usr/bin/env python3
"""
Secure Boot bypass / bootkit detection helper (Linux + Windows-aware).

Collects:
  - Secure Boot enabled state
  - dbx (revocation list) entry count and freshness signal
  - SHA-256 hashes of EFI boot binaries on the ESP
  - CHIPSEC secureboot.variables result (optional, requires root + chipsec)

Emits a JSON report and a human-readable summary. Read-only by default.
Authorized assessment use only; run from a trusted/live environment.
"""
import argparse
import glob
import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path

ESP_PATHS = ["/boot/efi/EFI", "/boot/EFI", "/efi/EFI"]


def run(cmd: list[str], timeout: int = 300) -> tuple[int, str, str]:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout, p.stderr
    except FileNotFoundError:
        return 127, "", f"not found: {cmd[0]}"
    except subprocess.SubprocessError as exc:
        return 1, "", str(exc)


def secure_boot_state() -> dict:
    state = {"platform": platform.system()}
    if platform.system() == "Linux":
        if shutil.which("mokutil"):
            rc, out, _ = run(["mokutil", "--sb-state"])
            state["mokutil_sb_state"] = out.strip() or "unknown"
            state["enabled"] = "enabled" in out.lower()
        else:
            # Fall back to reading the EFI variable directly
            var = glob.glob("/sys/firmware/efi/efivars/SecureBoot-*")
            if var:
                try:
                    data = Path(var[0]).read_bytes()
                    state["enabled"] = bool(data and data[-1] == 1)
                    state["efivar_raw"] = data.hex()
                except OSError as exc:
                    state["error"] = f"efivar read failed: {exc}"
            else:
                state["error"] = "no mokutil and no SecureBoot efivar"
    elif platform.system() == "Windows":
        rc, out, err = run(
            ["powershell", "-NoProfile", "-Command", "Confirm-SecureBootUEFI"]
        )
        state["confirm_secureboot"] = out.strip()
        state["enabled"] = out.strip().lower() == "true"
    return state


def dbx_status() -> dict:
    info = {}
    if shutil.which("dbxtool"):
        rc, out, err = run(["dbxtool", "--list"])
        # Each revocation is one line; count non-empty lines as an approximation
        lines = [l for l in out.splitlines() if l.strip()]
        info["dbxtool_entries"] = len(lines)
        info["sample"] = lines[:5]
        if len(lines) < 50:
            info["warning"] = "low dbx entry count; platform may be behind on revocations"
    elif shutil.which("efi-readvar"):
        rc, out, err = run(["efi-readvar", "-v", "dbx"])
        info["efi_readvar_dbx_excerpt"] = out[:800]
    else:
        info["error"] = "neither dbxtool nor efi-readvar available"
    return info


def hash_esp_binaries() -> list[dict]:
    results = []
    base = next((p for p in ESP_PATHS if os.path.isdir(p)), None)
    if not base:
        return [{"error": "no ESP path found (run as root with EFI mounted)"}]
    for path in Path(base).rglob("*.efi"):
        try:
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            results.append({"file": str(path), "sha256": digest, "size": path.stat().st_size})
        except OSError as exc:
            results.append({"file": str(path), "error": str(exc)})
    return results


def chipsec_secureboot() -> dict:
    if not shutil.which("chipsec_main"):
        return {"error": "chipsec_main not installed"}
    rc, out, err = run(["chipsec_main", "-m", "common.secureboot.variables"], timeout=600)
    verdict = "PASSED" if "PASSED" in out else "FAILED" if "FAILED" in out else "UNKNOWN"
    return {"verdict": verdict, "tail": out[-1200:]}


def main() -> int:
    ap = argparse.ArgumentParser(description="Secure Boot / bootkit assessment")
    ap.add_argument("--check-chipsec", action="store_true", help="Run CHIPSEC secureboot module (root)")
    ap.add_argument("--output", help="Write JSON report")
    args = ap.parse_args()

    if platform.system() == "Linux" and os.geteuid() != 0:
        print("[warn] not running as root; some checks may be incomplete", file=sys.stderr)

    report = {
        "secure_boot": secure_boot_state(),
        "dbx": dbx_status(),
        "esp_binaries": hash_esp_binaries(),
    }
    if args.check_chipsec:
        report["chipsec_secureboot_variables"] = chipsec_secureboot()

    sb = report["secure_boot"]
    print(f"[+] Secure Boot enabled: {sb.get('enabled')}")
    if not sb.get("enabled"):
        print("[!] Secure Boot is NOT enabled — platform is unprotected against bootkits")
    if "warning" in report["dbx"]:
        print(f"[!] dbx: {report['dbx']['warning']}")
    print(f"[+] {len([b for b in report['esp_binaries'] if 'sha256' in b])} EFI binaries hashed")
    if args.check_chipsec:
        print(f"[+] CHIPSEC secureboot.variables: {report['chipsec_secureboot_variables'].get('verdict')}")

    if args.output:
        Path(args.output).write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(f"[+] report written to {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
