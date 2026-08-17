#!/usr/bin/env python3
"""
esp_bootkit_hunter.py — Baseline and hunt malicious EFI binaries on the EFI System Partition.

Mounts (or reads an already-mounted) ESP, inventories EFI/PE boot binaries, computes
SHA-256 hashes, verifies Secure Boot signatures with sbverify, flags files outside the
canonical EFI/ directory, diffs against a golden baseline, and optionally YARA-scans.

Real tooling used: sbverify (sbsigntool), yara, sha256 hashing. No placeholders.

Usage:
  sudo python3 esp_bootkit_hunter.py --esp /mnt/esp --baseline baseline.sha256
  sudo python3 esp_bootkit_hunter.py --device /dev/sda1 --mount --yara bootkit.yar
"""
import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile

EFI_EXTENSIONS = (".efi", ".sys", ".dll")


def run(cmd):
    """Run a command, return (returncode, stdout, stderr)."""
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        return p.returncode, p.stdout, p.stderr
    except FileNotFoundError:
        return 127, "", f"binary not found: {cmd[0]}"
    except subprocess.TimeoutExpired:
        return 124, "", "timeout"


def mount_esp(device, mountpoint):
    os.makedirs(mountpoint, exist_ok=True)
    rc, _, err = run(["mount", "-o", "ro,umask=077", device, mountpoint])
    if rc != 0:
        sys.exit(f"[!] Failed to mount {device}: {err.strip()}")
    print(f"[+] Mounted {device} read-only at {mountpoint}")


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def find_efi_binaries(esp_root):
    found = []
    for dirpath, _, files in os.walk(esp_root):
        for name in files:
            if name.lower().endswith(EFI_EXTENSIONS):
                found.append(os.path.join(dirpath, name))
    return found


def detect_anomalous_root(esp_root):
    """Per Velociraptor/Rapid7: EFI/ should be the only top-level dir on the ESP."""
    allowed = {"efi", "system volume information"}
    anomalies = []
    for entry in os.listdir(esp_root):
        if entry.lower() not in allowed:
            anomalies.append(os.path.join(esp_root, entry))
    return anomalies


def verify_signature(path):
    """Use sbverify --list to confirm the binary carries a Secure Boot signature."""
    if not shutil.which("sbverify"):
        return "sbverify-missing"
    rc, out, _ = run(["sbverify", "--list", path])
    if rc != 0:
        return "UNSIGNED-or-invalid"
    # sbverify --list prints 'signature N' lines for each embedded signature
    return "signed" if "signature" in out.lower() else "UNSIGNED"


def load_baseline(path):
    baseline = set()
    if not path or not os.path.exists(path):
        return baseline
    with open(path) as f:
        for line in f:
            tok = line.strip().split()
            if tok:
                baseline.add(tok[0].lower())
    return baseline


def yara_scan(rules, esp_root):
    if not shutil.which("yara"):
        return "yara-missing"
    rc, out, err = run(["yara", "-r", "-w", rules, esp_root])
    return out.strip() or ("(no matches)" if rc == 0 else err.strip())


def main():
    ap = argparse.ArgumentParser(description="Hunt bootkits on the EFI System Partition.")
    ap.add_argument("--esp", default="/mnt/esp", help="ESP mountpoint")
    ap.add_argument("--device", help="ESP block device to mount (e.g. /dev/sda1)")
    ap.add_argument("--mount", action="store_true", help="Mount --device read-only first")
    ap.add_argument("--baseline", help="Golden baseline sha256 file to diff against")
    ap.add_argument("--yara", help="YARA ruleset to scan the ESP with")
    ap.add_argument("--json", help="Write findings to this JSON path")
    args = ap.parse_args()

    if os.geteuid() != 0:
        print("[!] Warning: ESP access typically requires root.", file=sys.stderr)

    if args.mount:
        if not args.device:
            sys.exit("--mount requires --device")
        mount_esp(args.device, args.esp)

    if not os.path.isdir(args.esp):
        sys.exit(f"[!] ESP path not found: {args.esp}")

    report = {"esp": args.esp, "binaries": [], "root_anomalies": [],
              "baseline_new": [], "yara": None}

    # Step 2: anomalous root entries
    report["root_anomalies"] = detect_anomalous_root(args.esp)
    for a in report["root_anomalies"]:
        print(f"[!] ANOMALY: non-EFI entry in ESP root -> {a}")

    # Steps 3-4: inventory, hash, verify signatures
    baseline = load_baseline(args.baseline)
    for path in find_efi_binaries(args.esp):
        try:
            digest = sha256_file(path)
        except OSError as e:
            print(f"[!] Cannot read {path}: {e}", file=sys.stderr)
            continue
        sig = verify_signature(path)
        new = bool(baseline) and digest.lower() not in baseline
        entry = {"path": path, "sha256": digest, "signature": sig, "new_vs_baseline": new}
        report["binaries"].append(entry)
        flag = ""
        if sig.startswith("UNSIGNED"):
            flag += " [UNSIGNED]"
        if new:
            flag += " [NOT-IN-BASELINE]"
            report["baseline_new"].append(digest)
        print(f"[+] {digest}  {sig:18s} {path}{flag}")

    # Step 6: YARA
    if args.yara:
        report["yara"] = yara_scan(args.yara, args.esp)
        print(f"[+] YARA results:\n{report['yara']}")

    # Summary
    n_unsigned = sum(1 for b in report["binaries"] if b["signature"].startswith("UNSIGNED"))
    print(f"\n[=] {len(report['binaries'])} EFI binaries | "
          f"{n_unsigned} unsigned | {len(report['baseline_new'])} new vs baseline | "
          f"{len(report['root_anomalies'])} root anomalies")

    if args.json:
        with open(args.json, "w") as f:
            json.dump(report, f, indent=2)
        print(f"[+] Wrote findings to {args.json}")

    # Non-zero exit if anything suspicious was found (CI/hunt automation friendly)
    if n_unsigned or report["baseline_new"] or report["root_anomalies"]:
        sys.exit(2)


if __name__ == "__main__":
    main()
