#!/usr/bin/env python3
# For authorized penetration testing and educational environments only.
# Container escape grants full host compromise. Run only against systems you
# own or are explicitly authorized in writing to test.
"""Container escape posture assessor.

Enumerates the privilege posture of the *current* container and flags which
real-world escape primitives are likely available (privileged/CAP_SYS_ADMIN,
mounted Docker socket, hostPath mount of host root, shared host namespaces) and
whether the installed runC/Docker runtime is vulnerable to the known container
escape CVEs (CVE-2024-21626 and the 2025 procfs write-redirect family).
"""

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from datetime import datetime, timezone


def _run(cmd):
    """Run a command, returning (rc, stdout, stderr) without raising."""
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        return p.returncode, p.stdout.strip(), p.stderr.strip()
    except FileNotFoundError:
        return 127, "", f"not found: {cmd[0]}"
    except subprocess.TimeoutExpired:
        return 124, "", "timeout"


def check_capabilities():
    """Decode the effective capability bitmask from /proc/self/status."""
    findings = {"cap_eff_hex": None, "all_caps": False, "cap_sys_admin": False}
    try:
        with open("/proc/self/status") as fh:
            for line in fh:
                if line.startswith("CapEff:"):
                    hexval = line.split()[1]
                    findings["cap_eff_hex"] = hexval
                    mask = int(hexval, 16)
                    # CAP_SYS_ADMIN is bit 21
                    findings["cap_sys_admin"] = bool(mask & (1 << 21))
                    # "all caps" full-width masks observed in privileged ctrs
                    findings["all_caps"] = hexval.lower().endswith("3fffffffff") or \
                        hexval.lower().endswith("ffffffffff")
    except OSError as exc:
        findings["error"] = str(exc)
    return findings


def check_docker_socket():
    """Detect a mounted (and reachable) Docker daemon socket."""
    sock = "/var/run/docker.sock"
    present = os.path.exists(sock)
    reachable = False
    if present:
        rc, out, _ = _run([
            "curl", "-s", "--max-time", "5", "--unix-socket", sock,
            "http://localhost/version",
        ])
        reachable = rc == 0 and "ApiVersion" in out
    return {"present": present, "reachable": reachable}


def check_host_mounts():
    """Look for hostPath / host-root style mounts in /proc/self/mountinfo."""
    suspects = []
    try:
        with open("/proc/self/mountinfo") as fh:
            for line in fh:
                parts = line.split()
                if len(parts) < 5:
                    continue
                src, dst = parts[3], parts[4]
                if src == "/" or "/var/run/docker.sock" in line or \
                        dst.startswith("/host"):
                    suspects.append({"source": src, "mountpoint": dst})
    except OSError as exc:
        return {"error": str(exc)}
    return {"host_mounts": suspects}


def check_namespaces():
    """Heuristically detect shared host PID namespace."""
    shared_pid = False
    try:
        # If we can read the host init's root and see many host pids, likely shared
        shared_pid = os.path.isdir("/proc/1/root/bin") and \
            len([p for p in os.listdir("/proc") if p.isdigit()]) > 50
    except OSError:
        pass
    return {"likely_host_pid_ns": shared_pid}


def _parse_semver(text):
    m = re.search(r"(\d+)\.(\d+)\.(\d+)", text)
    return tuple(int(x) for x in m.groups()) if m else None


def check_runtime_cves():
    """Check runc version against the known escape CVE patch baselines."""
    result = {"runc_version": None, "vulns": []}
    if not shutil.which("runc"):
        result["note"] = "runc not on PATH in this container; check on the host"
        return result
    _, out, _ = _run(["runc", "--version"])
    result["runc_raw"] = out
    ver = _parse_semver(out)
    result["runc_version"] = ".".join(map(str, ver)) if ver else None
    if not ver:
        return result
    # CVE-2024-21626: 1.0.0-rc93 .. 1.1.11  -> fixed 1.1.12
    if (1, 0, 0) <= ver <= (1, 1, 11):
        result["vulns"].append("CVE-2024-21626 (Leaky Vessels fd leak)")
    # 2025 family: <= 1.2.7, 1.3.2, 1.4.0-rc.2  -> fixed 1.2.8 / 1.3.3 / 1.4.0-rc.3
    if ver <= (1, 2, 7) or (1, 3, 0) <= ver <= (1, 3, 2):
        result["vulns"].append(
            "CVE-2025-31133/52565/52881 (procfs write-redirect family)")
    return result


def assess():
    report = {
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "capabilities": check_capabilities(),
        "docker_socket": check_docker_socket(),
        "mounts": check_host_mounts(),
        "namespaces": check_namespaces(),
        "runtime": check_runtime_cves(),
    }
    primitives = []
    if report["capabilities"].get("cap_sys_admin") or report["capabilities"].get("all_caps"):
        primitives.append("privileged/CAP_SYS_ADMIN -> cgroup release_agent escape")
    if report["docker_socket"].get("reachable"):
        primitives.append("docker.sock mounted -> spawn host-root container")
    if report["mounts"].get("host_mounts"):
        primitives.append("hostPath/host-root mount -> direct host file write")
    if report["namespaces"].get("likely_host_pid_ns"):
        primitives.append("shared host PID namespace -> host process access")
    for v in report["runtime"].get("vulns", []):
        primitives.append(f"vulnerable runtime -> {v}")
    report["available_escape_primitives"] = primitives or ["none obvious detected"]
    return report


def main():
    ap = argparse.ArgumentParser(
        description="Assess container escape posture (authorized testing only)")
    ap.add_argument("-o", "--output", help="write JSON report to file")
    ap.add_argument("--quiet", action="store_true", help="JSON only, no banner")
    args = ap.parse_args()

    report = assess()

    if not args.quiet:
        print("=" * 60)
        print("  CONTAINER ESCAPE POSTURE ASSESSMENT")
        print(f"  {report['generated_utc']}")
        print("=" * 60)
        print("\n[+] Available escape primitives:")
        for p in report["available_escape_primitives"]:
            print(f"    - {p}")
        rt = report["runtime"]
        if rt.get("vulns"):
            print(f"\n[!] Vulnerable runtime: {rt.get('runc_version')}")
            for v in rt["vulns"]:
                print(f"    - {v}")

    out = json.dumps(report, indent=2)
    if args.output:
        with open(args.output, "w") as fh:
            fh.write(out)
        print(f"\n[+] Report written to {args.output}")
    elif args.quiet:
        print(out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
