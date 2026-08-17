#!/usr/bin/env python3
"""
pqc_agent.py — Post-quantum cryptography migration helper.

Three defensive functions for quantum-readiness work:

  scan      Inventory the public-key crypto of a remote TLS endpoint and a set
            of local X.509 certificates, flagging quantum-vulnerable algorithms
            (RSA/EC/DSA/DH) vs. quantum-safe (ML-KEM / ML-DSA / SLH-DSA).
  prioritize  Apply Mosca's inequality to a CSV of assets to rank migration order.
  hybrid-test  Use the local OpenSSL CLI to negotiate the hybrid X25519MLKEM768
            TLS group against a host and report whether it succeeded.

Run only against systems you are authorized to assess. The scan opens TLS
sockets and reads certificates; it does not transmit or store key material.

Examples:
  python3 pqc_agent.py scan --host example.com --port 443 --certs ./certs/*.pem
  python3 pqc_agent.py prioritize --csv assets.csv --crqc-years 8
  python3 pqc_agent.py hybrid-test --host pq.cloudflareresearch.com --port 443
"""
import argparse
import csv
import glob
import socket
import ssl
import subprocess
import sys

try:
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa, ed25519, ed448
    HAVE_CRYPTO = True
except ImportError:
    HAVE_CRYPTO = False

QUANTUM_VULNERABLE = ("rsa", "ec", "ecdsa", "dsa", "dh", "ecdh", "ed25519", "ed448")
QUANTUM_SAFE = ("ml-kem", "mlkem", "ml-dsa", "mldsa", "slh-dsa", "slhdsa")


def _classify_public_key(pubkey):
    """Return (algorithm_label, vulnerable_bool, key_size_or_curve)."""
    if isinstance(pubkey, rsa.RSAPublicKey):
        return "RSA", True, pubkey.key_size
    if isinstance(pubkey, ec.EllipticCurvePublicKey):
        return "EC", True, pubkey.curve.name
    if isinstance(pubkey, dsa.DSAPublicKey):
        return "DSA", True, pubkey.key_size
    if isinstance(pubkey, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
        return type(pubkey).__name__, True, "edwards"
    return pubkey.__class__.__name__, False, "?"


def _fetch_peer_cert_pem(host, port, timeout):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as ssock:
            der = ssock.getpeercert(binary_form=True)
            version = ssock.version()
            cipher = ssock.cipher()
    return ssl.DER_cert_to_PEM_cert(der), version, cipher


def _inspect_cert_pem(pem_text, label):
    if not HAVE_CRYPTO:
        sys.stderr.write("ERROR: install dependency: python3 -m pip install cryptography\n")
        sys.exit(2)
    cert = x509.load_pem_x509_certificate(pem_text.encode())
    alg, vuln, size = _classify_public_key(cert.public_key())
    sig = cert.signature_algorithm_oid._name
    sig_vuln = any(v in sig.lower() for v in QUANTUM_VULNERABLE) and \
        not any(s in sig.lower() for s in QUANTUM_SAFE)
    flag = "VULNERABLE" if (vuln or sig_vuln) else "quantum-safe"
    print(f"[{flag:>12}] {label}")
    print(f"               subject : {cert.subject.rfc4514_string()}")
    print(f"               pubkey  : {alg} ({size})")
    print(f"               sig alg : {sig}")
    return vuln or sig_vuln


def cmd_scan(args):
    findings = 0
    if args.host:
        try:
            pem, version, cipher = _fetch_peer_cert_pem(args.host, args.port, args.timeout)
            print(f"== Remote endpoint {args.host}:{args.port} ({version}, {cipher[0]}) ==")
            if _inspect_cert_pem(pem, f"{args.host}:{args.port} leaf cert"):
                findings += 1
        except (socket.error, ssl.SSLError, OSError) as exc:
            sys.stderr.write(f"ERROR: could not connect to {args.host}:{args.port}: {exc}\n")
    cert_paths = []
    for pattern in args.certs:
        cert_paths.extend(glob.glob(pattern))
    if cert_paths:
        print("\n== Local certificates ==")
    for path in cert_paths:
        try:
            with open(path, "r", encoding="utf-8") as fh:
                if _inspect_cert_pem(fh.read(), path):
                    findings += 1
        except (OSError, ValueError) as exc:
            sys.stderr.write(f"WARN: skipping {path}: {exc}\n")
    print(f"\nQuantum-vulnerable assets found: {findings}")
    return 1 if findings else 0


def cmd_prioritize(args):
    """Mosca's inequality: migrate if data_lifetime + migration_time > crqc_years."""
    try:
        with open(args.csv, newline="", encoding="utf-8") as fh:
            rows = list(csv.DictReader(fh))
    except OSError as exc:
        sys.stderr.write(f"ERROR: cannot read {args.csv}: {exc}\n")
        sys.exit(1)
    scored = []
    for r in rows:
        try:
            life = float(r.get("data_lifetime_years", 0))
            mig = float(r.get("migration_time_years", 1))
        except ValueError:
            life, mig = 0.0, 1.0
        urgent = (life + mig) > args.crqc_years
        margin = (life + mig) - args.crqc_years
        scored.append((margin, urgent, r.get("asset", "?"), life, mig))
    scored.sort(reverse=True)
    print(f"{'PRIORITY':<10}{'MARGIN':>8}  ASSET (data_life + migration vs CRQC={args.crqc_years}y)")
    print("-" * 70)
    for margin, urgent, asset, life, mig in scored:
        tag = "MIGRATE" if urgent else "monitor"
        print(f"{tag:<10}{margin:>+8.1f}  {asset}  (life={life}, mig={mig})")
    return 0


def cmd_hybrid_test(args):
    cmd = ["openssl", "s_client", "-tls1_3", "-groups", "X25519MLKEM768",
           "-connect", f"{args.host}:{args.port}"]
    try:
        proc = subprocess.run(cmd, input=b"", capture_output=True, timeout=args.timeout)
    except FileNotFoundError:
        sys.stderr.write("ERROR: openssl not found on PATH (need 3.5+ or oqs-provider).\n")
        sys.exit(2)
    except subprocess.TimeoutExpired:
        sys.stderr.write("ERROR: openssl s_client timed out.\n")
        sys.exit(1)
    out = (proc.stdout + proc.stderr).decode(errors="replace")
    ok = "Server Temp Key" in out or "Negotiated TLS1.3 group: X25519MLKEM768" in out
    if proc.returncode == 0 and ok:
        for line in out.splitlines():
            if "Temp Key" in line or "Negotiated" in line or "Cipher" in line:
                print(line.strip())
        print(f"\n[OK] {args.host}:{args.port} negotiated hybrid X25519MLKEM768")
        return 0
    sys.stderr.write(f"[FAIL] {args.host}:{args.port} did not negotiate X25519MLKEM768\n")
    sys.stderr.write(out[-800:] + "\n")
    return 1


def build_parser():
    p = argparse.ArgumentParser(description="Post-quantum cryptography migration helper.")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan", help="Inventory TLS endpoint + local certs for quantum-vulnerable crypto")
    s.add_argument("--host", help="Remote host to inspect")
    s.add_argument("--port", type=int, default=443)
    s.add_argument("--certs", nargs="*", default=[], help="Glob(s) of local PEM certs")
    s.add_argument("--timeout", type=float, default=10)
    s.set_defaults(func=cmd_scan)

    pr = sub.add_parser("prioritize", help="Rank assets via Mosca's inequality from a CSV")
    pr.add_argument("--csv", required=True,
                    help="CSV with columns: asset,data_lifetime_years,migration_time_years")
    pr.add_argument("--crqc-years", type=float, default=10,
                    help="Estimated years until a cryptographically relevant quantum computer")
    pr.set_defaults(func=cmd_prioritize)

    h = sub.add_parser("hybrid-test", help="Test hybrid X25519MLKEM768 negotiation via openssl")
    h.add_argument("--host", required=True)
    h.add_argument("--port", type=int, default=443)
    h.add_argument("--timeout", type=float, default=15)
    h.set_defaults(func=cmd_hybrid_test)
    return p


def main():
    args = build_parser().parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
