#!/usr/bin/env python3
"""
MISP feed operationalization helper.

Connects to a MISP instance with PyMISP, searches for fresh, actionable
(to_ids, published, warninglist-enforced) IOCs, and writes detection artifacts:
  - Suricata rules (via REST returnFormat:suricata)
  - a Wazuh CDB list (domains + IPs)
  - a Sigma rule (DNS contact to malicious domains)

Defensive threat-intelligence use. Handle exported IOCs per their TLP marking.
"""
import argparse
import json
import sys
from pathlib import Path

try:
    from pymisp import PyMISP
except ImportError:
    print("[error] pymisp not installed: pip install pymisp", file=sys.stderr)
    sys.exit(1)

import urllib.request
import ssl

IOC_TYPES = ["ip-dst", "ip-src", "domain", "hostname", "url", "md5", "sha256"]


def connect(url: str, key: str, insecure: bool) -> PyMISP:
    return PyMISP(url, key, ssl=not insecure)


def search_iocs(misp: PyMISP, last: str) -> list:
    try:
        return misp.search(
            controller="attributes",
            type_attribute=IOC_TYPES,
            to_ids=True,
            published=True,
            last=last,
            enforce_warninglist=True,
            pythonify=True,
        )
    except Exception as exc:  # noqa: BLE001
        print(f"[error] MISP search failed: {exc}", file=sys.stderr)
        return []


def export_suricata(url: str, key: str, last: str, insecure: bool, out: Path) -> bool:
    endpoint = (
        f"{url.rstrip('/')}/attributes/restSearch/returnFormat:suricata/"
        f"to_ids:1/type:domain%7Cip-dst%7Curl/last:{last}"
    )
    ctx = ssl.create_default_context()
    if insecure:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(
        endpoint, headers={"Authorization": key, "Accept": "application/json"}
    )
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=120) as resp:
            out.write_bytes(resp.read())
        return True
    except Exception as exc:  # noqa: BLE001
        print(f"[warn] suricata export failed: {exc}", file=sys.stderr)
        return False


def write_wazuh_cdb(attrs: list, out: Path) -> int:
    n = 0
    with out.open("w", encoding="utf-8") as fh:
        for a in attrs:
            if a.type in ("domain", "hostname", "ip-dst", "ip-src"):
                fh.write(f"{a.value}:\n")
                n += 1
    return n


def write_sigma(attrs: list, out: Path) -> int:
    domains = sorted({a.value for a in attrs if a.type in ("domain", "hostname")})
    if not domains:
        return 0
    rule = {
        "title": "MISP feed malicious domain contact",
        "status": "experimental",
        "description": "DNS query to a domain flagged malicious in MISP feeds",
        "logsource": {"category": "dns"},
        "detection": {"selection": {"query|contains": domains}, "condition": "selection"},
        "level": "high",
        "tags": ["attack.command_and_control", "attack.t1071.004"],
    }
    try:
        import yaml
        out.write_text("", encoding="utf-8")
        with out.open("w", encoding="utf-8") as fh:
            yaml.safe_dump(rule, fh, sort_keys=False, default_flow_style=False)
    except ImportError:
        out.write_text(json.dumps(rule, indent=2), encoding="utf-8")
        print("[warn] pyyaml missing; wrote Sigma rule as JSON", file=sys.stderr)
    return len(domains)


def main() -> int:
    ap = argparse.ArgumentParser(description="MISP feed -> detections pipeline")
    ap.add_argument("--url", required=True, help="MISP base URL")
    ap.add_argument("--key", required=True, help="MISP Auth Key")
    ap.add_argument("--last", default="7d", help="time window (e.g. 7d, 24h)")
    ap.add_argument("--outdir", default="./detections")
    ap.add_argument("--insecure", action="store_true", help="skip TLS verification (lab)")
    args = ap.parse_args()

    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)

    try:
        misp = connect(args.url, args.key, args.insecure)
    except Exception as exc:  # noqa: BLE001
        print(f"[error] cannot connect to MISP: {exc}", file=sys.stderr)
        return 2

    attrs = search_iocs(misp, args.last)
    print(f"[+] {len(attrs)} actionable IOC(s) retrieved (last {args.last})")

    suricata_ok = export_suricata(
        args.url, args.key, args.last, args.insecure, outdir / "misp_suricata.rules"
    )
    if suricata_ok:
        print(f"[+] Suricata rules -> {outdir / 'misp_suricata.rules'}")

    cdb_n = write_wazuh_cdb(attrs, outdir / "misp_iocs.cdb")
    print(f"[+] Wazuh CDB list ({cdb_n} entries) -> {outdir / 'misp_iocs.cdb'}")

    sig_n = write_sigma(attrs, outdir / "misp_domains.yml")
    print(f"[+] Sigma rule ({sig_n} domains) -> {outdir / 'misp_domains.yml'}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
