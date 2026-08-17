#!/usr/bin/env python3
"""
opencti_modeler.py — Build a threat-actor knowledge graph in OpenCTI via pycti.

Reads a simple JSON model describing an actor, intrusion set, campaign, techniques
(by MITRE ATT&CK id), and indicators, then creates the STIX domain objects and
relationships in OpenCTI. Can also export an intrusion set's full TTP profile.

Real tooling: pycti OpenCTIApiClient (the official OpenCTI Python client).

Usage:
  export OPENCTI_URL=http://localhost:8080
  export OPENCTI_TOKEN=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
  python3 opencti_modeler.py build --model actor_model.json
  python3 opencti_modeler.py export --intrusion-set EXAMPLE-SET

Model file shape (actor_model.json):
{
  "actor": {"name": "APT-EXAMPLE", "description": "...", "types": ["crime-syndicate"]},
  "intrusion_set": {"name": "EXAMPLE-SET", "description": "..."},
  "campaign": {"name": "Operation Example 2026", "description": "..."},
  "techniques": [{"name": "Spearphishing Attachment", "mitre_id": "T1566.001"}],
  "indicators": [{"name": "C2 domain", "pattern": "[domain-name:value = 'bad.example']",
                  "observable_type": "Domain-Name"}]
}
"""
import argparse
import json
import os
import sys
from datetime import datetime, timezone

try:
    from pycti import OpenCTIApiClient
except ImportError:
    sys.exit("[!] pycti not installed. Run: pip install pycti stix2")


def client():
    url = os.environ.get("OPENCTI_URL")
    token = os.environ.get("OPENCTI_TOKEN")
    if not url or not token:
        sys.exit("[!] Set OPENCTI_URL and OPENCTI_TOKEN environment variables.")
    return OpenCTIApiClient(url, token, ssl_verify=False)


def now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def relate(api, from_id, to_id, rtype):
    api.stix_core_relationship.create(
        fromId=from_id, toId=to_id, relationship_type=rtype)
    print(f"    + {rtype}: {from_id[:18]}... -> {to_id[:18]}...")


def build(api, model):
    # Threat actor
    a = model.get("actor", {})
    actor = api.threat_actor_group.create(
        name=a["name"], description=a.get("description", ""),
        threat_actor_types=a.get("types", []), update=True)
    print(f"[+] Threat actor: {a['name']} ({actor['id']})")

    # Intrusion set
    s = model.get("intrusion_set", {})
    iset = api.intrusion_set.create(
        name=s["name"], description=s.get("description", ""), update=True)
    print(f"[+] Intrusion set: {s['name']} ({iset['id']})")
    relate(api, iset["id"], actor["id"], "attributed-to")

    # Campaign
    c = model.get("campaign")
    campaign = None
    if c:
        campaign = api.campaign.create(
            name=c["name"], description=c.get("description", ""), update=True)
        print(f"[+] Campaign: {c['name']} ({campaign['id']})")
        relate(api, campaign["id"], iset["id"], "attributed-to")

    # Techniques (attack patterns by MITRE id)
    for t in model.get("techniques", []):
        ap = api.attack_pattern.create(
            name=t["name"], x_mitre_id=t.get("mitre_id"), update=True)
        print(f"[+] Technique: {t['name']} {t.get('mitre_id','')} ({ap['id']})")
        relate(api, iset["id"], ap["id"], "uses")

    # Indicators
    for ind in model.get("indicators", []):
        obj = api.indicator.create(
            name=ind["name"], pattern_type="stix", pattern=ind["pattern"],
            x_opencti_main_observable_type=ind.get("observable_type", "Unknown"),
            valid_from=now_iso(), update=True)
        print(f"[+] Indicator: {ind['name']} ({obj['id']})")
        relate(api, obj["id"], iset["id"], "indicates")

    print("[=] Knowledge graph build complete.")


def export(api, iset_name):
    iset = api.intrusion_set.read(filters={
        "mode": "and",
        "filters": [{"key": "name", "values": [iset_name]}],
        "filterGroups": [],
    })
    if not iset:
        sys.exit(f"[!] Intrusion set not found: {iset_name}")
    print(f"[+] Intrusion set: {iset['name']} ({iset['id']})")
    rels = api.stix_core_relationship.list(
        fromId=iset["id"], relationship_type="uses")
    print(f"[+] Techniques used ({len(rels)}):")
    for r in rels:
        to = r.get("to", {})
        print(f"    - {to.get('name')}  {to.get('x_mitre_id', '')}")


def main():
    ap = argparse.ArgumentParser(description="Model threats in OpenCTI via pycti.")
    sub = ap.add_subparsers(dest="cmd", required=True)

    b = sub.add_parser("build", help="Create the graph from a JSON model")
    b.add_argument("--model", required=True, help="Path to the model JSON file")

    e = sub.add_parser("export", help="Export an intrusion set's TTP profile")
    e.add_argument("--intrusion-set", required=True, help="Intrusion set name")

    args = ap.parse_args()
    api = client()

    if args.cmd == "build":
        try:
            with open(args.model) as f:
                model = json.load(f)
        except (OSError, json.JSONDecodeError) as ex:
            sys.exit(f"[!] Cannot read model: {ex}")
        build(api, model)
    elif args.cmd == "export":
        export(api, args.intrusion_set)


if __name__ == "__main__":
    main()
