#!/usr/bin/env python3
# For authorized AI red-teaming and defense of models you own or are permitted to test.
# Cloning a third-party model or inferring its training data without consent may
# violate terms of service, copyright, and privacy law.
"""Model-extraction detection helper.

Two modes:
  detect   - Parse an inference-API audit log (JSONL) and flag principals whose
             query behaviour matches MITRE ATLAS AML.T0024 (model extraction /
             inference). Pure stdlib, no external model needed.
  extract  - Self red-team: train an ART surrogate against your own scikit-learn
             model and report fidelity vs. query budget (requires ART).

Audit log format (one JSON object per line):
  {"ts": 1700000000.0, "principal": "key-123", "input_hash": "ab..",
   "wants_probs": true, "n_features": 12}
"""
import argparse
import collections
import json
import sys


def load_audit(path):
    records = []
    with open(path, "r", encoding="utf-8") as fh:
        for ln, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError as exc:
                print(f"[!] skip malformed line {ln}: {exc}", file=sys.stderr)
    return records


def score_principals(records, q_threshold, uniq_threshold, prob_threshold):
    agg = collections.defaultdict(lambda: {"q": 0, "uniq": set(), "probs": 0})
    for r in records:
        principal = r.get("principal", "unknown")
        a = agg[principal]
        a["q"] += 1
        a["uniq"].add(r.get("input_hash", id(r)))
        a["probs"] += int(bool(r.get("wants_probs", False)))

    findings = []
    for principal, a in agg.items():
        q = a["q"]
        uniq_ratio = len(a["uniq"]) / q if q else 0.0
        prob_ratio = a["probs"] / q if q else 0.0
        suspected = (q >= q_threshold and uniq_ratio >= uniq_threshold
                     and prob_ratio >= prob_threshold)
        findings.append({
            "principal": principal,
            "queries": q,
            "unique_ratio": round(uniq_ratio, 3),
            "prob_request_ratio": round(prob_ratio, 3),
            "suspected_extraction": suspected,
        })
    return sorted(findings, key=lambda x: (-x["suspected_extraction"], -x["queries"]))


def cmd_detect(args):
    records = load_audit(args.audit)
    if not records:
        print("[!] no usable records in audit log", file=sys.stderr)
        return 1
    findings = score_principals(records, args.min_queries,
                                args.min_unique_ratio, args.min_prob_ratio)
    flagged = [f for f in findings if f["suspected_extraction"]]
    print(f"[+] analysed {len(records)} requests across {len(findings)} principals")
    print(f"[+] {len(flagged)} principal(s) match AML.T0024 extraction pattern\n")
    for f in findings:
        mark = "[ALERT]" if f["suspected_extraction"] else "       "
        print(f"{mark} {f['principal']:<24} q={f['queries']:<7} "
              f"uniq={f['unique_ratio']:<6} probs={f['prob_request_ratio']}")
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            json.dump(findings, fh, indent=2)
        print(f"\n[+] findings written to {args.output}")
    return 0


def cmd_extract(args):
    try:
        import numpy as np
        from sklearn.datasets import load_iris
        from sklearn.ensemble import RandomForestClassifier
        from sklearn.model_selection import train_test_split
        from art.estimators.classification import SklearnClassifier
        from art.attacks.extraction import KnockoffNets
    except ImportError:
        print("[!] install: pip install adversarial-robustness-toolbox scikit-learn numpy",
              file=sys.stderr)
        return 1

    # demo victim trained on a public dataset (replace with your production model)
    data = load_iris()
    x_tr, x_te, y_tr, y_te = train_test_split(data.data, data.target,
                                              test_size=0.4, random_state=42)
    victim_model = RandomForestClassifier(n_estimators=100, random_state=0).fit(x_tr, y_tr)
    victim = SklearnClassifier(model=victim_model)

    thief = SklearnClassifier(model=RandomForestClassifier(n_estimators=100))
    attack = KnockoffNets(classifier=victim, batch_size_fit=16, batch_size_query=16,
                          nb_epochs=5, nb_stolen=args.budget, sampling_strategy="random")
    stolen = attack.extract(x=x_te, thief_classifier=thief)

    agreement = float(np.mean(stolen.predict(x_te).argmax(1) ==
                              victim.predict(x_te).argmax(1)))
    print(f"[+] query budget         : {args.budget}")
    print(f"[+] surrogate fidelity   : {agreement:.2%} agreement with victim")
    risk = "HIGH" if agreement > 0.9 else "MEDIUM" if agreement > 0.7 else "LOW"
    print(f"[+] extractability risk  : {risk}")
    return 0


def main():
    p = argparse.ArgumentParser(description="Model-extraction detection / self red-team")
    sub = p.add_subparsers(dest="cmd", required=True)

    d = sub.add_parser("detect", help="flag extraction-like principals in an audit log")
    d.add_argument("--audit", required=True, help="path to JSONL inference audit log")
    d.add_argument("--min-queries", type=int, default=100)
    d.add_argument("--min-unique-ratio", type=float, default=0.9)
    d.add_argument("--min-prob-ratio", type=float, default=0.8)
    d.add_argument("--output", help="write findings JSON")
    d.set_defaults(func=cmd_detect)

    e = sub.add_parser("extract", help="ART self red-team on a demo model")
    e.add_argument("--budget", type=int, default=2000, help="query budget for surrogate")
    e.set_defaults(func=cmd_extract)

    args = p.parse_args()
    sys.exit(args.func(args))


if __name__ == "__main__":
    main()
