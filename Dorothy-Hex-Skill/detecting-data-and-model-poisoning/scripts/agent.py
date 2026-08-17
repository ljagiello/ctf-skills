#!/usr/bin/env python3
# For authorized defensive ML-security use in isolated environments only.
"""Data and model poisoning detection agent.

Modes:
  integrity -- verify model-weight digests and flag unsafe pickle-based artifacts.
  labels    -- run Cleanlab label-issue detection from saved labels + pred_probs (.npy).
  activations -- run ART activation-clustering poisoning detection on a saved model.

Examples:
  python agent.py integrity --model-dir ./models --expected-sha256 ABC...
  python agent.py labels --labels labels.npy --pred-probs probs.npy
  python agent.py activations --model model.h5 --x x_train.npy --y y_train.npy
"""
import argparse
import glob
import hashlib
import json
import os
import sys
from datetime import datetime, timezone

UNSAFE_EXT = (".pt", ".bin", ".pkl", ".pickle", ".ckpt", ".pth")


def sha256_file(path, chunk=1 << 20):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(chunk), b""):
            h.update(block)
    return h.hexdigest()


def run_integrity(args):
    report = {"ts": datetime.now(timezone.utc).isoformat(),
              "atlas": "AML.T0010", "unsafe_artifacts": [], "digests": {}}
    for path in glob.glob(os.path.join(args.model_dir, "**", "*"), recursive=True):
        if not os.path.isfile(path):
            continue
        if path.lower().endswith(UNSAFE_EXT):
            report["unsafe_artifacts"].append(path)
        if path.lower().endswith(".safetensors"):
            report["digests"][path] = sha256_file(path)

    if args.expected_sha256:
        match = any(d.lower() == args.expected_sha256.lower()
                    for d in report["digests"].values())
        report["expected_digest_match"] = match
        if not match:
            report["warning"] = "No .safetensors matched the expected digest"

    if report["unsafe_artifacts"]:
        report["warning_unsafe"] = (
            "Pickle-based artifacts can execute code on load; prefer safetensors")
    print(json.dumps(report, indent=2))
    return report


def run_labels(args):
    try:
        import numpy as np
        from cleanlab.filter import find_label_issues
    except ImportError:
        print("Install: pip install cleanlab numpy", file=sys.stderr)
        sys.exit(1)
    labels = np.load(args.labels)
    pred_probs = np.load(args.pred_probs)
    issues = find_label_issues(labels=labels, pred_probs=pred_probs,
                               return_indices_ranked_by="self_confidence")
    report = {"ts": datetime.now(timezone.utc).isoformat(), "atlas": "AML.T0020",
              "n_samples": int(len(labels)), "n_label_issues": int(len(issues)),
              "top_suspect_indices": [int(i) for i in issues[:50]]}
    print(json.dumps(report, indent=2))
    return report


def run_activations(args):
    try:
        import numpy as np
        from tensorflow.keras.models import load_model
        from art.estimators.classification import KerasClassifier
        from art.defences.detector.poison import ActivationDefence
    except ImportError as exc:
        print(f"Install: pip install adversarial-robustness-toolbox tensorflow numpy "
              f"({exc})", file=sys.stderr)
        sys.exit(1)
    model = load_model(args.model)
    x_train = np.load(args.x)
    y_train = np.load(args.y)
    classifier = KerasClassifier(model=model)
    defence = ActivationDefence(classifier, x_train, y_train)
    _, is_clean_lst = defence.detect_poison(nb_clusters=2, nb_dims=10, reduce="PCA")
    poisoned = [int(i) for i, c in enumerate(is_clean_lst) if c == 0]
    report = {"ts": datetime.now(timezone.utc).isoformat(), "atlas": "AML.T0018",
              "n_samples": int(len(is_clean_lst)),
              "n_poisoned_flagged": len(poisoned),
              "poisoned_indices_sample": poisoned[:50]}
    print(json.dumps(report, indent=2))
    return report


def main():
    ap = argparse.ArgumentParser(description="Data/model poisoning detection agent")
    sub = ap.add_subparsers(dest="mode", required=True)

    pi = sub.add_parser("integrity", help="Verify weight digests / flag unsafe formats")
    pi.add_argument("--model-dir", required=True)
    pi.add_argument("--expected-sha256", help="Expected safetensors SHA-256")

    pl = sub.add_parser("labels", help="Cleanlab label-issue detection")
    pl.add_argument("--labels", required=True, help=".npy integer labels")
    pl.add_argument("--pred-probs", required=True, help=".npy out-of-sample probs")

    pa = sub.add_parser("activations", help="ART activation-clustering detection")
    pa.add_argument("--model", required=True, help="Keras .h5 model")
    pa.add_argument("--x", required=True, help=".npy training inputs")
    pa.add_argument("--y", required=True, help=".npy training labels")

    args = ap.parse_args()
    if args.mode == "integrity":
        run_integrity(args)
    elif args.mode == "labels":
        run_labels(args)
    elif args.mode == "activations":
        run_activations(args)


if __name__ == "__main__":
    main()
