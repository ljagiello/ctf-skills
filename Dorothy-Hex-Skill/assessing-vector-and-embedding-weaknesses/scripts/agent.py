#!/usr/bin/env python3
"""Vector/embedding weakness assessor.

Runs four checks against a RAG pipeline you are authorized to test:
  inversion  - measures how close a guessed reconstruction sits to a target vector
  membership - computes in-corpus vs control top-1 similarity delta (Qdrant)
  isolation  - verifies server-side tenant filtering (Qdrant)
  injection  - scans retrieved chunk text for indirect prompt-injection markers

Examples
--------
    python agent.py inversion --secret "MRN 553120 hypertension" \
        --guess "patient MRN hypertension diagnosis"
    python agent.py membership --url http://localhost:6333 --collection docs \
        --quote "<exact chunk quote>" --control "unrelated sentence"
    python agent.py isolation --url http://localhost:6333 --collection docs \
        --tenant-field tenant_id --tenant B --query "salary information"
"""
import argparse
import re
import sys

INJECTION_PATTERNS = [
    r"ignore (all|previous|the above) instructions",
    r"system prompt", r"you are now", r"disregard previous",
    r"</?(system|instructions)>",
]


def get_embedder(model_name):
    try:
        from sentence_transformers import SentenceTransformer
    except ImportError:
        sys.exit("[!] sentence-transformers not installed. pip install sentence-transformers")
    return SentenceTransformer(model_name)


def get_qdrant(url):
    try:
        from qdrant_client import QdrantClient
    except ImportError:
        sys.exit("[!] qdrant-client not installed. pip install qdrant-client")
    return QdrantClient(url=url)


def cmd_inversion(args):
    from sklearn.metrics.pairwise import cosine_similarity
    model = get_embedder(args.model)
    tv = model.encode([args.secret])
    gv = model.encode([args.guess])
    sim = float(cosine_similarity(tv, gv)[0][0])
    print(f"inversion cosine(secret, guess) = {sim:.4f}")
    verdict = "HIGH inversion risk" if sim >= 0.85 else "moderate" if sim >= 0.6 else "low"
    print(f"verdict: {verdict}")
    return 1 if sim >= 0.85 else 0


def cmd_membership(args):
    model = get_embedder(args.model)
    client = get_qdrant(args.url)

    def top1(text):
        vec = model.encode([text])[0].tolist()
        hits = client.search(collection_name=args.collection, query_vector=vec, limit=1)
        return hits[0].score if hits else 0.0

    in_corpus = top1(args.quote)
    control = top1(args.control)
    delta = in_corpus - control
    print(f"in-corpus top1 = {in_corpus:.4f}")
    print(f"control  top1 = {control:.4f}")
    print(f"delta         = {delta:.4f}")
    leak = delta >= 0.2
    print("verdict:", "MEMBERSHIP LEAK" if leak else "no clear membership signal")
    return 1 if leak else 0


def cmd_isolation(args):
    from qdrant_client.models import Filter, FieldCondition, MatchValue
    model = get_embedder(args.model)
    client = get_qdrant(args.url)
    vec = model.encode([args.query])[0].tolist()

    filtered = client.search(
        collection_name=args.collection, query_vector=vec, limit=10,
        query_filter=Filter(must=[FieldCondition(
            key=args.tenant_field, match=MatchValue(value=args.tenant))]),
    )
    leak_filtered = [h for h in filtered
                     if h.payload.get(args.tenant_field) != args.tenant]

    unfiltered = client.search(collection_name=args.collection, query_vector=vec, limit=10)
    leak_unfiltered = [h for h in unfiltered
                       if h.payload.get(args.tenant_field) != args.tenant]

    print(f"filtered query foreign rows   : {len(leak_filtered)}")
    print(f"unfiltered query foreign rows : {len(leak_unfiltered)}")
    if leak_filtered:
        print("CRITICAL: filtered query returned other tenants' data")
    elif leak_unfiltered:
        print("WARNING: isolation appears client-side only; server returns cross-tenant data")
    else:
        print("isolation OK at server level for this query")
    return 1 if (leak_filtered or leak_unfiltered) else 0


def cmd_injection(args):
    model = get_embedder(args.model)
    client = get_qdrant(args.url)
    vec = model.encode([args.query])[0].tolist()
    hits = client.search(collection_name=args.collection, query_vector=vec, limit=args.limit)
    found = 0
    for h in hits:
        text = (h.payload or {}).get("text", "")
        flags = [p for p in INJECTION_PATTERNS if re.search(p, text.lower())]
        if flags:
            found += 1
            print(f"INJECTION in chunk {h.id}: {flags}")
    print(f"{found} of {len(hits)} retrieved chunks flagged for indirect injection")
    return 1 if found else 0


def main():
    p = argparse.ArgumentParser(description="Vector/embedding weakness assessor")
    p.add_argument("--model", default="all-MiniLM-L6-v2", help="embedding model")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("inversion"); s.add_argument("--secret", required=True); s.add_argument("--guess", required=True)
    s = sub.add_parser("membership")
    s.add_argument("--url", required=True); s.add_argument("--collection", required=True)
    s.add_argument("--quote", required=True); s.add_argument("--control", required=True)
    s = sub.add_parser("isolation")
    s.add_argument("--url", required=True); s.add_argument("--collection", required=True)
    s.add_argument("--tenant-field", default="tenant_id"); s.add_argument("--tenant", required=True)
    s.add_argument("--query", required=True)
    s = sub.add_parser("injection")
    s.add_argument("--url", required=True); s.add_argument("--collection", required=True)
    s.add_argument("--query", default="help"); s.add_argument("--limit", type=int, default=10)

    args = p.parse_args()
    dispatch = {
        "inversion": cmd_inversion, "membership": cmd_membership,
        "isolation": cmd_isolation, "injection": cmd_injection,
    }
    try:
        sys.exit(dispatch[args.cmd](args))
    except Exception as exc:
        sys.exit(f"[!] {args.cmd} failed: {exc}")


if __name__ == "__main__":
    main()
