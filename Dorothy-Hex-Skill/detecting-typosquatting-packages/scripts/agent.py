#!/usr/bin/env python3
"""
Typosquatting screening helper.

Generates the standard typogard/typomania mutation set for a candidate package
name, screens names against a popular-name corpus, and enriches suspected
squats with live registry metadata (npm / PyPI) to support triage.

No third-party dependencies required (stdlib only). Network calls use urllib.

Examples:
    # Screen a single name against a PyPI corpus
    python agent.py screen --ecosystem pypi --corpus top-pypi-packages.json --name reqeusts

    # Screen names from stdin (e.g., a diff of requirements.txt)
    git diff | python agent.py screen --ecosystem npm --corpus npm-top.json --stdin

    # Show the generated mutation set for a legit name
    python agent.py mutate --name requests

    # Pull registry metadata for triage
    python agent.py enrich --ecosystem pypi --name reqeusts
"""
import argparse
import json
import sys
import urllib.request
import urllib.error

QWERTY_ADJ = {
    "q": "wa", "w": "qeas", "e": "wrsd", "r": "etdf", "t": "ryfg",
    "y": "tugh", "u": "yihj", "i": "uojk", "o": "ipkl", "p": "ol",
    "a": "qwsz", "s": "awedxz", "d": "serfcx", "f": "drtgvc",
    "g": "ftyhbv", "h": "gyujnb", "j": "huikmn", "k": "jiolm",
    "l": "kop", "z": "asx", "x": "zsdc", "c": "xdfv", "v": "cfgb",
    "b": "vghn", "n": "bhjm", "m": "njk",
    "0": "9", "1": "2", "2": "13", "3": "24", "4": "35",
}
DELIMS = ["-", "_", ".", ""]


def mutations(name):
    """Reproduce the typogard/typomania squat primitives for `name`."""
    out = set()
    n = name.lower()
    # 1. omission
    for i in range(len(n)):
        out.add(n[:i] + n[i + 1:])
    # 2. repetition
    for i in range(len(n)):
        out.add(n[:i] + n[i] + n[i:])
    # 3. transposition / swap of adjacent chars
    for i in range(len(n) - 1):
        out.add(n[:i] + n[i + 1] + n[i] + n[i + 2:])
    # 4. keyboard-adjacency 1-edit substitution
    for i, ch in enumerate(n):
        for repl in QWERTY_ADJ.get(ch, ""):
            out.add(n[:i] + repl + n[i + 1:])
    # 5. delimiter swaps
    for d in DELIMS:
        for d2 in DELIMS:
            if d and d in n:
                out.add(n.replace(d, d2))
    # 6. word-order swap for compound names
    for d in ("-", "_", "."):
        if d in n:
            parts = n.split(d)
            if len(parts) == 2:
                out.add(d.join(reversed(parts)))
    # 7. common suffixes
    for suf in ("js", "py", "lib", "cli", "2", "-ng"):
        out.add(n + suf)
        out.add(n + "-" + suf)
    out.discard(n)
    return {m for m in out if m}


def levenshtein(a, b):
    if len(a) < len(b):
        a, b = b, a
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def load_corpus(path):
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    names = set()
    # Accept several common corpus shapes
    if isinstance(data, dict) and "rows" in data:          # top-pypi-packages
        names = {r["project"] for r in data["rows"]}
    elif isinstance(data, dict) and "objects" in data:     # npm search
        names = {o["package"]["name"] for o in data["objects"]}
    elif isinstance(data, list):
        names = {(x if isinstance(x, str) else x.get("name", "")) for x in data}
    elif isinstance(data, dict):
        names = set(data.keys())
    return {n.lower() for n in names if n}


def http_json(url):
    req = urllib.request.Request(url, headers={"User-Agent": "typosquat-screen/1.0"})
    with urllib.request.urlopen(req, timeout=20) as resp:
        return json.loads(resp.read().decode("utf-8"))


def enrich(ecosystem, name):
    """Pull triage metadata from the live registry."""
    try:
        if ecosystem == "npm":
            d = http_json(f"https://registry.npmjs.org/{name}")
            latest = d.get("dist-tags", {}).get("latest")
            ver = d.get("versions", {}).get(latest, {})
            return {
                "name": name,
                "created": d.get("time", {}).get("created"),
                "maintainers": [m.get("name") for m in d.get("maintainers", [])],
                "scripts": ver.get("scripts", {}),
                "repository": ver.get("repository"),
            }
        elif ecosystem == "pypi":
            d = http_json(f"https://pypi.org/pypi/{name}/json")
            info = d.get("info", {})
            return {
                "name": name,
                "author": info.get("author"),
                "home_page": info.get("home_page"),
                "releases": list(d.get("releases", {}).keys()),
                "project_urls": info.get("project_urls"),
            }
    except urllib.error.HTTPError as exc:
        return {"name": name, "error": f"HTTP {exc.code} (name may not exist)"}
    except Exception as exc:  # noqa: BLE001
        return {"name": name, "error": str(exc)}
    return {"name": name, "error": "unsupported ecosystem"}


def screen_name(name, corpus, threshold=2):
    """Return list of (legit_name, distance) the candidate squats on."""
    name = name.lower().strip()
    hits = []
    if name in corpus:
        return []  # exact legit match is not a squat
    for legit in corpus:
        d = levenshtein(name, legit)
        if 0 < d <= threshold and abs(len(name) - len(legit)) <= threshold:
            hits.append((legit, d))
    hits.sort(key=lambda x: x[1])
    return hits


def cmd_mutate(args):
    for m in sorted(mutations(args.name)):
        print(m)


def cmd_screen(args):
    corpus = load_corpus(args.corpus)
    candidates = []
    if args.stdin:
        for line in sys.stdin:
            for tok in line.replace('"', " ").replace(",", " ").split():
                tok = tok.strip("+-=:'`@^~>< \t")
                if tok and tok[0].isalpha():
                    candidates.append(tok)
    if args.name:
        candidates.append(args.name)
    flagged = 0
    for cand in dict.fromkeys(candidates):
        hits = screen_name(cand, corpus, args.threshold)
        if hits:
            flagged += 1
            top = ", ".join(f"{l}(d={d})" for l, d in hits[:3])
            print(f"[FLAG] {cand} -> resembles {top}")
    print(f"\nScreened {len(set(candidates))} name(s), flagged {flagged}.", file=sys.stderr)
    sys.exit(1 if flagged else 0)


def cmd_enrich(args):
    print(json.dumps(enrich(args.ecosystem, args.name), indent=2))


def main():
    p = argparse.ArgumentParser(description="Typosquatting screening helper")
    sub = p.add_subparsers(dest="cmd", required=True)

    m = sub.add_parser("mutate", help="Print squat mutations of a name")
    m.add_argument("--name", required=True)
    m.set_defaults(func=cmd_mutate)

    s = sub.add_parser("screen", help="Screen names against a popular-name corpus")
    s.add_argument("--corpus", required=True)
    s.add_argument("--ecosystem", choices=["npm", "pypi", "cargo"], default="pypi")
    s.add_argument("--name")
    s.add_argument("--stdin", action="store_true")
    s.add_argument("--threshold", type=int, default=2)
    s.set_defaults(func=cmd_screen)

    e = sub.add_parser("enrich", help="Pull registry metadata for triage")
    e.add_argument("--ecosystem", choices=["npm", "pypi"], required=True)
    e.add_argument("--name", required=True)
    e.set_defaults(func=cmd_enrich)

    args = p.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
