#!/usr/bin/env python3
# For authorized defensive AI-security use only.
"""Indirect prompt-injection detection agent.

Extracts hidden/obfuscated text from HTML, PDF, or image artifacts, normalizes it,
and scans for prompt-injection using heuristics and (optionally) LLM Guard and a
transformer classifier. Emits a structured JSON verdict suitable for a SIEM.

Examples:
  python agent.py --html page.html
  python agent.py --pdf report.pdf --use-llmguard
  python agent.py --image screenshot.png --use-model
"""
import argparse
import base64
import codecs
import hashlib
import json
import re
import sys
import unicodedata
from datetime import datetime, timezone

ZERO_WIDTH = dict.fromkeys(map(ord, "​‌‍⁠﻿"), None)
TAG_RANGE = set(range(0xE0000, 0xE0080))

# Heuristic injection indicators (case-insensitive).
HEURISTICS = [
    r"ignore (all |the )?(previous|prior|above) instructions",
    r"disregard (the )?(system|previous) (prompt|instructions)",
    r"you are (now )?(an?|in) (developer|admin|dan|jailbreak)",
    r"reveal (the )?(system prompt|secret|api[_ ]?key)",
    r"exfiltrat", r"send .* to https?://", r"new instructions?:",
    r"do not (tell|inform) the user",
]


def normalize(text: str) -> str:
    text = text.translate(ZERO_WIDTH)
    text = "".join(ch for ch in text if ord(ch) not in TAG_RANGE)
    text = unicodedata.normalize("NFKC", text)
    extra = []
    for token in re.findall(r"[A-Za-z0-9+/=]{20,}", text):
        try:
            dec = base64.b64decode(token).decode("utf-8", "ignore")
            if dec.isprintable() and len(dec) > 4:
                extra.append(f"[b64] {dec}")
        except Exception:
            pass
    try:
        extra.append("[rot13] " + codecs.decode(text, "rot_13"))
    except Exception:
        pass
    return text + ("\n" + "\n".join(extra) if extra else "")


def extract_html(path):
    from bs4 import BeautifulSoup, Comment
    soup = BeautifulSoup(open(path, encoding="utf-8", errors="ignore").read(), "html.parser")
    parts = []
    for c in soup.find_all(string=lambda t: isinstance(t, Comment)):
        parts.append(c.strip())
    for el in soup.select('[style*="display:none"],[style*="visibility:hidden"],[hidden]'):
        parts.append(el.get_text(" ", strip=True))
    for img in soup.find_all("img"):
        if img.get("alt"):
            parts.append(img["alt"])
    parts.append(soup.get_text(" ", strip=True))
    return "\n".join(p for p in parts if p)


def extract_pdf(path):
    from pypdf import PdfReader
    return "\n".join((pg.extract_text() or "") for pg in PdfReader(path).pages)


def extract_image(path):
    from PIL import Image
    import pytesseract
    return pytesseract.image_to_string(Image.open(path))


def heuristic_hits(text):
    low = text.lower()
    return [pat for pat in HEURISTICS if re.search(pat, low)]


def scan_llmguard(text):
    try:
        from llm_guard.input_scanners import PromptInjection
        from llm_guard.input_scanners.prompt_injection import MatchType
        s = PromptInjection(threshold=0.5, match_type=MatchType.FULL)
        _, is_valid, risk = s.scan(text)
        return {"available": True, "injection": not is_valid, "risk": risk}
    except ImportError:
        return {"available": False}


def scan_model(text):
    try:
        from transformers import pipeline
        clf = pipeline("text-classification",
                       model="protectai/deberta-v3-base-prompt-injection-v2")
        out = clf(text[:512])[0]
        return {"available": True,
                "injection": out["label"].upper() == "INJECTION",
                "score": out["score"]}
    except ImportError:
        return {"available": False}


def main():
    ap = argparse.ArgumentParser(description="Indirect prompt-injection detector")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--html")
    g.add_argument("--pdf")
    g.add_argument("--image")
    g.add_argument("--text", help="Raw text to scan")
    ap.add_argument("--use-llmguard", action="store_true")
    ap.add_argument("--use-model", action="store_true")
    ap.add_argument("--output")
    args = ap.parse_args()

    try:
        if args.html:
            raw, src = extract_html(args.html), args.html
        elif args.pdf:
            raw, src = extract_pdf(args.pdf), args.pdf
        elif args.image:
            raw, src = extract_image(args.image), args.image
        else:
            raw, src = args.text, "stdin-text"
    except ImportError as exc:
        print(f"[!] Missing dependency: {exc}", file=sys.stderr)
        sys.exit(1)
    except OSError as exc:
        print(f"[!] Cannot read input: {exc}", file=sys.stderr)
        sys.exit(2)

    normalized = normalize(raw or "")
    hits = heuristic_hits(normalized)
    lg = scan_llmguard(normalized) if args.use_llmguard else {"available": False}
    md = scan_model(normalized) if args.use_model else {"available": False}

    flagged = bool(hits) or lg.get("injection") or md.get("injection")
    verdict = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "source": src,
        "sha256": hashlib.sha256((raw or "").encode("utf-8", "ignore")).hexdigest(),
        "atlas": "AML.T0051.001",
        "owasp": "LLM01:2025",
        "heuristic_hits": hits,
        "llmguard": lg,
        "model": md,
        "decision": "block" if flagged else "allow",
    }
    print(json.dumps(verdict, indent=2))
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            json.dump(verdict, fh, indent=2)
    sys.exit(1 if flagged else 0)


if __name__ == "__main__":
    main()
