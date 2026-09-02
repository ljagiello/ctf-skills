"""Mocked intruder/payload deploy tests for ctf-web python-requests toolkit.

Validates sync/threaded/async intruder helpers, PAT loader cap, 429
Retry-After throttle, proxy pass-through, and processing-chain skip rule.
No real network — all requests mocked via unittest.mock.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import html
import re
import time
import urllib.parse
import unittest
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, call, patch

try:
    import pytest  # type: ignore[import]
except ImportError:  # pragma: no cover
    pytest = None  # type: ignore[assignment]

try:
    import requests  # type: ignore[import]
except ImportError:  # pragma: no cover
    import sys
    from unittest.mock import MagicMock as _MagicMock

    class _FakeSession:
        def __init__(self, *a, **kw):
            self.headers: dict = {}
            self.proxies: dict = {}
            self.cookies = _MagicMock()
            self.verify = True

        def get(self, *a, **kw):
            return _MagicMock(text="", status_code=200, headers={})

        def post(self, *a, **kw):
            return _MagicMock(text="", status_code=200, headers={})

    _fake_requests = _MagicMock()
    _fake_requests.Session = _FakeSession  # type: ignore[attr-defined]
    _fake_requests.RequestException = Exception  # type: ignore[attr-defined]
    requests = _fake_requests  # type: ignore[assignment]
    sys.modules["requests"] = _fake_requests  # type: ignore[assignment]

try:
    import httpx  # type: ignore[import]
except ImportError:  # pragma: no cover
    httpx = None  # type: ignore[assignment]

# ---------------------------------------------------------------------------
# Helpers — mirror ctf-web/python-requests.md and ctf-web/scripts/async_fuzz.py
# ---------------------------------------------------------------------------

TIMEOUT = 10
USER_AGENTS = ["ctf-web/1.0", "Mozilla/5.0 (ctf-web)", "ctf-web/2.0 (example.com)"]


def _make_session(proxy: str | None = None) -> requests.Session:
    sess = requests.Session()
    sess.headers.update({"User-Agent": "ctf-web/1.0"})
    if proxy:
        sess.proxies = {"http": proxy, "https": proxy}
    return sess


def intruder_sync(url_template: str, payloads: list[str], grep_hit: str = "flag{") -> tuple[str, MagicMock] | None:
    sess = requests.Session()
    sess.headers.update({"User-Agent": "ctf-web/1.0"})
    # baseline (mirrors doc; adds one extra GET — tests mock it)
    try:
        baseline = sess.get("https://example.com/profile", timeout=10)
        _ = (len(baseline.text), baseline.status_code)
    except requests.RequestException:
        pass
    for p in payloads:
        url = url_template.replace("FUZZ", urllib.parse.quote(str(p), safe=""))
        try:
            r = sess.get(url, timeout=10)
            hit = (grep_hit in r.text) or ("error" in r.text.lower()) or (r.status_code not in (200, 404))
            if hit:
                return url, r
        except requests.RequestException:
            continue
    return None


def intruder_threaded(
    url_template: str, payload_iter, threads: int = 30, grep_hit: str = "flag{"
) -> str | None:
    def worker(payload_url: str):
        s = requests.Session()
        s.headers.update({"User-Agent": "ctf-web/1.0"})
        try:
            r = s.get(payload_url, timeout=10)
            hit = ("flag{" in r.text.lower()) or ("error" in r.text.lower()) or (r.status_code not in (200, 404))
            return payload_url, r.status_code, len(r.text), hit, r.text[:400]
        except requests.RequestException:
            return payload_url, None, 0, False, ""

    urls = [url_template.replace("FUZZ", urllib.parse.quote(str(p), safe="")) for p in payload_iter]
    with ThreadPoolExecutor(max_workers=threads) as ex:
        futs = {ex.submit(worker, url): url for url in urls}
        for fut in as_completed(futs):
            url, code, n, hit, snippet = fut.result()
            if hit:
                for pending in futs:
                    pending.cancel()
                return url
    return None


async def intruder_async(
    url_template: str, payload_iter, concurrency: int = 100, grep_hit: str = "flag{"
) -> str | None:
    if httpx is None:
        raise RuntimeError("httpx not installed")
    payloads = list(payload_iter)
    urls = [url_template.replace("FUZZ", urllib.parse.quote(str(p), safe="")) for p in payloads]
    limits = httpx.Limits(max_connections=concurrency, max_keepalive_connections=20)
    timeout = httpx.Timeout(10.0, connect=5.0)
    async with httpx.AsyncClient(limits=limits, timeout=timeout, follow_redirects=True) as client:
        sem = asyncio.Semaphore(concurrency)

        async def fetch(url: str):
            async with sem:
                try:
                    r = await client.get(url)
                    hit = ("flag{" in r.text.lower()) or ("error" in r.text.lower()) or (r.status_code not in (200, 404))
                    return url if hit else None
                except Exception:
                    return None

        results = await asyncio.gather(*(fetch(u) for u in urls))
        return next((r for r in results if r), None)


def load_pat(category: str = "XSS Injection", cap: int = 200) -> list[str]:
    primary = Path("ctf-web/payloads/PayloadsAllTheThings") / category
    fallback = Path.home() / ".ctf-tools" / "PayloadsAllTheThings" / category
    pat = primary if primary.exists() else fallback
    if not pat.exists():
        return []
    out: list[str] = []
    for f in pat.rglob("*.txt"):
        for line in f.read_text(errors="ignore").splitlines()[:cap]:
            s = line.strip()
            if s and not s.startswith("#"):
                out.append(s)
            if len(out) >= cap:
                break
        if len(out) >= cap:
            break
        break  # first file only; remove to aggregate all
    return out


def send_with_throttle(sess, url: str, delay_ms: int = 0, jitter_ms: int = 0, retries: int = 2, pause_ms: int = 200, backoff_codes=(429, 503)):
    import random

    for attempt in range(retries + 1):
        try:
            sess.headers["User-Agent"] = __import__("random").choice(USER_AGENTS)
            r = sess.get(url, timeout=10)
            if r.status_code in backoff_codes:
                retry_after = r.headers.get("Retry-After", "")
                try:
                    wait = int(retry_after)
                except ValueError:
                    wait = delay_ms / 1000 if delay_ms else 1
                wait += random.uniform(0, jitter_ms / 1000) if jitter_ms else 0
                time.sleep(wait)
                continue
            if delay_ms:
                time.sleep(delay_ms / 1000 + (random.uniform(0, jitter_ms / 1000) if jitter_ms else 0))
            return r
        except requests.RequestException:
            if attempt < retries:
                time.sleep(pause_ms / 1000)
            else:
                raise
    return None


def process_payload(p: str, rules) -> str | None:
    cur, raw = p, p
    for kind, *args in rules:
        if kind == "prefix":
            cur = args[0] + cur
        elif kind == "suffix":
            cur = cur + args[0]
        elif kind == "replace":
            cur = re.sub(args[0], args[1], cur)
        elif kind == "substring":
            off, n = args
            cur = cur[off : off + n]
        elif kind == "reverse_substring":
            end, n = args
            cur = cur[len(cur) - end - n : len(cur) - end] if end else cur[len(cur) - n :]
        elif kind == "case":
            cur = {"upper": str.upper, "lower": str.lower, "title": str.title}[args[0]](cur)
        elif kind == "encode":
            cur = {"url": lambda x: urllib.parse.quote(x, safe=""), "html": html.escape, "base64": lambda x: base64.b64encode(x.encode()).decode(), "hex": lambda x: x.encode().hex()}[args[0]](cur)
        elif kind == "decode":
            cur = {"url": urllib.parse.unquote, "base64": lambda x: base64.b64decode(x).decode(errors="ignore")}[args[0]](cur)
        elif kind == "hash":
            cur = {"md5": lambda x: hashlib.md5(x.encode()).hexdigest(), "sha1": lambda x: hashlib.sha1(x.encode()).hexdigest(), "sha256": lambda x: hashlib.sha256(x.encode()).hexdigest()}[args[0]](cur)
        elif kind == "raw":
            cur = (raw + cur) if args[0] == "append" else (cur + raw)
        elif kind == "skip":
            if re.search(args[0], cur):
                return None
        elif kind == "extension":
            cur = args[0](cur)
        elif kind == "base":
            cur = cur.replace("{base}", args[0])
        elif kind == "collab":
            cur = re.sub(args[0], args[1], cur)
        elif kind == "final_urlencode":
            cur = urllib.parse.quote(cur, safe="")
    return cur


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestWebRequestsSnippets(unittest.TestCase):
    """Mocked tests for python-requests intruder helpers."""

    def test_session_scaffold_has_ua(self) -> None:
        sess = requests.Session()
        sess.headers.update({"User-Agent": "ctf-web/1.0"})
        self.assertEqual(sess.headers.get("User-Agent"), "ctf-web/1.0")

    def test_intruder_sync_finds_flag(self) -> None:
        mock_sess = MagicMock()
        # baseline + payload hit
        mock_sess.get.side_effect = [
            MagicMock(text="baseline", status_code=200, headers={}),
            MagicMock(text="flag{test}", status_code=200, headers={}),
        ]
        mock_sess.headers = {}
        with patch("requests.Session", return_value=mock_sess):
            result = intruder_sync("https://example.com/search?q=FUZZ", ["payload"])
        self.assertIsNotNone(result)
        assert result is not None
        url, resp = result
        self.assertIn("payload", url)
        self.assertIn("flag{test}", resp.text)
        # ensure Session.get was called at least twice (baseline + payload)
        self.assertGreaterEqual(mock_sess.get.call_count, 2)

    def test_threaded_finds_hit(self) -> None:
        # Per-worker Session mock: every worker's get returns flag for second url
        def make_mock_sess(*args, **kwargs):
            m = MagicMock()
            m.headers = {}

            def fake_get(url, **kw):
                if "hitme" in url:
                    return MagicMock(text="flag{threaded}", status_code=200, headers={}, text_lower="flag{threaded}")
                # need .text.lower() check — return MagicMock with text containing flag only for hitme
                mm = MagicMock()
                mm.text = "not found"
                mm.status_code = 404
                mm.headers = {}
                return mm

            # simpler: inspect url string
            def get_impl(url, timeout=10, **kw):
                if "hitme" in url:
                    r = MagicMock()
                    r.text = "flag{threaded}"
                    r.status_code = 200
                    r.headers = {}
                    return r
                r = MagicMock()
                r.text = "not found"
                r.status_code = 404
                r.headers = {}
                return r

            m.get.side_effect = get_impl
            return m

        with patch("requests.Session", side_effect=make_mock_sess):
            result = intruder_threaded(
                "https://example.com/search?q=FUZZ", ["miss", "hitme", "miss2"], threads=2
            )
        self.assertIsNotNone(result)
        assert result is not None
        self.assertIn("hitme", result)

    def test_async_gather_called(self) -> None:
        if httpx is None:
            self.skipTest("httpx not installed")
        mock_client = AsyncMock()
        # mock response with flag
        mock_resp = MagicMock()
        mock_resp.text = "flag{async}"
        mock_resp.status_code = 200
        mock_resp.headers = {}
        mock_client.get.return_value = mock_resp
        # AsyncClient context manager
        mock_client.__aenter__.return_value = mock_client
        mock_client.__aexit__.return_value = AsyncMock()

        with patch("httpx.AsyncClient", return_value=mock_client) as mock_cls:
            with patch("asyncio.gather", wraps=asyncio.gather) as mock_gather:
                result = asyncio.run(
                    intruder_async("https://example.com/search?q=FUZZ", ["a", "b"], concurrency=5)
                )
                # gather should have been called at least once
                mock_gather.assert_called()
                # AsyncClient was instantiated
                mock_cls.assert_called()
                # result should be a hit url since mock always returns flag
                self.assertIsNotNone(result)

    def test_wordlist_cap_200(self) -> None:
        # Simulate a PAT file with 500 lines, ensure load_pat caps at 200
        mock_file = MagicMock()
        mock_file.read_text.return_value = "\n".join([f"payload{i}" for i in range(500)] + ["# comment", ""])
        with patch.object(Path, "exists", return_value=True):
            with patch.object(Path, "rglob", return_value=[mock_file]):
                out = load_pat("XSS Injection", cap=200)
        self.assertEqual(len(out), 200)
        # also test cap larger not exceeded: 50 lines -> 50
        mock_file2 = MagicMock()
        mock_file2.read_text.return_value = "\n".join([f"x{i}" for i in range(50)])
        with patch.object(Path, "exists", return_value=True):
            with patch.object(Path, "rglob", return_value=[mock_file2]):
                out2 = load_pat("XSS Injection", cap=200)
        self.assertEqual(len(out2), 50)
        self.assertLessEqual(len(out), 200)

    def test_retry_after_429(self) -> None:
        mock_sess = MagicMock()
        mock_sess.headers = {}
        # first call 429 with Retry-After 1, second 200
        r429 = MagicMock()
        r429.status_code = 429
        r429.headers = {"Retry-After": "1"}
        r429.text = ""
        r200 = MagicMock()
        r200.status_code = 200
        r200.headers = {}
        r200.text = "ok flag{test}"
        mock_sess.get.side_effect = [r429, r200]
        with patch("time.sleep") as mock_sleep:
            result = send_with_throttle(mock_sess, "https://example.com/FUZZ", retries=2)
        # sleep should have been called with 1 (Retry-After)
        mock_sleep.assert_called()
        # check at least one call arg ==1 or 1.0
        calls = [c.args[0] if c.args else None for c in mock_sleep.call_args_list]
        self.assertTrue(any(c == 1 or c == 1.0 for c in calls), f"sleep calls were {mock_sleep.call_args_list}")
        self.assertIsNotNone(result)
        self.assertEqual(result.status_code, 200)

    def test_proxy_passed(self) -> None:
        proxy = "http://127.0.0.1:8080"
        sess = _make_session(proxy=proxy)
        self.assertIn("127.0.0.1:8080", sess.proxies["http"])
        self.assertIn("127.0.0.1:8080", sess.proxies["https"])
        # also verify worker-style per-thread session can carry proxy
        with patch("requests.Session") as mock_cls:
            mock_inst = MagicMock()
            mock_inst.headers = {}
            mock_inst.proxies = {}
            mock_cls.return_value = mock_inst
            s = requests.Session()
            s.proxies = {"http": proxy, "https": proxy}
            s.headers.update({"User-Agent": "ctf-web/1.0"})
            # simulate worker proxy assignment
            self.assertEqual(s.proxies["http"], proxy)
            self.assertEqual(s.proxies["https"], proxy)

    def test_processing_chain_skip_regex(self) -> None:
        # skip if matches ^.{0,3}$  -> strings length 0-3 should be skipped (return None)
        self.assertIsNone(process_payload("ab", [("skip", r"^.{0,3}$")]))
        self.assertIsNone(process_payload("abc", [("skip", r"^.{0,3}$")]))
        self.assertIsNone(process_payload("", [("skip", r"^.{0,3}$")]))
        # longer strings pass through
        self.assertIsNotNone(process_payload("abcd", [("skip", r"^.{0,3}$")]))
        self.assertEqual(process_payload("abcd", [("skip", r"^.{0,3}$")]), "abcd")
        # also test skip combined with other rules: prefix then skip
        self.assertIsNone(process_payload("a", [("prefix", "ab"), ("skip", r"^.{0,3}$")]))  # "aba" len 3 -> skip
        self.assertEqual(process_payload("abcd", [("prefix", "x"), ("skip", r"^.{0,3}$")]), "xabcd")
