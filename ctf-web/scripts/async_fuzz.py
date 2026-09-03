#!/usr/bin/env python3
# <!-- audit-ok --> Burp Intruder-like fuzzer: ThreadPool + httpx, FUZZ placeholder
import argparse, asyncio, base64, hashlib, html, random, re, time, urllib.parse
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests
try: import httpx; HAS_HTTPX=True
except ImportError: HAS_HTTPX=False
UAS=["ctf-web/1.0","Mozilla/5.0 (ctf-web)","ctf-web/2.0"]
def load_wordlist(p): return Path(p).read_text().splitlines()
def apply_processing(p, chain):
    cur,raw=p,p
    for kind,*a in chain:
        if kind=="prefix": cur=a[0]+cur
        elif kind=="suffix": cur=cur+a[0]
        elif kind=="replace": cur=re.sub(a[0],a[1],cur)
        elif kind=="substring": cur=cur[a[0]:a[0]+a[1]]
        elif kind=="reverse_substring": cur=cur[len(cur)-a[0]-a[1]:len(cur)-a[0]] if a[0] else cur[len(cur)-a[1]:]
        elif kind=="case": cur={"upper":str.upper,"lower":str.lower,"title":str.title}[a[0]](cur)
        elif kind=="encode": cur={"url":lambda x:urllib.parse.quote(x,safe=""),"html":html.escape,"base64":lambda x:base64.b64encode(x.encode()).decode(),"hex":lambda x:x.encode().hex()}[a[0]](cur)
        elif kind=="decode": cur={"url":urllib.parse.unquote,"base64":lambda x:base64.b64decode(x).decode(errors="ignore")}[a[0]](cur)
        elif kind=="hash": cur={"md5":lambda x:hashlib.md5(x.encode()).hexdigest(),"sha1":lambda x:hashlib.sha1(x.encode()).hexdigest(),"sha256":lambda x:hashlib.sha256(x.encode()).hexdigest()}[a[0]](cur)
        elif kind=="raw": cur=raw+cur if a[0]=="append" else cur+raw
        elif kind=="skip" and re.search(a[0],cur): return None
        elif kind=="base": cur=cur.replace("{base}",a[0])
        elif kind=="collab": cur=re.sub(a[0],a[1],cur)
        elif kind=="final_urlencode": cur=urllib.parse.quote(cur,safe="")
    return cur
def parse_chain(s): return [tuple(x.split(":",1)) if ":" in x else (x,"") for x in s.split(",") if x] if s else []
def render(url,p): return url.replace("FUZZ",urllib.parse.quote(urllib.parse.unquote(str(p)),safe=""))  # unquote first: quote exactly once even if input already encoded
def sniper(url,payloads,chain):
    for p in payloads:
        c=apply_processing(p,chain)
        if c is not None: yield render(url,c)
def ram(url,payloads,chain): yield from sniper(url,payloads,chain)
def pitchfork(url,sets,chain):
    for combo in zip(*sets):
        pcs=[apply_processing(p,chain) for p in combo]
        if None in pcs: continue
        yield render(url,"|".join(pcs))
def cluster(url,sets,chain,cap=50000):
    import itertools
    for combo in itertools.islice(itertools.product(*sets),cap):
        pcs=[str(apply_processing(p,chain) or "") for p in combo]
        yield render(url,"|".join(pcs))
def grep_match(t,pats): return any(re.search(p,t,re.I) if p.startswith("re:") else p.lower() in t.lower() for p in pats)
def grep_extract(t,rx,max_len=500):
    m=re.search(rx,t,re.S); return (m.group(1)[:max_len] if m and m.lastindex else m.group(0)[:max_len] if m else "")
def run_threaded(url,payloads,threads,delay,jitter,proxy,grep):
    def worker(u):
        s=requests.Session(); s.headers["User-Agent"]=random.choice(UAS)
        if proxy: s.proxies={"http":proxy,"https":proxy}; s.verify=False  # <!-- audit-ok --> CTF self-signed only, not prod
        try:
            r=s.get(u,timeout=10)
            if r.status_code==429:
                try: time.sleep(int(r.headers.get("Retry-After","1")))
                except: time.sleep(1)
            if delay: time.sleep(delay/1000+random.uniform(0,jitter/1000) if jitter else delay/1000)
            hit=grep_match(r.text,grep) if grep else r.status_code not in (200,404)
            return u,r.status_code,len(r.text),hit
        except requests.RequestException: return u,None,0,False
    with ThreadPoolExecutor(max_workers=threads) as ex:
        futs={ex.submit(worker,u):u for u in payloads}
        for f in as_completed(futs):
            u,code,n,hit=f.result(); print(f"{u} -> {code} {n} {'HIT' if hit else ''}")
            if hit: return u
def run_async(url,payloads,conc,grep=None,proxy=None):
    async def _run():
        if not HAS_HTTPX: print("httpx not installed"); return
        limits=httpx.Limits(max_connections=conc,max_keepalive_connections=20)
        kwargs={"limits":limits,"timeout":10,"follow_redirects":True,"verify":False}
        if proxy: kwargs["proxy"]=proxy
        async with httpx.AsyncClient(**kwargs) as client:
            sem=asyncio.Semaphore(conc)
            async def fetch(u):
                async with sem:
                    try:
                        r=await client.get(u)
                        if r.status_code==429:
                            try: await asyncio.sleep(int(r.headers.get("Retry-After","1")))
                            except: await asyncio.sleep(1)
                        hit=grep_match(r.text,grep) if grep else r.status_code not in (200,404); print(f"{u} {r.status_code} {len(r.text)} {'HIT' if hit else ''}"); return u if hit else None
                    except (httpx.RequestError,Exception): return None
            res=await asyncio.gather(*(fetch(u) for u in payloads)); return next((x for x in res if x),None)
    return asyncio.run(_run())
if __name__=="__main__":
    ap=argparse.ArgumentParser(description="async_fuzz — Burp Intruder-like fuzzer (FUZZ)")
    ap.add_argument("--url",required=True,help="target URL with FUZZ marker e.g. https://target/FUZZ")
    ap.add_argument("--wordlist",required=True,help="wordlist file path")
    ap.add_argument("--threads",type=int,default=30,help="concurrency / threads")
    ap.add_argument("--attack",choices=["sniper","ram","pitchfork","cluster"],default="sniper")
    ap.add_argument("--delay",type=int,default=0,help="ms delay between requests")
    ap.add_argument("--jitter",type=int,default=0,help="ms jitter")
    ap.add_argument("--processing",default="",help="chain e.g. prefix:FOO,encode:base64,final_urlencode:")
    ap.add_argument("--proxy",default="",help="http proxy e.g. http://127.0.0.1:8080")
    ap.add_argument("--grep",nargs="*",default=[],help="grep patterns (re: prefix for regex)")
    ap.add_argument("--async",dest="use_async",action="store_true",help="use httpx async")
    args=ap.parse_args()
    chain=parse_chain(args.processing)
    raw=load_wordlist(args.wordlist); payloads=[apply_processing(p,chain) for p in raw]
    payloads=[p for p in payloads if p is not None]
    if args.attack=="sniper": urls=list(sniper(args.url,payloads,[]))
    elif args.attack=="ram": urls=list(ram(args.url,payloads,[]))
    elif args.attack=="pitchfork": urls=list(pitchfork(args.url,[payloads,payloads],[]))
    else: urls=list(cluster(args.url,[payloads,payloads],[]))
    (run_async(args.url,urls,args.threads,args.grep,args.proxy or None) if args.use_async else run_threaded(args.url,urls,args.threads,args.delay,args.jitter,args.proxy,args.grep))
