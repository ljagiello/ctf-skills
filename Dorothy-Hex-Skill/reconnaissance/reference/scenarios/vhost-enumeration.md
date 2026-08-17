# Virtual Host Enumeration

## When this applies

A web server hosts multiple sites distinguished by the `Host` header (name-based virtual hosting). The "default" site visible at the IP differs from internal vhosts that may host admin panels, staging environments, or private APIs.

Strong indicators that vhost enumeration is worthwhile:

- TLS certificate has a wildcard SAN (`*.example.tld`) or many SANs.
- Response headers leak a hostname (`X-Backend-Server`, `X-Forwarded-Host`, `X-Served-By`).
- Hosts file or DNS history references names that don't resolve publicly.
- Different content appears when the same IP is reached with different `Host` headers.
- The app integrates a backend platform (ML registry, CI, monitoring) whose admin/API service is often split onto its own vhost (`models.`, `mlflow.`, `ci.`, `grafana.`). A `Host` value returning **401 with `WWW-Authenticate: Basic realm="..."`** (vs the default 301/200) exposes such a backend — then try that product's default creds (e.g. MLflow `admin:password`, see [MLflow registry RCE](../../../ai-threat-testing/reference/scenarios/llm/llm05-supply-chain-vulnerabilities.md)).

## Technique

Send the same HTTP request with different `Host` headers and detect responses that differ from the default. Differences manifest as response size, status code, content hash, or redirect target.

Two common modes:

1. **Brute force** - Try a wordlist of subdomain names against the IP.
2. **Targeted** - Try names extracted from cert SANs, response headers, or related domains.

## Steps

1. **Establish the default response baseline**

   ```bash
   IP=192.0.2.10
   DOMAIN=example.tld

   # Default response (no Host or arbitrary Host)
   curl -sI -k "http://${IP}/" -H "Host: nonexistent.${DOMAIN}" \
     | tee recon/raw/vhost-baseline.txt
   curl -s  -k "http://${IP}/" -H "Host: nonexistent.${DOMAIN}" \
     | wc -c   # baseline size
   ```

   Record the baseline status code, content length, and content hash. Vhosts that match these values are not interesting.

2. **Brute force with ffuf (response-size filter)**

   ```bash
   WORDLIST=/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
   BASELINE_SIZE=1234     # from step 1

   ffuf -u "http://${IP}/" \
        -H "Host: FUZZ.${DOMAIN}" \
        -w ${WORDLIST} \
        -mc all -fs ${BASELINE_SIZE} \
        -o recon/raw/vhost-${DOMAIN}.json -of json
   ```

   `-mc all -fs <baseline>` means: match all status codes, but filter out responses with the baseline size. Anything that survives the filter is a candidate vhost.

3. **HTTPS with wildcard cert**

   ```bash
   ffuf -u "https://${IP}/" -k \
        -H "Host: FUZZ.${DOMAIN}" \
        -w ${WORDLIST} \
        -mc all -fs ${BASELINE_SIZE} \
        -o recon/raw/vhost-https-${DOMAIN}.json -of json
   ```

   `-k` skips certificate verification, which is required when the cert SAN does not match the IP.

4. **Shell loop fallback**

   When ffuf or gobuster are unavailable, a quick loop suffices:

   ```bash
   for sub in admin dev api portal dashboard staging git internal beta; do
     code=$(curl -s -o /dev/null -w "%{http_code}:%{size_download}" \
       -k -H "Host: ${sub}.${DOMAIN}" "http://${IP}/")
     echo "${sub}: ${code}"
   done
   ```

   Filter the output by response size differing from the baseline.

5. **Extract candidates from cert SANs first**

   Targeted enumeration is faster than brute force when the cert has SANs.

   ```bash
   echo | openssl s_client -connect ${IP}:443 -servername ${DOMAIN} 2>/dev/null \
     | openssl x509 -noout -text \
     | awk '/Subject Alternative Name/{getline; print}' \
     | tr ',' '\n' | sed 's/^ *DNS://' \
     > recon/raw/cert-sans-${DOMAIN}.txt

   while read host; do
     code=$(curl -s -o /dev/null -w "%{http_code}:%{size_download}" \
       -k -H "Host: ${host}" "https://${IP}/")
     echo "${host}: ${code}"
   done < recon/raw/cert-sans-${DOMAIN}.txt
   ```

6. **Add discovered vhosts to /etc/hosts**

   ```bash
   echo "${IP} admin.${DOMAIN} dev.${DOMAIN}" | sudo tee -a /etc/hosts
   ```

7. **Verify each candidate by content**

   ```bash
   for host in admin.${DOMAIN} dev.${DOMAIN}; do
     curl -sk "https://${host}/" | sha256sum   # content hash
     curl -skI "https://${host}/"              # headers
   done
   ```

## Verifying success

- For every candidate, the response status, size, and hash differ from the baseline.
- New vhosts are added to `/etc/hosts` and listed in `recon/inventory/vhosts.txt`.
- Cert SANs and `X-*` header hostname leaks are recorded in `recon/analysis/attack-surface.md`.

## After foothold: read the proxy config directly

When recon yields a foothold (RCE via a default-creds web admin, file-read primitive, etc.) AND the front is nginx/Apache/HAProxy/Caddy, skip the brute force and read the config files directly. Internal vhosts that map to `localhost:3000` / `localhost:5000` / `127.0.0.1:8080` are the real attack surface; the public vhost is usually the boring one.

```bash
# nginx
cat /etc/nginx/sites-enabled/* /etc/nginx/conf.d/*.conf
ls -l /etc/nginx/sites-enabled/

# Apache
cat /etc/apache2/sites-enabled/*.conf
cat /etc/httpd/conf.d/*.conf

# HAProxy
cat /etc/haproxy/haproxy.cfg

# Caddy
cat /etc/caddy/Caddyfile
```

Each `server { server_name <name>; }` block (or HAProxy `frontend`/`backend` pair) reveals an internal `server_name` plus the upstream `proxy_pass http://localhost:<port>`. Add the discovered vhost to `/etc/hosts` (`<TARGET_IP> <internal-vhost>`), probe externally, and the nginx routing turns the internal service into an external attack surface.

Frequent pattern in CWEE/AppSec engagements: the outer vhost is benign (static blog, marketing site); the inner vhost has the real auth flow / WS handler / DB-backed feature.

## Common pitfalls

- Forgetting `-k` against IPs whose certs are issued for hostnames - HTTPS requests fail before the Host header is even processed.
- Using a single response-size filter when the default site dynamically varies in size; switch to content-hash filtering with `-mr`/`-fr` regex rules.
- Ignoring 30x redirects: a 302 to `https://internal.example.tld/` confirms the vhost exists even if the body is empty.
- Brute-forcing with massive wordlists before checking cert SANs and headers - SANs often hand the answer over directly.
- Running enumeration against the public hostname instead of the raw IP; the front-door domain is just one vhost among many.
- Brute-forcing vhosts when you already have a shell on the foothold — `cat /etc/nginx/sites-enabled/*` is faster and complete.

## Tools

- `ffuf`, `gobuster vhost` - vhost brute force with response filtering.
- `openssl s_client` - SAN extraction.
- `wfuzz` - alternative HTTP fuzzer with `-H "Host: FUZZ"` support.
- `httpx` - probing with `-vhost` mode (auto-detection of vhost differences).
- SecLists `Discovery/DNS/` for vhost-friendly wordlists.
