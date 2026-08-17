# Standards and References — Building C2 Redirector Infrastructure

## MITRE ATT&CK References

| Technique ID | Name | Tactic | Rationale |
|-------------|------|--------|-----------|
| T1090.002 | Proxy: External Proxy | Command and Control | The redirector is the external proxy node that hides the team server |
| T1090.004 | Proxy: Domain Fronting | Command and Control | CDN fronting routes C2 through a trusted high-reputation domain |
| T1071.001 | Application Layer Protocol: Web Protocols | Command and Control | C2 is tunneled over HTTP/HTTPS shaped by the malleable profile |
| T1573.002 | Encrypted Channel: Asymmetric Cryptography | Command and Control | TLS termination at the redirector encrypts the channel |
| T1583.006 | Acquire Infrastructure: Web Services | Resource Development | Disposable VPS/CDN edges acquired for resilient C2 |

## NIST Cybersecurity Framework 2.0

| ID | Name | Rationale |
|----|------|-----------|
| DE.CM-01 | Networks and network services are monitored to find potentially adverse events | Redirector-fronted C2 is the adverse traffic defenders must detect; building it informs detection of T1090.002 |

## Official Resources

- MITRE ATT&CK T1090.002: https://attack.mitre.org/techniques/T1090/002/
- Apache mod_rewrite: https://httpd.apache.org/docs/current/mod/mod_rewrite.html
- nginx proxy_pass docs: https://nginx.org/en/docs/http/ngx_http_proxy_module.html
- cs2modrewrite: https://github.com/threatexpress/cs2modrewrite
- RedWarden: https://github.com/mgeeky/RedWarden
- ired.team redirectors/forwarders: https://www.ired.team/offensive-security/red-team-infrastructure/redirectors-forwarders

## Key Research

- RedOps: Cobalt Strike — CDN / Reverse Proxy Setup
- ired.team: Red Team Infrastructure Wiki
- threatexpress: cs2modrewrite project documentation
