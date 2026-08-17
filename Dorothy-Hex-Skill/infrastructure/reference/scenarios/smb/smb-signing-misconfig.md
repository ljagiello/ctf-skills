# SMB Signing Misconfiguration

## When this applies

- Target Windows host or file server has SMB exposed (TCP 445).
- Signing is **enabled but not required** — the host accepts both signed and unsigned sessions, and a relayed unsigned session is honored.
- Goal is to enumerate signing policy across the network to identify relay candidates and document a network-level finding.

## Technique

Probe each host's SMB negotiation for signing capability and requirement. Hosts with `Required: false` accept relayed authentication and are vulnerable to NTLM relay attacks (see `scenarios/smb/ntlm-relay-coercion.md`). DCs require signing by default and are typically not relay targets; member servers/workstations often don't enforce signing.

## Steps

### 1. Network-wide signing audit

```bash
# nxc (formerly CrackMapExec) — fastest signing audit, generates relay list
nxc smb 10.0.0.0/24
nxc smb 10.0.0.0/24 --gen-relay-list relay-targets.txt
```

Output legend:
- `signing:True` — enforced (not relay-vulnerable)
- `signing:False` — disabled or optional (relay candidate)

### 2. nmap NSE alternative

```bash
nmap --script smb2-security-mode -p445 TARGET_RANGE -oN signing.txt
nmap --script smb-security-mode -p445 TARGET_RANGE      # SMBv1
```

Output:
- `Message signing enabled and required` — locked down
- `Message signing enabled but not required` — relay candidate
- `Message signing disabled` — even worse, fully unsigned

### 3. Manual probe via smbclient

```bash
# Client signing flag negotiation
smbclient -L //TARGET -N --client-protection=sign
smbclient -L //TARGET -N --client-protection=encrypt
```

If a server accepts a session without enforcing signing, it's a candidate. Without `--client-protection=sign`, modern smbclient still negotiates signing, but the server's response indicates whether it required or merely allowed signing.

### 4. Signing policy interpretation

| Server type | Default policy | Override |
|---|---|---|
| Domain Controller | Required | Disable via Group Policy (rare, intentional misconfig) |
| Member server | Enabled, not required | Set via GPO `Microsoft network server: Digitally sign communications (always)` |
| Workstation | Enabled, not required | Same GPO |
| Standalone server | Disabled | Same GPO |

The relevant Group Policy:
- `Computer Configuration → Policies → Windows Settings → Security Settings → Local Policies → Security Options`
  - `Microsoft network server: Digitally sign communications (always)` = Enabled (required)
  - `Microsoft network server: Digitally sign communications (if client agrees)` = Enabled (optional)

### 5. SMB encryption (SMB3+)

SMB3 introduces transport encryption per share or per server:

```bash
# Check if server requires encryption (SMB 3.x)
nmap --script smb2-security-mode -p445 TARGET
```

SMB3 encryption (AES-CCM/GCM) supersedes signing for protected sessions. A server with `EncryptData = required` is even harder to relay than signed-only.

### 6. LDAP signing / channel binding (parallel concern)

When auditing for relay opportunities, also check LDAP/LDAPS:

```bash
nxc ldap DC -u '' -p '' --signing
# or with creds for a more reliable check
nxc ldap DC -u user -p pass --signing
```

LDAP relay viability:
- LDAP signing **not** required → can relay NTLM to LDAP for AD ACL abuse / RBCD
- LDAPS channel binding **not** required → can relay NTLM to LDAPS

Both are typical defaults pre-2019 and after the MS-Mar-2020 hardening guidance, but many domains still lag.

### 7. Generate relay target list

```bash
nxc smb 10.0.0.0/24 --gen-relay-list relay-targets.txt
wc -l relay-targets.txt   # how many relay candidates exist
```

Feed the list directly to `ntlmrelayx -tf relay-targets.txt`.

### 8. Reporting

A typical report finding:

> **Title**: SMB signing not required on N hosts
> **Severity**: Medium-High depending on environment
> **Affected**: list of IPs / hostnames where signing is enabled but not required
> **Recommendation**: Enforce SMB signing via Group Policy `Microsoft network server: Digitally sign communications (always) = Enabled`. For DCs, this is the default; for member servers/workstations, requires explicit GPO. Verify after rollout with `nxc smb <range>`.

## Verifying success

- Audit table mapping each host → signing required? signing enabled? encryption?
- `relay-targets.txt` enumerates only hosts with `signing:False`.
- For any flagged host, a successful relay (with PoC ntlmrelayx run) confirms exploitability.

## Common pitfalls

- **DCs and signing**: `Domain controller: Digitally sign secure channel data (when possible)` is a different policy from SMB signing. DCs require SMB signing by default; the secure-channel signing policy is for the netlogon channel.
- **SMB1 signing is broken** — even with required signing, SMB1 lacks downgrade protection. Disabling SMB1 is more important than enforcing SMB1 signing.
- **`nmap` SMB2 security-mode script** shows the negotiated mode for the scanner's session — not necessarily the server's full policy.
- **Per-share encryption override**: `Set-SmbShare -Name <Name> -EncryptData $true` enforces encryption only for that share. Server-wide `Set-SmbServerConfiguration -EncryptData $true` covers everything.
- **GPO precedence**: Domain GPO can override local; local can override default. Check effective policy with `gpresult /h`.

## Tools

- nxc / crackmapexec (`--gen-relay-list`, fastest audit)
- nmap NSE: `smb2-security-mode`, `smb-security-mode`
- smbclient with `--client-protection=` flag
- impacket-ntlmrelayx (consumer of the relay list)
- PowerShell `Get-SmbServerConfiguration` (on-host view of effective config)
