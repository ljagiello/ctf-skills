# ROADtools Command Reference

## ROADrecon

| Command | Purpose | Key flags |
|---------|---------|-----------|
| `roadrecon auth` | Authenticate to Entra ID | `-u` user, `-p` password, `--device-code`, `--access-token`, `--refresh-token`, `--prt`, `--prt-sessionkey`, `--prt-cookie`, `--prt-init` |
| `roadrecon gather` | Gather directory into roadrecon.db | `--mfa` (needs privileged role) |
| `roadrecon gui` | Launch Angular GUI (http://127.0.0.1:5000) | — |
| `roadrecon plugin policies` | Analyze conditional-access policies | `-f` file, `-p` |
| `roadrecon plugin bloodhound` | Export to BloodHound format | — |

Auth state is stored in `.roadtools_auth`; directory data in `roadrecon.db`.

## roadtx (ROADtools Token eXchange)

### Token acquisition
| Command | Purpose | Key flags |
|---------|---------|-----------|
| `roadtx gettokens` | Acquire tokens (ROPC / refresh) | `-u`, `-p`, `-c` client, `-r` resource, `-s` scope, `--refresh-token`, `--cae`, `--tokens-stdout` |
| `roadtx interactiveauth` | Interactive (browser) auth | `-u`, `-p`, `-c`, `-r`, `-ru` redirect-url |
| `roadtx codeauth` | Exchange auth code for tokens | — |
| `roadtx refreshtokento` | Convert stored RT to another resource | `-r`, `-s`, `-c` |
| `roadtx appauth` | App (client-credential) auth | `-c`, `-p` secret, `-t` tenant, `-r`, `-s`, `--cert-pem`, `--key-pem`, `--cert-pfx`, `--pfx-pass` |
| `roadtx federatedappauth` | Federated app auth (workload identity) | `-c`, `--cert-pem`, `--key-pem`, `--subject`, `-t`, `--issuer`, `-s`, `--kid` |

### Device + PRT
| Command | Purpose | Key flags |
|---------|---------|-----------|
| `roadtx device` | Register/delete a device | `-n` name, `-a` action, `-c` cert, `-k` key |
| `roadtx hybriddevice` | Register hybrid-joined device | — |
| `roadtx prt` | Request/renew a PRT | `-u`, `-p`, `--key-pem`, `--cert-pem`, `-a` action, `-r` refresh-token |
| `roadtx prtauth` | Auth a client using a PRT | `-c`, `-r`, `-f` prt-file, `--prt`, `--prt-sessionkey`, `--tokens-stdout` |
| `roadtx browserprtauth` | Browser auth using PRT | `-url`, `-c`, `-r`, `-f` |
| `roadtx browserprtinject` | Inject PRT compliance claims | `-u`, `-r`, `-c` |
| `roadtx prtenrich` | Add MFA claim to PRT | `-u` |
| `roadtx prtcookie` | Mint browser cookie from PRT | — |

### Utility
| Command | Purpose | Key flags |
|---------|---------|-----------|
| `roadtx describe` | Decode token claims | `-t` token (or stdin) |
| `roadtx decrypt` | Decrypt JWE tokens | — |
| `roadtx getscope` | Find clients holding a scope | `-s`, `--foci` |
| `roadtx getotp` | Generate TOTP from a seed | `<seed>` |
| `roadtx listaliases` | List client/resource aliases | — |
| `roadtx keepassauth` | Selenium auth from KeePass | `-c`, `-u`, `-kp`, `-kpp`, `-url`, `--keep-open` |
| `roadtx sharepointlogin` | Authenticate to SharePoint/OneDrive | `<token>`, `--host` |

### Common client (`-c`) and resource (`-r`) aliases
Clients: `azcli`, `msteams`, `msgraph` (as client where applicable), `office`, `broker`.
Resources: `msgraph`, `azrm`, `aadgraph`, `devicereg`. Use `roadtx listaliases` for the full list.
