# SMB Null and Guest Session Enumeration

## When this applies

- Target has SMB / NetBIOS exposed (TCP 139/445, UDP 137/138).
- Anonymous (null session) or guest access is allowed for share listing, RPC queries, or RID cycling.
- Goal is to enumerate users, groups, shares, and policies without valid credentials.

## Technique

SMB allows two unauthenticated identities: **null session** (`-U "" -p ""`) and **guest** (`-U guest -p ""`). They expose different RPC subsets — always test both. From either, enumerate via `smbclient`/`rpcclient`/`enum4linux-ng`/`netexec`. SAMR RID cycling is the highest-yield technique when null bind is partially restricted.

## Steps

### 1. Test null and guest separately

```bash
# Null session
smbclient -L //TARGET -N
nxc smb TARGET -u "" -p "" --shares

# Guest (often allows reads where null gets ACCESS_DENIED)
smbclient -L //TARGET -U guest%
nxc smb TARGET -u "guest" -p "" --shares
```

Always try BOTH — they yield different results. Guest often has READ on shares where null gets ACCESS_DENIED.

### 2. Built-in account empty-password check

Common Windows accounts that may have empty password (especially on lab/test systems):

```bash
smbclient -L //TARGET -U Administrator -N
smbclient //TARGET/C$ -U Administrator -N
# Also try: Guest, admin, sa
```

### 3. enum4linux-ng (full RPC enumeration)

```bash
# Full enumeration: users, groups, shares, password policy, OS info
enum4linux-ng -A TARGET

# Just user enumeration (RID cycling)
enum4linux-ng -R TARGET

# Just shares
enum4linux-ng -S TARGET
```

Output sections:
- `users` — full user list with RID, comment, full name, last login
- `groups` — local + domain groups with members
- `shares` — share name, comment, ACL hint
- `policy` — password complexity / lockout / expiration

### 4. SAMR RID cycling

Highest-yield when null bind is denied for users but `guest` is enabled. SAMR over SMB returns every RID's name + group membership even when no shares are readable.

```bash
nxc smb TARGET -u guest -p '' --rid-brute 5000
nxc smb TARGET -u '' -p '' --rid-brute 5000
```

Output feeds AS-REP roast / Kerberoast / web-app login lists.

RID layout to expect:
- 500 = Administrator
- 501 = Guest
- 1000+ = local users / domain users (created in order)

### 5. rpcclient null session

```bash
rpcclient -U "" -N TARGET

# Inside the rpcclient shell:
srvinfo                    # OS + server version
enumdomusers               # list users
querydominfo              # password policy
enumdomgroups             # groups
enumalsgroups domain      # alias groups
queryuser RID             # detail per user
lookupnames Administrator # name → SID
lookupsids S-1-5-21-...   # SID → name
```

### 6. NetBIOS name enumeration

```bash
# nbtscan
nbtscan TARGET_RANGE

# nmblookup (single host)
nmblookup -A TARGET
```

NetBIOS names reveal the workgroup/domain name and the host's role (e.g. `<00>` workstation, `<20>` server service, `<1B>` domain master browser).

### 7. CrackMapExec / NetExec verbs

```bash
# Default check + version
nxc smb TARGET

# Authenticated user enumeration after foothold
nxc smb TARGET -u user -p pass --users
nxc smb TARGET -u user -p pass --groups
nxc smb TARGET -u user -p pass --shares
nxc smb TARGET -u user -p pass --pass-pol
nxc smb TARGET -u user -p pass --loggedon-users
```

## Verifying success

- User list with RIDs, ideally with `--rid-brute` finding domain users.
- Share list with ACL hints (READ/WRITE).
- Password policy (length, complexity, lockout) — used to plan password spraying.
- OS / domain / workgroup information.

## Common pitfalls

- **Modern Windows defaults disable null sessions** — Server 2003+ requires `RestrictAnonymous` lowering. Don't assume null works just because port 445 is open.
- **`smbclient -N` vs `-U guest%`** — `-N` means "no auth" (null), `-U guest%` means "guest user with empty password". Different code paths.
- **`enum4linux` (legacy Perl)** is slower and less complete than `enum4linux-ng` (Python rewrite). Always prefer the `-ng` variant.
- **SMB1 is often disabled** on modern Windows. `smbclient` defaults to SMB2/3 — use `-m NT1` to force SMB1 if testing legacy systems.
- **Read-only RID bruteforce**: `--rid-brute` only enumerates names, not credentials. Pair with AS-REP roasting / Kerberoasting for credential discovery.
- **Domain controllers vs workstations**: DC null sessions return domain users; workstation null sessions return only local accounts.

## Tools

- smbclient (samba client suite)
- rpcclient (samba RPC client)
- enum4linux-ng (Python rewrite, comprehensive)
- netexec / crackmapexec (modern AD enumeration multi-tool)
- nbtscan, nmblookup (NetBIOS name lookups)
- impacket (`SMBConnection`, scripts in `examples/`)
- nmap NSE: `smb-os-discovery`, `smb-enum-shares`, `smb-enum-users`, `smb-vuln-*`
