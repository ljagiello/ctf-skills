# Linux Authentication Logs

## When this applies

Investigating logon, sudo escalation, SSH key use, audit-events on a Linux system. Three canonical sources: `/var/log/auth.log` (Debian/Ubuntu) or `/var/log/secure` (RHEL), `journalctl -u sshd`, and the kernel audit subsystem (`/var/log/audit/audit.log`).

## Technique

Modern systemd-journal collects most logs centrally; many distros keep a text mirror in `/var/log/`. Audit produces structured records keyed by `type=` (USER_LOGIN, USER_AUTH, SYSCALL, EXECVE, USER_CMD). SSH activity also appears in `last`, `lastb` (bad logins), and `wtmp`/`btmp` binary records.

## Steps

1. SSH success/failure:
   ```bash
   grep -E 'Accepted|Failed' /var/log/auth.log | head
   journalctl -u ssh -u sshd --since "2024-09-01" --until "2024-09-02" | head
   ```
   Successful login:
   ```
   sshd[12345]: Accepted publickey for alice from 198.51.100.7 port 51234 ssh2: ED25519 SHA256:abc123...
   ```
   Brute-force pattern: many `Failed password for invalid user X` from same IP.
2. Login history (binary):
   ```bash
   last -F                                 # successful logins (utmp/wtmp)
   lastb -F                                # failed logins (btmp, root-readable)
   utmpdump /var/log/wtmp | head
   ```
3. Sudo usage:
   ```bash
   grep 'sudo:' /var/log/auth.log
   # USER : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/bash
   journalctl _COMM=sudo --since today
   ```
4. Audit (`auditd`) — high fidelity but verbose:
   ```bash
   ausearch -m USER_LOGIN -ts today
   ausearch -m USER_AUTH --start recent --interpret
   ausearch -k <rulekey> -i           # interpret syscalls into readable form
   aureport --auth                    # summary
   ```
   Useful preset rules to deploy:
   ```
   -w /etc/passwd -p wa -k passwd_changes
   -w /etc/sudoers -p wa -k sudoers_changes
   -a always,exit -F arch=b64 -S execve -k execve_audit
   ```
5. PAM-level failures (`pam_unix`, `pam_faillock`):
   ```bash
   grep pam_unix /var/log/auth.log | head
   grep pam_faillock /var/log/auth.log
   faillock --user alice
   ```
6. Cross-correlate SSH source IP, sudo escalation, and audit EXECVE for a single attacker session:
   ```bash
   # 1) Find SSH login window (start/end timestamps)
   # 2) ausearch --start 'HH:MM:SS today' --end 'HH:MM:SS today' -m EXECVE
   ```

## Verifying success

- SSH `Accepted` event timestamp matches `wtmp` `last` row for same user.
- Sudo COMMAND lines list every escalated action; corroborated by audit EXECVE.
- Failed-login counts from `lastb` agree with `aureport --auth --failed`.

## Common pitfalls

- `/var/log/auth.log` may be rotated/compressed (`auth.log.1`, `auth.log.2.gz`). Decompress before grepping.
- Some distros log only to journald (no text mirror). Use `journalctl --output=json` for stable parsing.
- `auditd` not enabled by default on minimal installs. If `audit.log` is missing, fall back to BPF (e.g. `bpftrace`, `tracee`) for live analysis only.
- Attackers often `truncate -s 0 /var/log/auth.log` or symlink to `/dev/null`. Check inode and journald for tampering.
- Container workloads: each container may have its own logs; pivot via `journalctl CONTAINER_NAME=foo` (systemd-nspawn) or per-runtime log driver.

## Tools

- `journalctl`, `last`, `lastb`, `utmpdump`
- `auditd` / `ausearch` / `aureport`
- `gnu-grep` / `ripgrep` (`rg`) for fast text scans
- `Sigma` Linux ruleset (`linux/auth/*.yml`) compatible with `chainsaw` and `hayabusa`
