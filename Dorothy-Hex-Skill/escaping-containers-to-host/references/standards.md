# Standards and References - Container Escape to Host

## MITRE ATT&CK

| Technique ID | Name | Tactic | Rationale |
|--------------|------|--------|-----------|
| T1611 | Escape to Host | Privilege Escalation | The core technique: breaking container isolation to execute on the host kernel/namespace. |
| T1610 | Deploy Container | Defense Evasion / Execution | Docker-socket escapes spawn a new privileged container mounting host root. |
| T1613 | Container and Resource Discovery | Discovery | Enumerating caps, namespaces, mounts to find a viable escape path. |
| T1068 | Exploitation for Privilege Escalation | Privilege Escalation | runC CVE exploitation (CVE-2024-21626, CVE-2025-31133/52565/52881). |

## NIST CSF 2.0

| ID | Name | Rationale |
|----|------|-----------|
| PR.PS-01 | Configuration management practices are established and applied | Hardening container runtime/pod config (no `--privileged`, no socket mount, no hostPath `/`) and keeping runC patched is the primary control against breakout. |

## Real CVEs Covered

| CVE | Runtime | Fixed In | Note |
|-----|---------|----------|------|
| CVE-2024-21626 | runC <=1.1.11 | runC 1.1.12, containerd 1.6.28/1.7.13, Docker 25.0.2 | "Leaky Vessels" host-cwd fd leak |
| CVE-2025-31133 | runC <=1.2.7/1.3.2/1.4.0-rc.2 | runC 1.2.8/1.3.3/1.4.0-rc.3 | `/dev/null` masked-path race |
| CVE-2025-52565 | runC <=1.2.7/1.3.2/1.4.0-rc.2 | runC 1.2.8/1.3.3/1.4.0-rc.3 | `/dev/console` bind-mount race |
| CVE-2025-52881 | runC <=1.2.7/1.3.2/1.4.0-rc.2 | runC 1.2.8/1.3.3/1.4.0-rc.3 | Arbitrary procfs write redirection |

## Official Resources

- runC security advisories: https://github.com/opencontainers/runc/security/advisories
- GHSA-cgrx-mc8f-2prm (2025 write gadgets): https://github.com/opencontainers/runc/security/advisories/GHSA-cgrx-mc8f-2prm
- GHSA-9493-h29p-rfm2 (2025 masked-path): https://github.com/opencontainers/runc/security/advisories/GHSA-9493-h29p-rfm2
- Palo Alto Leaky Vessels: https://www.paloaltonetworks.com/blog/cloud-security/leaky-vessels-vulnerabilities-container-escape/
- Sysdig runc 2025 escape blog: https://www.sysdig.com/blog/runc-container-escape-vulnerabilities
- HackTricks Docker Breakout: https://book.hacktricks.xyz/linux-hardening/privilege-escalation/docker-security/docker-breakout-privilege-escalation
