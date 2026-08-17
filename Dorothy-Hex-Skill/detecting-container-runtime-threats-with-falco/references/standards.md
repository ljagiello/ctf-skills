# Standards and References - Falco Container Runtime Detection

## MITRE ATT&CK

| Technique ID | Name | Tactic | Rationale |
|--------------|------|--------|-----------|
| T1611 | Escape to Host | Privilege Escalation | Falco rules detect the syscalls/files used in container breakout (release_agent, setns, privileged mount). |
| T1059.004 | Command and Scripting Interpreter: Unix Shell | Execution | Reverse-shell rule detects shells wired to network sockets in containers. |
| T1610 | Deploy Container | Defense Evasion / Execution | docker.sock access rule detects daemon-API container spawning. |
| T1543 | Create or Modify System Process | Persistence | Anomalous process/service creation inside containers. |
| T1071.001 | Application Layer Protocol: Web Protocols | Command and Control | Unexpected outbound connections from containers. |

## NIST CSF 2.0

| ID | Name | Rationale |
|----|------|-----------|
| DE.CM-01 | Networks and network services are monitored to find potentially adverse events | Falco continuously monitors syscall and network behavior at runtime, surfacing adverse container activity. |

## Official Resources

- Falco documentation: https://falco.org/docs/
- Custom ruleset guide: https://falco.org/docs/concepts/rules/custom-ruleset/
- Default rules: https://falco.org/docs/reference/rules/default-rules/
- falcosecurity/rules repo: https://github.com/falcosecurity/rules/blob/main/rules/falco_rules.yaml
- Falco Helm chart README: https://github.com/falcosecurity/charts/blob/master/charts/falco/README.md
- falcoctl: https://github.com/falcosecurity/falcoctl
- Falcosidekick: https://github.com/falcosecurity/falcosidekick

## Key Research

- Sysdig: "Detecting CVE-2025-22224 with Falco"
- Falco supported fields reference: https://falco.org/docs/reference/rules/supported-fields/
