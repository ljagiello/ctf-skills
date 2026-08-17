# Standards and Framework Mapping

## MITRE ATT&CK

| ID | Name | Rationale |
|----|------|-----------|
| T1195.002 | Supply Chain Compromise: Compromise Software Supply Chain | Core technique — trojanized package shipped through the npm registry. |
| T1059.007 | Command and Scripting Interpreter: JavaScript | Install scripts and module code run attacker JavaScript on the victim. |
| T1552.001 | Unsecured Credentials: Credentials In Files | Packages harvest `.npmrc`, `.env`, SSH keys, and cloud credential files. |
| T1041 | Exfiltration Over C2 Channel | Stolen data is POSTed to attacker HTTP(S) endpoints. |
| T1027 | Obfuscated Files or Information | base64/eval/hex obfuscation conceals the payload. |

## NIST Cybersecurity Framework 2.0

| ID | Name | Rationale |
|----|------|-----------|
| DE.CM-09 | Computing hardware and software, runtime environments, and their data are monitored to find potentially adverse events | Static + dynamic triage of npm packages and lockfiles is the monitoring control that surfaces malicious dependencies. |

## Supporting Standards

- **OWASP Top 10 CI/CD Security Risks — CICD-SEC-03: Dependency Chain Abuse.** Malicious package ingestion is a primary dependency-chain abuse vector.
- **NIST SP 800-218 (SSDF) — PW.4 / PS.3.** Reuse and verify the integrity of acquired software components; triaging packages satisfies the verification practice.
- **SLSA provenance.** Verifying build provenance reduces the chance of consuming a tampered or republished package.
