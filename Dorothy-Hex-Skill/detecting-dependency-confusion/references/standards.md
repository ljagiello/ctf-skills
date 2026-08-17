# Standards and Framework Mapping

## MITRE ATT&CK

| ID | Name | Rationale |
|----|------|-----------|
| T1195.001 | Supply Chain Compromise: Compromise Software Dependencies and Development Tools | Dependency confusion substitutes a malicious public package for a private dependency, compromising the dev/build toolchain. |
| T1195.002 | Supply Chain Compromise: Compromise Software Supply Chain | Covers the tainted build artifacts shipped downstream once confusion succeeds. |
| T1059.007 | Command and Scripting Interpreter: JavaScript | npm install lifecycle scripts run attacker JS during resolution. |
| T1071.001 | Application Layer Protocol: Web Protocols | Substituted packages exfiltrate stolen secrets over HTTP(S). |

## NIST Cybersecurity Framework 2.0

| ID | Name | Rationale |
|----|------|-----------|
| ID.RA-09 | The authenticity and integrity of hardware and software are assessed prior to acquisition and use | Detecting confusable names and pinning registries validates that resolved packages are the authentic internal artifacts, not public substitutes. |

## Supporting Standards

- **OWASP Top 10 CI/CD Security Risks — CICD-SEC-03: Dependency Chain Abuse.** Dependency confusion is the canonical example of dependency chain abuse; remediation guidance aligns with this control.
- **NIST SP 800-161r1 — Cybersecurity Supply Chain Risk Management Practices.** Provides organizational SCRM controls (C-SCRM) into which namespace governance and registry pinning fit.
- **SLSA (Supply-chain Levels for Software Artifacts).** Source/build provenance requirements reduce the blast radius of a successful substitution.
