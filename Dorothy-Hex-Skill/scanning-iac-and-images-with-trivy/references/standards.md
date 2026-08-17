# Standards and References — Scanning IaC and Images with Trivy

## NIST CSF 2.0

| ID | Name | Rationale |
|----|------|-----------|
| ID.RA-01 | Asset vulnerabilities are identified and recorded | Trivy enumerates CVEs, misconfigurations, and embedded secrets across images, IaC, and SBOMs, recording them for risk assessment and remediation tracking. |

## MITRE ATT&CK

| Technique ID | Name | Tactic | Rationale |
|--------------|------|--------|-----------|
| T1525 | Implant Internal Image | Persistence | Scanning images and SBOMs before they reach a registry detects vulnerable, secret-laden, or malicious layers an adversary could implant to persist across deployments. |

## Supporting Frameworks and Standards

- **CIS Benchmarks** — Trivy `misconfig` checks align with CIS Docker/Kubernetes hardening guidance.
- **CycloneDX / SPDX** — SBOM output formats supported for supply-chain transparency.
- **SARIF** — Static Analysis Results Interchange Format for code-scanning dashboards.
- **OWASP Top 10 (A06: Vulnerable and Outdated Components)** — Trivy directly addresses outdated/vulnerable dependency detection.

## Official Resources

- Trivy: https://github.com/aquasecurity/trivy
- Trivy Docs: https://trivy.dev/latest/docs/
- Trivy DB: https://github.com/aquasecurity/trivy-db
- trivy-action: https://github.com/aquasecurity/trivy-action
- Aqua Security: https://www.aquasec.com/products/trivy/
