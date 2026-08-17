# Standards and Framework Mapping — Generating and Analyzing SBOMs

## NIST Cybersecurity Framework 2.0

| ID | Name | Rationale |
|----|------|-----------|
| ID.AM-08 | Systems, hardware, software, services, and data are managed throughout their life cycles | SBOMs are the authoritative software-component inventory that underpins lifecycle asset management and supply-chain risk visibility. |

## MITRE ATT&CK

| ID | Name | Rationale |
|----|------|-----------|
| T1195.001 | Supply Chain Compromise: Compromise Software Dependencies and Development Tools | SBOM generation plus vulnerability correlation surfaces vulnerable/compromised dependencies, directly countering this technique. |

## SBOM Standards and Authorities

| Standard / Authority | Role |
|----------------------|------|
| CycloneDX (OWASP) | Security-focused SBOM format (VEX, vulnerabilities) |
| SPDX (ISO/IEC 5962) | Licensing/provenance-focused SBOM format |
| CISA SBOM Minimum Elements | Baseline required SBOM fields |
| US Executive Order 14028 | Mandates SBOMs for software sold to the US government |
| NTIA "Framing Software Component Transparency" | Foundational SBOM guidance |

## Supporting References

- CISA SBOM: https://www.cisa.gov/sbom
- CycloneDX: https://cyclonedx.org/
- SPDX: https://spdx.dev/
- Syft: https://github.com/anchore/syft
- Grype: https://github.com/anchore/grype
- Sigstore Cosign: https://github.com/sigstore/cosign
