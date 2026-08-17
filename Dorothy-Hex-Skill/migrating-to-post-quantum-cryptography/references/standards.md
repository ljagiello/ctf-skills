# Standards and Framework Mapping

## NIST Cybersecurity Framework 2.0

| ID | Name | Rationale |
|----|------|-----------|
| PR.DS-02 | The confidentiality, integrity, and availability of data-in-transit are protected | Hybrid PQC key exchange (X25519MLKEM768) protects data in transit against harvest-now-decrypt-later attacks by a future CRQC. |

## MITRE ATT&CK

| ID | Name | Rationale |
|----|------|-----------|
| T1573 | Encrypted Channel | Migration hardens the encrypted channels protecting data in transit; cryptographic inventory of these channels also underpins detection of adversary encrypted C2. |
| T1573.001 | Encrypted Channel: Symmetric Cryptography | AES/symmetric ciphers — quantum-weakened by Grover and hardened via 256-bit keys. |
| T1573.002 | Encrypted Channel: Asymmetric Cryptography | RSA/ECDH — the asymmetric primitives broken by Shor's algorithm and replaced by ML-KEM. |

## NIST Post-Quantum Standards (finalized 13 Aug 2024)

| Standard | Algorithm | Former name | Purpose |
|----------|-----------|-------------|---------|
| FIPS 203 | ML-KEM (Module-Lattice KEM) | CRYSTALS-Kyber | Key encapsulation / establishment |
| FIPS 204 | ML-DSA (Module-Lattice DSA) | CRYSTALS-Dilithium | Primary digital signatures |
| FIPS 205 | SLH-DSA (Stateless Hash-based DSA) | SPHINCS+ | Conservative backup signatures |

## Migration Guidance

| Reference | Rationale |
|-----------|-----------|
| NIST SP 1800-38 (NCCoE, Migration to Post-Quantum Cryptography) | Crypto-discovery test plan, CBOM-driven inventory, and migration architecture across CI/CD, operational systems, and network services. |
| Mosca's inequality | Prioritization rule: migrate when data_lifetime + migration_time > time_to_CRQC. |
| CycloneDX 1.6 CBOM | Cryptography Bill of Materials object model for inventory and dependency tracking. |
