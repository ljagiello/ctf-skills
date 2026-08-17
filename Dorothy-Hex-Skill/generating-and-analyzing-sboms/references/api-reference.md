# SBOM Toolchain Command Reference

## Syft (SBOM generation)

Source prefixes: `<image>` (default = container image), `dir:<path>`, `file:<path>`,
`registry:<image>`, `docker:<image>`, `oci-archive:<path>`.

| Flag / form | Purpose |
|-------------|---------|
| `-o <format>[=<file>]` | Output format and optional file |
| `--scope <squashed\|all-layers>` | Layer scope for images |
| `--exclude <glob>` | Exclude paths |
| `syft <src> -o table` | Human-readable summary |

Common `-o` formats: `cyclonedx-json`, `cyclonedx-xml`, `spdx-json`, `spdx` (tag-value), `syft-json`, `table`.

```bash
syft alpine:latest -o cyclonedx-json=alpine.cdx.json
syft dir:. -o spdx-json=app.spdx.json
syft myorg/app:1.4.2 -o cyclonedx-json=app.cdx.json -o spdx-json=app.spdx.json -o table
```

## Grype (vulnerability scanning)

Source prefixes: `sbom:<file>`, `<image>`, `dir:<path>`, `registry:<image>`.

| Flag | Purpose |
|------|---------|
| `-o <format>` | `table`, `json`, `cyclonedx`, `sarif` |
| `--fail-on <severity>` | Exit non-zero at/above severity (`low\|medium\|high\|critical`) |
| `--only-fixed` | Report only vulns with a fix available |
| `--add-cpes-if-none` | Improve matching for SBOMs lacking CPEs |
| `db update` | Update the vulnerability database |

```bash
grype sbom:app.cdx.json -o table
grype sbom:app.cdx.json -o json > app.vulns.json
grype sbom:app.cdx.json --only-fixed --fail-on critical
grype myorg/app:1.4.2 -o table
grype db update
```

## Cosign (signing / attestation)

| Command | Purpose |
|---------|---------|
| `cosign attest --key <key> --predicate <sbom> --type <type> <image>` | Attach signed SBOM attestation |
| `cosign verify-attestation --key <pub> --type <type> <image>` | Verify attestation |
| `cosign download attestation <image>` | Retrieve attached attestation |
| `cosign generate-key-pair` | Create signing keys |

`--type` values: `spdxjson`, `cyclonedx`, `slsaprovenance`, or a custom URI.
Keyless mode: set `COSIGN_EXPERIMENTAL=1` and omit `--key` (uses Fulcio/Rekor).

```bash
cosign attest --key cosign.key --predicate app.spdx.json --type spdxjson myorg/app:1.4.2
cosign verify-attestation --key cosign.pub --type spdxjson myorg/app:1.4.2
cosign download attestation myorg/app:1.4.2
```

## Policy file (`.grype.yaml`)

```yaml
only-fixed: true
fail-on-severity: high
ignore:
  - vulnerability: CVE-2024-0000   # documented, risk-accepted
```
