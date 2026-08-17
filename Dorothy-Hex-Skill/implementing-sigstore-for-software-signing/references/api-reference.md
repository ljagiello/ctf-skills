# API Reference: Sigstore Software Signing Agent

## Overview

Automates Sigstore-based software signing and verification using Cosign keyless signing, Rekor transparency log queries, and Fulcio certificate authority integration. Wraps the Cosign CLI and Rekor REST API to sign artifacts, verify signatures against expected OIDC identities, search the transparency log, and audit signing events end-to-end.

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| requests | >=2.28 | HTTP requests to Rekor REST API |
| cosign | >=2.4 (CLI) | Signing and verification of blobs and container images |
| rekor-cli | >=1.3 (CLI, optional) | Direct Rekor entry verification with inclusion proofs |

## CLI Usage

```bash
# Check cosign installation and Rekor connectivity
python agent.py check

# Sign a file blob (triggers OIDC auth flow)
python agent.py sign-blob myfile.tar.gz --bundle myfile.sigstore.json

# Verify a signed blob
python agent.py verify-blob myfile.tar.gz --bundle myfile.sigstore.json \
  --cert-identity user@example.com \
  --cert-oidc-issuer https://accounts.google.com

# Sign a container image (use digest, not tag)
python agent.py sign-container registry.io/myimage@sha256:abc123...

# Verify a container image
python agent.py verify-container registry.io/myimage@sha256:abc123... \
  --cert-identity user@example.com \
  --cert-oidc-issuer https://accounts.google.com

# Search Rekor by artifact hash
python agent.py search-rekor --hash <sha256-hash>

# Search Rekor by signer email
python agent.py search-rekor --email user@example.com

# Search Rekor by file (computes hash automatically)
python agent.py search-rekor --file myfile.tar.gz

# Retrieve a specific Rekor entry
python agent.py get-rekor-entry <uuid>

# Get Rekor transparency log state
python agent.py log-info

# Full audit of a signing event
python agent.py audit --file myfile.tar.gz \
  --cert-identity user@example.com \
  --cert-oidc-issuer https://accounts.google.com

# All commands support custom output path
python agent.py sign-blob myfile.tar.gz --output custom_report.json
```

## Arguments

| Argument | Required | Description |
|----------|----------|-------------|
| `command` | Yes | Subcommand: `check`, `sign-blob`, `verify-blob`, `sign-container`, `verify-container`, `search-rekor`, `get-rekor-entry`, `log-info`, `audit` |
| `--bundle` | Varies | Path to sigstore bundle file (required for verify-blob, optional for sign-blob) |
| `--cert-identity` | For verify | Expected signer identity (email or workflow URL) |
| `--cert-oidc-issuer` | For verify | Expected OIDC issuer URL (e.g., `https://accounts.google.com`) |
| `--rekor-url` | No | Custom Rekor server URL (default: `https://rekor.sigstore.dev`) |
| `--output` | No | Output report path (default: `sigstore_report.json`) |

## Key Functions

### `sign_blob_keyless(filepath, bundle_path)`
Signs a file using Cosign keyless signing. Triggers OIDC authentication, obtains a Fulcio certificate, records the event in Rekor, and outputs a sigstore bundle containing the signature, certificate, and inclusion proof.

### `verify_blob_keyless(filepath, bundle_path, cert_identity, cert_oidc_issuer)`
Verifies a signed blob against the expected certificate identity and OIDC issuer. Validates the certificate chain, Rekor inclusion proof, and signature integrity.

### `sign_container_keyless(image_uri)`
Signs a container image by digest using keyless signing. The signature is stored as an OCI artifact attached to the image in the registry.

### `verify_container_keyless(image_uri, cert_identity, cert_oidc_issuer)`
Verifies container image signatures and returns parsed verification details including all matching signatures.

### `search_rekor_by_hash(artifact_hash, rekor_url)`
Queries the Rekor REST API `POST /api/v1/index/retrieve` with a SHA-256 hash to find all log entries for an artifact.

### `search_rekor_by_email(email, rekor_url)`
Queries Rekor for all signing events associated with an email identity.

### `get_rekor_entry(uuid, rekor_url)`
Retrieves a specific Rekor log entry by UUID from `GET /api/v1/log/entries/<uuid>`, parsing log index, integrated time, inclusion proof presence, and signed entry timestamp.

### `get_rekor_log_info(rekor_url)`
Retrieves the current Rekor log state from `GET /api/v1/log`, including tree size, root hash, and signed tree head.

### `audit_signing_event(filepath, image_uri, cert_identity, cert_oidc_issuer, rekor_url)`
Performs a comprehensive audit combining artifact hash computation, Rekor log search, entry detail retrieval, inclusion proof verification, and signature verification into a single pass/fail report.

## Rekor REST API Endpoints Used

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/api/v1/log` | GET | Retrieve current log state (tree size, root hash) |
| `/api/v1/index/retrieve` | POST | Search entries by hash or email |
| `/api/v1/log/entries/<uuid>` | GET | Retrieve a specific log entry |

## Common OIDC Issuers

| Provider | Issuer URL |
|----------|-----------|
| Google | `https://accounts.google.com` |
| GitHub Actions | `https://token.actions.githubusercontent.com` |
| Microsoft | `https://login.microsoftonline.com` |
| GitLab | `https://gitlab.com` |
