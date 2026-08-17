# API Reference: FIDO2/WebAuthn Hardware Security Key Authentication Server

## Overview

Implements a complete WebAuthn relying party server with registration/authentication ceremonies, YubiKey enrollment, credential management, recovery codes, and audit logging. Built on python-fido2 and Flask, supporting both roaming authenticators (USB/NFC security keys) and platform authenticators (Windows Hello, Touch ID).

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| fido2 | >=2.0.0 | Yubico's python-fido2 library for WebAuthn relying party operations |
| flask | >=2.3 | HTTP server framework for API endpoints and session management |
| cryptography | >=41.0 | Cryptographic primitives used by python-fido2 |

Install with: `pip install fido2 flask cryptography`

## CLI Usage

```bash
# Development server on localhost (no TLS needed)
python agent.py --rp-id localhost --rp-name "My App" --port 5000

# Production with strict security settings
python agent.py --rp-id auth.example.com --rp-name "Example Corp" \
    --user-verification required --attestation direct --db prod_keys.db

# Verbose logging for debugging
python agent.py --rp-id localhost --rp-name "Test" -v
```

## Arguments

| Argument | Required | Description |
|----------|----------|-------------|
| `--rp-id` | No | Relying Party ID -- must match the application domain (default: localhost) |
| `--rp-name` | No | Relying Party display name shown in authenticator prompts (default: FIDO2 Demo) |
| `--host` | No | Server bind address (default: localhost) |
| `--port` | No | Server port (default: 5000) |
| `--db` | No | SQLite database path for credentials and users (default: webauthn.db) |
| `--attestation` | No | Attestation preference: none, indirect, direct, enterprise (default: none) |
| `--user-verification` | No | UV requirement: required, preferred, discouraged (default: preferred) |
| `-v, --verbose` | No | Enable debug logging |

## API Endpoints

### Registration

#### `POST /api/register/begin`
Start the WebAuthn registration ceremony.

**Request body:**
```json
{
  "username": "alice",
  "display_name": "Alice Smith",
  "resident_key": true
}
```

**Response:** PublicKeyCredentialCreationOptions (JSON-serialized)

#### `POST /api/register/complete`
Complete registration with the authenticator's response.

**Request body:** Serialized PublicKeyCredential from `navigator.credentials.create()`

**Response:**
```json
{
  "status": "OK",
  "recovery_codes": ["A1B2C3D4", "E5F6G7H8", ...],
  "message": "Save these recovery codes securely."
}
```

### Authentication

#### `POST /api/authenticate/begin`
Start the WebAuthn authentication ceremony.

**Request body:**
```json
{
  "username": "alice"
}
```
Omit `username` for discoverable credential (passwordless) flow.

**Response:** PublicKeyCredentialRequestOptions (JSON-serialized)

#### `POST /api/authenticate/complete`
Complete authentication with the authenticator's assertion.

**Request body:** Serialized PublicKeyCredential from `navigator.credentials.get()`

**Response:**
```json
{
  "status": "OK",
  "username": "alice"
}
```

### Key Management

#### `GET /api/keys`
List all registered security keys for the authenticated user.

#### `POST /api/keys/<id>/revoke`
Revoke a security key. Requires at least one remaining active credential.

#### `PUT /api/keys/<id>/label`
Update a key's display label.

### Recovery

#### `POST /api/recover`
Authenticate using a recovery code when all keys are unavailable.

**Request body:**
```json
{
  "username": "alice",
  "recovery_code": "A1B2C3D4"
}
```

### Admin

#### `GET /api/admin/stats`
Deployment statistics: total users, credentials, backup key adoption, authentication metrics.

#### `GET /api/admin/audit-log?limit=100`
Authentication event audit trail with timestamps, usernames, event types, and IP addresses.

## Key Functions

### User Management

#### `create_user(conn, username, display_name)`
Creates a user with a cryptographically random 32-byte user handle.

#### `get_user_by_username(conn, username)` / `get_user_by_handle(conn, user_handle)`
User lookups by username (standard flow) or user handle (discoverable credential flow).

### Credential Management

#### `store_credential(conn, user_id, credential_id, public_key, sign_count, ...)`
Persists a WebAuthn credential with AAGUID, label, transport hints, and discoverable flag.

#### `get_user_credentials(conn, user_id)`
Retrieves all active (non-revoked) credentials for a user.

#### `revoke_credential(conn, credential_db_id, user_id)`
Soft-revokes a credential. Prevents revocation of the last remaining credential.

#### `update_sign_count(conn, credential_id, new_count)`
Updates sign count and last-used timestamp after successful authentication. Sign count regression is logged as a security event (possible cloned key).

### Recovery

#### `generate_recovery_codes(conn, user_id, count=8)`
Generates 8 one-time recovery codes (stored as SHA-256 hashes). Previous codes are invalidated.

#### `verify_recovery_code(conn, user_id, code)`
Verifies and consumes a recovery code (single-use).

### Helpers

#### `build_credential_descriptors(creds)`
Converts stored credentials to `PublicKeyCredentialDescriptor` list for WebAuthn ceremonies.

#### `reconstruct_credential_data(creds)`
Rebuilds `AttestedCredentialData` objects from database records for python-fido2 verification.

## Database Schema

| Table | Purpose |
|-------|---------|
| `users` | User accounts with random user handles, usernames, and passkey-only flag |
| `credentials` | WebAuthn credentials with public keys, sign counts, AAGUIDs, and revocation status |
| `auth_events` | Audit log of all registration, authentication, revocation, and recovery events |
| `recovery_codes` | Hashed one-time recovery codes with usage tracking |

## Security Features

| Feature | Implementation |
|---------|---------------|
| Phishing resistance | Origin binding via WebAuthn RP ID verification |
| Clone detection | Sign count validation with regression warnings |
| Recovery codes | SHA-256 hashed, single-use, auto-invalidated on regeneration |
| Session security | Secure, HttpOnly, SameSite=Strict cookies |
| Key revocation | Soft delete with minimum-one-key enforcement |
| Audit trail | All auth events logged with IP, user agent, and timestamp |
| Attestation verification | Configurable attestation preference for enterprise key verification |
