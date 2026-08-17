# API Reference: HashiCorp Vault Secrets Management

## Libraries Used

| Library | Purpose |
|---------|---------|
| `hvac` | Official Python client for HashiCorp Vault API |
| `requests` | HTTP fallback for direct Vault REST calls |
| `json` | Parse Vault JSON responses |
| `os` | Read `VAULT_ADDR` and `VAULT_TOKEN` environment variables |

## Installation

```bash
pip install hvac requests
```

## Authentication

### Token Authentication
```python
import hvac

client = hvac.Client(
    url=os.environ.get("VAULT_ADDR", "https://127.0.0.1:8200"),
    token=os.environ.get("VAULT_TOKEN"),
)
assert client.is_authenticated()
```

### AppRole Authentication
```python
client = hvac.Client(url=os.environ["VAULT_ADDR"])
resp = client.auth.approle.login(
    role_id=os.environ["VAULT_ROLE_ID"],
    secret_id=os.environ["VAULT_SECRET_ID"],
)
client.token = resp["auth"]["client_token"]
```

### Kubernetes Authentication
```python
with open("/var/run/secrets/kubernetes.io/serviceaccount/token") as f:
    jwt = f.read()
client.auth.kubernetes.login(role="my-role", jwt=jwt)
```

## Core API — KV Secrets Engine v2

### Write a Secret
```python
client.secrets.kv.v2.create_or_update_secret(
    path="myapp/database",
    secret={"username": "admin", "password": "s3cure!"},
    mount_point="secret",
)
```

### Read a Secret
```python
resp = client.secrets.kv.v2.read_secret_version(
    path="myapp/database",
    mount_point="secret",
)
data = resp["data"]["data"]  # {"username": "admin", "password": "s3cure!"}
```

### List Secrets
```python
resp = client.secrets.kv.v2.list_secrets(path="myapp/", mount_point="secret")
keys = resp["data"]["keys"]  # ["database", "api-keys", ...]
```

### Delete a Secret
```python
client.secrets.kv.v2.delete_metadata_and_all_versions(
    path="myapp/database",
    mount_point="secret",
)
```

## System Backend — Audit and Health

### Check Seal Status
```python
status = client.sys.read_seal_status()
# {"sealed": False, "t": 3, "n": 5, "progress": 0}
```

### List Auth Methods
```python
methods = client.sys.list_auth_methods()
# {"token/": {...}, "approle/": {...}, ...}
```

### List Enabled Secrets Engines
```python
engines = client.sys.list_mounted_secrets_engines()
```

### Enable Audit Device
```python
client.sys.enable_audit_device(
    device_type="file",
    options={"file_path": "/var/log/vault_audit.log"},
)
```

## Transit Secrets Engine — Encryption as a Service

### Encrypt Data
```python
import base64
plaintext_b64 = base64.b64encode(b"sensitive-data").decode()
resp = client.secrets.transit.encrypt_data(
    name="my-key",
    plaintext=plaintext_b64,
)
ciphertext = resp["data"]["ciphertext"]  # "vault:v1:..."
```

### Decrypt Data
```python
resp = client.secrets.transit.decrypt_data(
    name="my-key",
    ciphertext=ciphertext,
)
plaintext = base64.b64decode(resp["data"]["plaintext"])
```

## REST API Endpoints (Direct)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/v1/sys/health` | Health check and seal status |
| GET | `/v1/sys/seal-status` | Detailed seal status |
| POST | `/v1/auth/token/create` | Create new token |
| GET | `/v1/secret/data/{path}` | Read KV v2 secret |
| POST | `/v1/secret/data/{path}` | Write KV v2 secret |
| LIST | `/v1/secret/metadata/{path}` | List secrets at path |
| DELETE | `/v1/secret/metadata/{path}` | Permanently delete secret |
| POST | `/v1/transit/encrypt/{key}` | Encrypt with transit engine |
| POST | `/v1/transit/decrypt/{key}` | Decrypt with transit engine |

## Error Handling

```python
from hvac.exceptions import Forbidden, InvalidPath, VaultError

try:
    secret = client.secrets.kv.v2.read_secret_version(path="missing")
except InvalidPath:
    print("Secret path does not exist")
except Forbidden:
    print("Insufficient permissions — check Vault policy")
except VaultError as e:
    print(f"Vault error: {e}")
```

## Output Format

```json
{
  "request_id": "abc-123",
  "lease_id": "",
  "renewable": false,
  "data": {
    "data": {"username": "admin", "password": "s3cure!"},
    "metadata": {
      "created_time": "2025-01-15T10:30:00.000Z",
      "version": 3,
      "destroyed": false
    }
  }
}
```
