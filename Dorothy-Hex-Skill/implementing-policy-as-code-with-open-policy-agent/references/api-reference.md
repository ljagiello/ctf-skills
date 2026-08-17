# API Reference: Open Policy Agent (OPA) Policy-as-Code

## Libraries Used

| Library | Purpose |
|---------|---------|
| `requests` | HTTP client for OPA REST API |
| `json` | Parse OPA decision responses |
| `subprocess` | Run `opa eval` and `opa test` CLI commands |
| `yaml` | Parse Kubernetes admission review objects |

## Installation

```bash
# OPA binary
curl -L -o opa https://openpolicyagent.org/downloads/latest/opa_linux_amd64_static
chmod 755 opa && sudo mv opa /usr/local/bin/

# Python dependencies
pip install requests pyyaml
```

## OPA REST API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| PUT | `/v1/policies/{id}` | Create or update a policy module |
| GET | `/v1/policies/{id}` | Retrieve a policy module |
| DELETE | `/v1/policies/{id}` | Delete a policy module |
| GET | `/v1/policies` | List all policy modules |
| PUT | `/v1/data/{path}` | Create or overwrite a document |
| GET | `/v1/data/{path}` | Evaluate a rule or retrieve data |
| POST | `/v1/data/{path}` | Evaluate a rule with input |
| PATCH | `/v1/data/{path}` | Patch a data document |
| POST | `/v1/query` | Execute ad-hoc Rego query |
| POST | `/v1/compile` | Partially evaluate a query |
| GET | `/health` | Health check (liveness) |
| GET | `/health?bundles` | Health check including bundle status |

## Core Operations

### Upload a Rego Policy
```python
import requests
import os

OPA_URL = os.environ.get("OPA_URL", "http://localhost:8181")

policy_rego = """
package authz

default allow := false

allow if {
    input.user.role == "admin"
}

allow if {
    input.user.role == "editor"
    input.action == "read"
}
"""

resp = requests.put(
    f"{OPA_URL}/v1/policies/authz",
    data=policy_rego,
    headers={"Content-Type": "text/plain"},
    timeout=10,
)
resp.raise_for_status()
```

### Evaluate a Policy Decision
```python
decision_input = {
    "input": {
        "user": {"role": "editor", "name": "alice"},
        "action": "read",
        "resource": "/api/reports",
    }
}

resp = requests.post(
    f"{OPA_URL}/v1/data/authz/allow",
    json=decision_input,
    timeout=10,
)
result = resp.json()
allowed = result.get("result", False)  # True
```

### Upload Data Documents
```python
role_permissions = {
    "admin": ["read", "write", "delete", "admin"],
    "editor": ["read", "write"],
    "viewer": ["read"],
}

resp = requests.put(
    f"{OPA_URL}/v1/data/roles",
    json=role_permissions,
    timeout=10,
)
```

### List All Policies
```python
resp = requests.get(f"{OPA_URL}/v1/policies", timeout=10)
policies = resp.json().get("result", [])
for p in policies:
    print(f"  {p['id']} — {len(p.get('raw', ''))} bytes")
```

## OPA CLI Reference

```bash
# Evaluate a policy locally
opa eval -i input.json -d policy.rego "data.authz.allow"

# Run Rego unit tests
opa test ./policies/ -v

# Check policy syntax
opa check policy.rego

# Format Rego files
opa fmt -w policy.rego

# Start OPA as a server
opa run --server --addr :8181 ./policies/ ./data/

# Build an OPA bundle
opa build -b ./policies/ -o bundle.tar.gz
```

## Kubernetes Gatekeeper Integration

```yaml
apiVersion: templates.gatekeeper.sh/v1
kind: ConstraintTemplate
metadata:
  name: k8srequiredlabels
spec:
  crd:
    spec:
      names:
        kind: K8sRequiredLabels
      validation:
        openAPIV3Schema:
          type: object
          properties:
            labels:
              type: array
              items:
                type: string
  targets:
    - target: admission.k8s.gatekeeper.sh
      rego: |
        package k8srequiredlabels
        violation[{"msg": msg}] {
          provided := {l | input.review.object.metadata.labels[l]}
          required := {l | l := input.parameters.labels[_]}
          missing := required - provided
          count(missing) > 0
          msg := sprintf("Missing required labels: %v", [missing])
        }
```

## Output Format

```json
{
  "decision_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "result": true,
  "policy": "data.authz.allow",
  "input": {
    "user": {"role": "admin"},
    "action": "delete",
    "resource": "/api/users/42"
  }
}
```
