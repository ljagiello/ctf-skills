# API Reference: Okta SCIM 2.0 Provisioning

## Libraries Used

| Library | Purpose |
|---------|---------|
| `requests` | HTTP client for SCIM 2.0 and Okta Management API |
| `json` | Parse SCIM user and group payloads |
| `os` | Read `OKTA_DOMAIN`, `OKTA_API_TOKEN`, `SCIM_BASE_URL` |

## Installation

```bash
pip install requests
```

## Authentication

### Okta Management API
```python
import requests
import os

OKTA_DOMAIN = os.environ["OKTA_DOMAIN"]  # e.g., "dev-12345.okta.com"
OKTA_TOKEN = os.environ["OKTA_API_TOKEN"]
headers = {
    "Authorization": f"SSWS {OKTA_TOKEN}",
    "Content-Type": "application/json",
    "Accept": "application/json",
}
```

### SCIM 2.0 Endpoint (Bearer Token)
```python
SCIM_URL = os.environ["SCIM_BASE_URL"]  # e.g., "https://app.example.com/scim/v2"
scim_headers = {
    "Authorization": f"Bearer {os.environ['SCIM_TOKEN']}",
    "Content-Type": "application/scim+json",
}
```

## SCIM 2.0 Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/scim/v2/Users` | List users with filtering |
| GET | `/scim/v2/Users/{id}` | Get a specific user |
| POST | `/scim/v2/Users` | Create a new user |
| PUT | `/scim/v2/Users/{id}` | Replace a user (full update) |
| PATCH | `/scim/v2/Users/{id}` | Partial user update (activate/deactivate) |
| DELETE | `/scim/v2/Users/{id}` | Delete a user |
| GET | `/scim/v2/Groups` | List groups |
| GET | `/scim/v2/Groups/{id}` | Get a specific group |
| POST | `/scim/v2/Groups` | Create a group |
| PATCH | `/scim/v2/Groups/{id}` | Update group membership |
| GET | `/scim/v2/ServiceProviderConfig` | SCIM service capabilities |
| GET | `/scim/v2/Schemas` | Supported SCIM schemas |
| GET | `/scim/v2/ResourceTypes` | Available resource types |

## Core Operations

### List SCIM Users with Filtering
```python
resp = requests.get(
    f"{SCIM_URL}/Users",
    headers=scim_headers,
    params={
        "filter": 'userName eq "alice@example.com"',
        "startIndex": 1,
        "count": 100,
    },
    timeout=30,
)
users = resp.json()
for user in users.get("Resources", []):
    print(f"{user['userName']} — active: {user.get('active', True)}")
```

### Create a User
```python
new_user = {
    "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
    "userName": "bob@example.com",
    "name": {"givenName": "Bob", "familyName": "Smith"},
    "emails": [
        {"value": "bob@example.com", "type": "work", "primary": True}
    ],
    "active": True,
}
resp = requests.post(
    f"{SCIM_URL}/Users",
    headers=scim_headers,
    json=new_user,
    timeout=30,
)
created = resp.json()
user_id = created["id"]
```

### Deactivate a User (PATCH)
```python
deactivate_payload = {
    "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
    "Operations": [
        {"op": "Replace", "path": "active", "value": False}
    ],
}
resp = requests.patch(
    f"{SCIM_URL}/Users/{user_id}",
    headers=scim_headers,
    json=deactivate_payload,
    timeout=30,
)
```

### Manage Group Membership
```python
add_member = {
    "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
    "Operations": [
        {
            "op": "Add",
            "path": "members",
            "value": [{"value": user_id, "display": "bob@example.com"}],
        }
    ],
}
resp = requests.patch(
    f"{SCIM_URL}/Groups/{group_id}",
    headers=scim_headers,
    json=add_member,
    timeout=30,
)
```

## Okta Management API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/apps` | List applications |
| GET | `/api/v1/apps/{appId}/users` | List users assigned to an app |
| POST | `/api/v1/apps/{appId}/users` | Assign user to app |
| GET | `/api/v1/users` | List Okta users |
| POST | `/api/v1/users/{userId}/lifecycle/deactivate` | Deactivate user |

### List Okta Applications with SCIM Provisioning
```python
resp = requests.get(
    f"https://{OKTA_DOMAIN}/api/v1/apps",
    headers=headers,
    params={"filter": 'status eq "ACTIVE"', "limit": 50},
    timeout=30,
)
for app in resp.json():
    features = app.get("features", [])
    if "PUSH_NEW_USERS" in features or "PUSH_PROFILE_UPDATES" in features:
        print(f"SCIM-enabled: {app['label']} — features: {features}")
```

## Output Format

```json
{
  "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
  "totalResults": 42,
  "startIndex": 1,
  "itemsPerPage": 100,
  "Resources": [
    {
      "id": "2819c223-7f76-453a-919d-ab1234567890",
      "userName": "alice@example.com",
      "name": {"givenName": "Alice", "familyName": "Johnson"},
      "active": true,
      "emails": [{"value": "alice@example.com", "type": "work", "primary": true}]
    }
  ]
}
```
