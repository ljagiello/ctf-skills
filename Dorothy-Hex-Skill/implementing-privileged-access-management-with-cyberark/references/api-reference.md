# API Reference: CyberArk Privileged Access Management

## Libraries Used

| Library | Purpose |
|---------|---------|
| `requests` | HTTP client for CyberArk PVWA REST API |
| `json` | Parse CyberArk JSON responses |
| `os` | Read environment variables for credentials |
| `urllib.parse` | URL-encode safe and account query parameters |

## Installation

```bash
pip install requests
```

## Authentication

CyberArk PVWA REST API requires session token authentication:

```python
import requests
import os

PVWA_URL = os.environ.get("CYBERARK_URL", "https://pvwa.example.com")

# CyberArk credential authentication
resp = requests.post(
    f"{PVWA_URL}/PasswordVault/api/auth/cyberark/logon",
    json={
        "username": os.environ["CYBERARK_USER"],
        "password": os.environ["CYBERARK_PASS"],
    },
    timeout=30,
    verify=True,
)
session_token = resp.json()  # Returns session token string
headers = {"Authorization": session_token}
```

### LDAP Authentication
```python
resp = requests.post(
    f"{PVWA_URL}/PasswordVault/api/auth/ldap/logon",
    json={"username": user, "password": password},
    timeout=30,
    verify=True,
)
```

### RADIUS Authentication
```python
resp = requests.post(
    f"{PVWA_URL}/PasswordVault/api/auth/radius/logon",
    json={"username": user, "password": otp_code},
    timeout=30,
    verify=True,
)
```

## REST API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/auth/{method}/logon` | Authenticate (cyberark, ldap, radius) |
| POST | `/api/auth/logoff` | End session |
| GET | `/api/Accounts` | List privileged accounts |
| GET | `/api/Accounts/{id}` | Get account details |
| POST | `/api/Accounts` | Add a new privileged account |
| PATCH | `/api/Accounts/{id}` | Update account properties |
| DELETE | `/api/Accounts/{id}` | Delete an account |
| POST | `/api/Accounts/{id}/Password/Retrieve` | Retrieve account password |
| POST | `/api/Accounts/{id}/Change` | Trigger password change |
| POST | `/api/Accounts/{id}/Reconcile` | Reconcile password |
| POST | `/api/Accounts/{id}/Verify` | Verify password on target |
| GET | `/api/Safes` | List safes |
| GET | `/api/Safes/{name}` | Get safe details |
| POST | `/api/Safes` | Create a safe |
| GET | `/api/Safes/{name}/Members` | List safe members |
| POST | `/api/Safes/{name}/Members` | Add safe member |
| GET | `/api/Platforms` | List platforms |
| GET | `/api/ComponentsMonitoringDetails/{component}` | System health |

## Core Operations

### List Privileged Accounts
```python
resp = requests.get(
    f"{PVWA_URL}/PasswordVault/api/Accounts",
    headers=headers,
    params={"search": "Linux", "limit": 100},
    timeout=30,
    verify=True,
)
accounts = resp.json()
for acct in accounts.get("value", []):
    print(f"{acct['name']} — platform: {acct['platformId']}, safe: {acct['safeName']}")
```

### Retrieve a Password (Check-Out)
```python
resp = requests.post(
    f"{PVWA_URL}/PasswordVault/api/Accounts/{account_id}/Password/Retrieve",
    headers=headers,
    json={"reason": "Automated security audit"},
    timeout=30,
    verify=True,
)
password = resp.text  # Returns the password as plain text
```

### List Safes and Audit Permissions
```python
resp = requests.get(
    f"{PVWA_URL}/PasswordVault/api/Safes",
    headers=headers,
    params={"limit": 200},
    timeout=30,
    verify=True,
)
for safe in resp.json().get("value", []):
    members_resp = requests.get(
        f"{PVWA_URL}/PasswordVault/api/Safes/{safe['safeName']}/Members",
        headers=headers,
        timeout=30,
        verify=True,
    )
    members = members_resp.json().get("value", [])
    print(f"Safe: {safe['safeName']} — {len(members)} members")
```

### Trigger Password Rotation
```python
resp = requests.post(
    f"{PVWA_URL}/PasswordVault/api/Accounts/{account_id}/Change",
    headers=headers,
    json={"ChangeEntireGroup": False},
    timeout=60,
    verify=True,
)
```

### Logoff
```python
requests.post(
    f"{PVWA_URL}/PasswordVault/api/auth/logoff",
    headers=headers,
    timeout=10,
    verify=True,
)
```

## Output Format

```json
{
  "value": [
    {
      "id": "42_8",
      "name": "root-linux-prod01",
      "address": "10.0.1.50",
      "userName": "root",
      "platformId": "UnixSSH",
      "safeName": "LinuxRoot",
      "secretType": "password",
      "platformAccountProperties": {
        "LogonDomain": "",
        "Port": "22"
      },
      "secretManagement": {
        "automaticManagementEnabled": true,
        "lastModifiedTime": 1705334400
      }
    }
  ],
  "count": 1
}
```
