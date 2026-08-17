# Password Generation & Credential Management

Quick reference for generating policy-compliant test passwords and managing credentials during pentests.

## Use cases

- Account creation flows that require complex passwords.
- Bulk test-account provisioning.
- Storing valid credentials between test phases.
- Exporting to wordlists for reuse / spray testing.

## PasswordGenerator

### Generate by length / complexity

```python
import secrets, string

def gen_password(length=16, upper=True, lower=True, digits=True, symbols=True):
    chars = ''
    if upper: chars += string.ascii_uppercase
    if lower: chars += string.ascii_lowercase
    if digits: chars += string.digits
    if symbols: chars += '!@#$%^&*()_+-=[]{}|;:,.<>?'
    return ''.join(secrets.choice(chars) for _ in range(length))
```

### Parse policy from form

Common policy hint patterns:
- "Must be at least N characters" → length ≥ N.
- "Must contain uppercase / lowercase / digit / special" → include category.
- "Cannot contain `<chars>`" → exclude charset.
- "Cannot start with `<digit>`" → constraint on first char.
- "Cannot contain username" → personalization filter.

```python
def parse_policy(hint_text):
    policy = {'min_length': 8, 'upper': False, 'lower': False,
              'digits': False, 'symbols': False, 'forbidden': []}
    import re
    if m := re.search(r'at least (\d+) char', hint_text, re.I):
        policy['min_length'] = int(m.group(1))
    if 'uppercase' in hint_text.lower():
        policy['upper'] = True
    if 'lowercase' in hint_text.lower():
        policy['lower'] = True
    if any(t in hint_text.lower() for t in ['digit','number','numeric']):
        policy['digits'] = True
    if any(t in hint_text.lower() for t in ['special','symbol','non-alphanumeric']):
        policy['symbols'] = True
    return policy
```

### Generate compliant password

```python
def gen_compliant(policy):
    while True:
        pw = gen_password(policy['min_length'])
        if policy['upper'] and not any(c.isupper() for c in pw): continue
        if policy['lower'] and not any(c.islower() for c in pw): continue
        if policy['digits'] and not any(c.isdigit() for c in pw): continue
        if policy['symbols'] and not any(c in '!@#$%^&*()_+' for c in pw): continue
        if any(f in pw for f in policy['forbidden']): continue
        return pw
```

### Common policy patterns

| Site type | Typical policy |
|---|---|
| Banking | 8-16 chars, all 4 categories, no repeats |
| Generic SaaS | 8+ chars, mix of categories |
| Government / healthcare | 12+ chars, all categories, no dictionary words |
| Bug bounty platforms | 8+ chars, mixed |

## CredentialManager

### Storage format (per-engagement)

```
YYMMDD_hhmmss_engagement/
└── findings/
    └── credentials.json
```

```json
{
  "engagement": "ACME-2024-Q1",
  "credentials": [
    {
      "username": "test_user_001",
      "password": "...",
      "email": "test_user_001@target-test.com",
      "tags": ["created","admin","2fa-enabled"],
      "created": "2024-01-15T14:30:00Z",
      "notes": "Account with full admin role for IDOR testing"
    }
  ]
}
```

### Add / retrieve

```python
import json, os
from datetime import datetime

class CredManager:
    def __init__(self, path='credentials.json'):
        self.path = path
        if os.path.exists(path):
            self.data = json.load(open(path))
        else:
            self.data = {'engagement':'', 'credentials':[]}

    def add(self, username, password, **kwargs):
        cred = {
            'username': username, 'password': password,
            'created': datetime.utcnow().isoformat() + 'Z',
            **kwargs
        }
        self.data['credentials'].append(cred)
        self._save()
        return cred

    def get_by_tag(self, tag):
        return [c for c in self.data['credentials'] if tag in c.get('tags',[])]

    def _save(self):
        with open(self.path, 'w') as f:
            json.dump(self.data, f, indent=2)
        os.chmod(self.path, 0o600)
```

### Export for tools

```python
# Hydra format: <user>:<pass>
def export_hydra(creds, path):
    with open(path,'w') as f:
        for c in creds:
            f.write(f"{c['username']}:{c['password']}\n")
    os.chmod(path, 0o600)

# Burp Intruder pitchfork: separate user.txt + pass.txt
def export_pitchfork(creds, base):
    with open(f'{base}_users.txt','w') as f:
        for c in creds: f.write(c['username']+'\n')
    with open(f'{base}_pass.txt','w') as f:
        for c in creds: f.write(c['password']+'\n')

# Hashcat combinator
def export_combo(creds, path):
    with open(path,'w') as f:
        for c in creds:
            f.write(f"{c['username']}:{c['password']}\n")
```

## Workflow

```python
# Account creation + storage
mgr = CredManager('engagement/credentials.json')
pw = gen_compliant(parse_policy(login_form_html))
register_user('newuser@example.com', pw)
mgr.add('newuser@example.com', pw, tags=['created','low-priv'])

# Login with stored
admin = mgr.get_by_tag('admin')[0]
session = login(admin['username'], admin['password'])
```

## Security & cleanup

- Use `secrets` (not `random`) for cryptographic strength.
- File permissions: `0o600`.
- Add `credentials.json` to `.gitignore` (also `*.creds`, `findings/credentials/`).
- Mark created accounts with `cleanup-pending` tag at end of engagement.
- Coordinate cleanup with engagement contact.

## References

- Python `secrets` module.
- OWASP Password Storage Cheat Sheet.
- NIST SP 800-63B.
