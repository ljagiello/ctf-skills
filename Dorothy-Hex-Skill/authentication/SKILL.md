---
name: authentication
description: Authentication security testing - auth bypass, JWT attacks, OAuth flaws, password attacks, 2FA bypass, CAPTCHA bypass, and bot detection evasion.
---

# Authentication

Test authentication mechanisms including login security, token handling, 2FA, CAPTCHA, and bot detection.

## Techniques

| Type | Key Vectors |
|------|-------------|
| **Auth Bypass** | Default credentials, logic flaws, response manipulation |
| **ADFS/SAML** | Golden SAML, token signing cert theft, assertion manipulation, SAML wrapping |
| **JWT** | Algorithm confusion, key injection, claim tampering, token forging |
| **OAuth** | Redirect manipulation, CSRF, token leakage, scope abuse |
| **Password** | Brute force, credential stuffing, password policy bypass |
| **2FA Bypass** | Response manipulation, direct endpoint access, code reuse, race conditions |
| **CAPTCHA Bypass** | Missing server validation, token reuse, OCR, parameter manipulation |
| **Bot Detection** | Behavioral biometrics simulation, fingerprint randomization, stealth mode |

## Tools

**PasswordGenerator** (`tools/password_generator.py`):
```python
from tools.password_generator import generate_password
password = generate_password(hint_text="8-16 chars, uppercase, numbers")
```

**CredentialManager** (`tools/credential_manager.py`):
```python
from tools.credential_manager import CredentialManager
mgr = CredentialManager()
mgr.store_credential(target="example.com", username="test", password="pass")
```

## Workflow

1. Analyze auth implementation (forms, tokens, 2FA, CAPTCHA)
2. Test bypass vectors per technique type
3. Use Playwright MCP with human-like behavior (typing 80-200ms, random pauses)
4. Capture evidence (screenshots, network logs, tokens)
5. Document findings with PoC scripts

## Reference

- `reference/authentication*.md` - Auth bypass techniques, payloads, and resources
- `reference/jwt*.md` - JWT attack techniques and cheat sheets
- `reference/oauth*.md` - OAuth vulnerability testing
- `reference/scenarios/password-attacks/*.md` - Password attack vectors (spray, stuffing, cracking, PtH)
- `reference/adfs-exploitation.md` - ADFS, Golden SAML, federation attacks
- `reference/scenarios/2fa/*.md` - 2FA bypass methods
- `reference/CAPTCHA_BYPASS.md` - 11 CAPTCHA bypass techniques
- `reference/BOT_DETECTION.md` - Bot detection evasion strategies
- `reference/PASSWORD_CREDENTIAL_MANAGEMENT.md` - Tool usage guide
