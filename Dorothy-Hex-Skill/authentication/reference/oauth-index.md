# OAuth Security Testing — Index

## Overview

OAuth testing covers authorization flow vulnerabilities, token theft, CSRF via missing state parameters, redirect_uri hijacking, and SSRF via dynamic client registration.

## Reference Documents

| File | Purpose |
|------|---------|
| `oauth-quickstart.md` | Fast-path attack reference and one-liner exploits |
| `scenarios/oauth/` | Per-technique scenario files (split from cheat-sheet) |
| `oauth-resources.md` | Tools, specifications, and learning resources |

## Key Attack Categories

| Attack | Time | Key Technique |
|--------|------|---------------|
| Implicit Flow Bypass | 5 min | Parameter manipulation on `/authenticate` |
| Forced Profile Linking (CSRF) | 10 min | Missing `state` parameter → CSRF |
| redirect_uri Hijacking | 5 min | redirect_uri validation bypass |
| Proxy Page Token Theft | 15 min | Directory traversal + postMessage |
| Open Redirect Token Theft | 15 min | Chained open redirect to exfil token |
| SSRF via Client Registration | 10 min | OpenID dynamic registration + `logo_uri` |

## Quick Reference

**Fastest wins (< 5 min each):**
1. Check for missing `state` parameter → CSRF
2. Test `redirect_uri=https://attacker.com` in Repeater
3. Check for implicit flow tokens in URL fragments
4. Enumerate `/.well-known/openid-configuration`

**Common OAuth Endpoints:**
```
/.well-known/openid-configuration
/auth?client_id=...
/oauth-callback
/token
/me or /userinfo
/reg (OpenID client registration)
```

## Related Skills

- `reference/authentication*.md` — General auth bypass techniques
- `reference/jwt*.md` — JWT token attacks (often used alongside OAuth)
