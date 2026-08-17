# Authentication Security Testing — Index

## Overview

Authentication testing covers login security, token handling, 2FA bypass, CAPTCHA bypass, and bot detection evasion.

## Reference Documents

| File | Purpose |
|------|---------|
| `authentication-quickstart.md` | Fast-path exploitation and rapid testing workflows |
| `authentication-cheat-sheet.md` | Comprehensive techniques, payloads, and methodology |
| `authentication-resources.md` | Tools, wordlists, and learning resources |

## Key Attack Categories

| Category | Key Vectors |
|----------|-------------|
| Username Enumeration | Response differences, timing, verbose errors |
| Credential Brute-Force | Rate limit bypass, IP rotation, account lockout evasion |
| Password Reset | Predictable tokens, host header injection, token leakage |
| 2FA Bypass | Direct endpoint access, response manipulation, code reuse |
| Multi-Factor Flaws | Skip MFA step, race conditions, backup code abuse |

## Quick Reference

**Fastest wins (< 5 min each):**
1. Default credentials (`admin:admin`, `admin:password`)
2. Username enumeration via response differences
3. Password reset token predictability
4. 2FA response manipulation (`"mfaCode":200` → change to `200 OK`)

**Tools:**
- `ffuf` / `hydra` — credential brute-force
- Burp Suite — request manipulation, Intruder for brute-force
- `authentication-quickstart.md` — ready-to-use commands

## Related Skills

- `INDEX.md` — full scenario index (JWT, OAuth, 2FA, password attacks)
- `authentication-principles.md` — decision tree and cross-cutting gotchas
- `scenarios/jwt/` — JWT token attacks (alg-confusion, signature bypass, etc.)
- `scenarios/oauth/` — OAuth flow vulnerabilities
- `scenarios/2fa/` — MFA bypass methods (10+ scenarios)
- `scenarios/password-attacks/` — brute force, hash cracking, PtH, spraying, stuffing
- `reference/CAPTCHA_BYPASS.md` — CAPTCHA bypass techniques
- `reference/BOT_DETECTION.md` — Bot detection evasion
