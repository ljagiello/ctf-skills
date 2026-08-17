# 2FA — Backup Code Abuse

## When this applies

- Application provides backup codes (one-time recovery passwords) for 2FA.
- Backup code validation is weak (reusable, no rate limiting, predictable, leaked).

## Technique

Backup codes serve as fallback when the user loses their authenticator device. Many implementations weaken security on these — accepting reuse, lacking rate limits, generating predictably, or leaking through error messages.

## Steps

### 1. Reusability test

```python
backup = "12345678"
verify_backup(backup)    # Works first time
verify_backup(backup)    # Should fail; if it works → reusable
```

### 2. Rate limiting test

```python
for i in range(1000):
    verify_backup("invalid_code")
```

If 1000 invalid attempts complete without 429 / lockout, no rate limiting on backup codes.

### 3. Brute force backup codes

8-digit numeric backup codes have 10⁸ values — typically infeasible. But:
- 6-digit codes: 10⁶ values, similar to regular OTP brute force.
- Alphanumeric codes: format-dependent.
- If the format is `XXXX-XXXX` with 4-char chunks, charset matters.

```python
import requests
import itertools, string

CHARSET = string.ascii_letters + string.digits
for code_chars in itertools.product(CHARSET, repeat=8):
    code = ''.join(code_chars)
    if verify_backup(code):
        print(f"Found: {code}")
        break
```

### 4. Predictability test

Generate multiple sets of backup codes and look for patterns:

```python
codes_set_1 = generate_backup_codes()    # Trigger via account settings
codes_set_2 = generate_backup_codes()
codes_set_3 = generate_backup_codes()

# Check for sequential patterns, low entropy, time-based seeds
```

### 5. Leak through error messages

```python
# Send an obviously-invalid backup code
r = verify_backup("clearly_invalid")
print(r.text)
# Some apps echo "Code expected: 12345678" or include hints
```

### 6. Leak through admin / debug endpoints

Some apps expose `/admin/users/{id}/backup_codes` for support. Check IDOR-style access:
```python
requests.get('https://target.com/admin/users/1/backup_codes',
             cookies=attacker_session)
```

### 7. Backup-code-as-password test

Some implementations accept a backup code as substitute for the user's password OR the OTP — combine and test both fields.

### 8. Test backup code via OTP field

```python
# If backup codes share format with OTP (both 6-digit numeric):
verify_2fa("87654321")    # Try backup code in OTP field
verify_backup("123456")   # Try OTP in backup code field
```

### 9. Generation race

Some apps generate new backup codes when requested, and the old codes remain valid. Try old + new simultaneously:

```python
old_codes = get_codes_today()
trigger_regenerate()
new_codes = get_codes_today()

for code in old_codes + new_codes:
    if verify_backup(code):
        print(f"Active: {code}")
```

## Verifying success

- Reused backup code authenticates successfully.
- Brute-force returns 200 on a specific code.
- Old codes still work after regeneration.

## Common pitfalls

- Modern apps invalidate ALL backup codes when one is used (single-use bundle), or invalidate pairwise.
- Rate limiting is often present on backup codes (similar to password attempts).
- Backup codes are usually 8+ chars from a strong charset (10⁹ space) — brute force impractical.
- Audit logs strongly flag backup code attempts — lots of noise.

## Tools

- Burp Suite Intruder for code-format-aware brute force.
- Custom Python for charset-specific iteration.
- Source code review for code generation algorithm.
