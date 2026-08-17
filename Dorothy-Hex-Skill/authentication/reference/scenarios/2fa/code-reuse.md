# 2FA — OTP Code Reuse

## When this applies

- The OTP verification endpoint does not invalidate codes after first use.
- Codes can be replayed, even hours/days later.
- Common with TOTP implementations that compare code AND time-window without tracking "used codes".

## Technique

Capture a valid OTP. After a successful verification (which logs you in), replay the same code in a separate session. If the verifier does not maintain a "used codes" set, the same code authenticates multiple sessions.

## Steps

### 1. Get a valid OTP

```python
otp = get_otp_from_email()    # e.g., "123456"
```

(Or from authenticator app, SMS, etc.)

### 2. Use code successfully

```python
verify_2fa(otp)               # Works first time → returns session
```

### 3. Try to reuse same code in a new session

Open new browser / clear cookies / use different requests.Session():

```python
verify_2fa(otp)               # Should fail; test if it works
```

If 200, codes are reusable.

### 4. Test with old codes

OTP codes typically have 30-second windows. Some apps don't invalidate, allowing replay even outside the window:

```python
old_otp = "654321"             # Code from a previous session
verify_2fa(old_otp)            # Should definitely fail
```

If old codes still work, time-window enforcement is broken.

### 5. Test concurrent reuse

Submit the same OTP in TWO concurrent requests:

```python
import threading
def verify():
    verify_2fa(otp)
threading.Thread(target=verify).start()
threading.Thread(target=verify).start()
```

Both may succeed if the "used codes" check is non-atomic.

### 6. Test cross-account reuse

If user A's OTP somehow works for user B's account (very rare but happens with shared random sources), it's a critical issue.

```python
# A's code
otp_a = "123456"
verify_2fa(user="A", otp=otp_a)    # Works
verify_2fa(user="B", otp=otp_a)    # Should fail; test
```

### 7. Test backup code reuse

Backup codes (one-time passwords for recovery) often have weaker invalidation:

```python
backup = get_backup_code(user)
verify_backup(user, backup)    # Works
verify_backup(user, backup)    # Should fail
```

## Verifying success

- Same OTP authenticates two sessions.
- Old codes still authenticate.
- Concurrent identical requests both succeed.

## Common pitfalls

- TOTP-RFC compliant implementations DO track used codes within the time window. Modern libraries (`pyotp`, `otplib`) handle this correctly.
- Some apps invalidate the code only when account state changes — short reuse window.
- Token rotation (each verification rotates the secret) blocks reuse but is rare.
- Audit logs flag reuse — note for engagement timeline.

## Tools

- Burp Suite Repeater (manual replay).
- Turbo Intruder for concurrent submission.
- Custom Python `threading` for race-condition tests.
