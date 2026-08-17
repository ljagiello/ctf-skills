# Cloud + Containers — Scenario Index

Read `cloud-containers-principles.md` first for the decision tree.

## AWS

| Trigger / fingerprint | Scenario file | One-line job |
|---|---|---|
| AWS credentials / AWS-hosted target | `scenarios/aws/recon-and-iam-privesc.md` | aws-cli enum + Pacu privesc + LocalStack |
| MinIO / self-hosted S3 (port 9000/8333) | `scenarios/aws/minio-self-hosted-s3.md` | mc admin info + hidden buckets |
| Lambda / SaaS / OAuth | `scenarios/aws/serverless-and-saas.md` | Function injection + subdomain takeover + Electron |
| Mock AWS endpoint (moto / motoserver) + need to verify guessed AKIAs | `scenarios/aws/moto-mock-aws-quirks.md` | `/moto-api/data.json` selective dump + `InvalidClientTokenId` vs `SignatureDoesNotMatch` oracle |

## Azure

| Trigger / fingerprint | Scenario file | One-line job |
|---|---|---|
| Azure credentials / Azure resources | `scenarios/azure/recon-and-storage.md` | az enumeration + ROADtools + Azure DevOps RCE |

## GCP

| Trigger / fingerprint | Scenario file | One-line job |
|---|---|---|
| GCP credentials / `metadata.google.internal` | `scenarios/gcp/recon-and-iam.md` | gcloud + gsutil + metadata SSRF + IAM privesc |

## Docker

| Trigger / fingerprint | Scenario file | One-line job |
|---|---|---|
| Foothold inside container, host testing | `scenarios/docker/container-recon-and-escape.md` | /proc/1/cgroup + mount info + cgroup release_agent + CVE-2022-0811 |

## Kubernetes

| Trigger / fingerprint | Scenario file | One-line job |
|---|---|---|
| K8s cluster / pod foothold | `scenarios/kubernetes/recon-and-rbac.md` | kubectl auth + kubelet 10250 + SA token pivot + hostPath |
