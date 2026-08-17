---
name: cloud-containers
description: Cloud and container security testing - AWS, Azure, GCP, Docker, and Kubernetes misconfigurations and exploitation.
---

# Cloud & Containers

Test cloud infrastructure and container environments for security misconfigurations and exploitation paths.

## Techniques

| Platform | Key Vectors |
|----------|-------------|
| **AWS** | S3 bucket exposure, IAM misconfig, metadata service, Lambda abuse |
| **Azure** | Blob storage, RBAC flaws, managed identity, App Service misconfig |
| **GCP** | Cloud Storage, service account keys, metadata server, IAM |
| **Docker** | Container escape, privileged mode, socket exposure, image vulnerabilities |
| **Kubernetes** | RBAC bypass, secret exposure, pod escape, API server access |

## Workflow

1. Enumerate cloud resources and services
2. Test IAM/RBAC configurations
3. Check storage and secrets exposure
4. Test container isolation and escape paths
5. Document findings with cloud-specific evidence

## Reference

- `reference/INDEX.md` - Router for platform-specific attack scenarios (AWS, Azure, GCP, Docker, K8s)
