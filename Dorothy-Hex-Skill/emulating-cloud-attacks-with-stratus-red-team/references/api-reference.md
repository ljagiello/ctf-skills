# Stratus Red Team — Command Reference

## Lifecycle Commands

| Command | Description |
|---------|-------------|
| `stratus list` | List all available attack techniques |
| `stratus list --platform aws` | Filter techniques by platform (`aws`, `azure`, `gcp`, `kubernetes`, `eks`) |
| `stratus list --mitre-attack-tactic credential-access` | Filter techniques by MITRE ATT&CK tactic |
| `stratus show <technique-id>` | Print a technique's full description and detonation details |
| `stratus warmup <technique-id>` | Provision prerequisite infrastructure (Terraform) without attacking |
| `stratus detonate <technique-id>` | Execute the attack actions (implicit warmup if needed) |
| `stratus detonate <id> --force` | Force a fresh warmup before detonating |
| `stratus status` | Show the lifecycle state (COLD/WARM/DETONATED) of all techniques |
| `stratus revert <technique-id>` | Undo detonation side effects, keeping prerequisites |
| `stratus cleanup <technique-id>` | Remove a technique's prerequisite infrastructure |
| `stratus cleanup --all` | Remove all infrastructure Stratus ever provisioned |
| `stratus version` | Print the Stratus Red Team version |

## State and Configuration

| Item | Value |
|------|-------|
| State directory | `~/.stratus-red-team/` (Terraform binary, provider plugins, per-technique state) |
| AWS credentials | Standard AWS SDK chain (`AWS_PROFILE`, `AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY`/`AWS_SESSION_TOKEN`) |
| Azure credentials | `az login` / Azure SDK environment chain |
| GCP credentials | Application Default Credentials (`gcloud auth application-default login`) |
| Kubernetes | Active `kubectl` context / kubeconfig |

## Example Technique IDs

| Technique ID | Tactic |
|--------------|--------|
| `aws.credential-access.ec2-steal-instance-credentials` | Credential Access |
| `aws.persistence.iam-create-admin-user` | Persistence |
| `aws.exfiltration.ec2-share-ebs-snapshot` | Exfiltration |
| `aws.discovery.ec2-enumerate-from-instance` | Discovery |
| `gcp.persistence.create-admin-service-account` | Persistence |
| `azure.execution.vm-custom-script-extension` | Execution |
| `k8s.persistence.create-admin-clusterrole` | Persistence |

## Programmatic Use (Go SDK)

Stratus also exposes a Go package `github.com/datadog/stratus-red-team/v2/pkg/stratus/runner` that can be embedded in tooling to warm up, detonate, revert, and clean up techniques programmatically.
