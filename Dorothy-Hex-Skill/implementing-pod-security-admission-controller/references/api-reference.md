# API Reference: Kubernetes Pod Security Admission Controller

## Libraries Used

| Library | Purpose |
|---------|---------|
| `kubernetes` | Official Kubernetes Python client for cluster API access |
| `json` | Parse and format admission review payloads |
| `yaml` | Read and write Pod Security Standard label configurations |

## Installation

```bash
pip install kubernetes pyyaml
```

## Authentication

```python
from kubernetes import client, config

# In-cluster (running inside a pod)
config.load_incluster_config()

# Local kubeconfig
config.load_kube_config(context="my-cluster")

v1 = client.CoreV1Api()
```

## Pod Security Standards Levels

| Level | Description |
|-------|-------------|
| `privileged` | Unrestricted — no restrictions applied |
| `baseline` | Minimally restrictive — prevents known privilege escalation |
| `restricted` | Heavily restricted — follows hardening best practices |

## Namespace Label API

Pod Security Admission is configured via namespace labels:

| Label | Purpose |
|-------|---------|
| `pod-security.kubernetes.io/enforce` | Reject pods that violate the policy |
| `pod-security.kubernetes.io/enforce-version` | Pin policy to specific k8s version |
| `pod-security.kubernetes.io/audit` | Log violations in audit log |
| `pod-security.kubernetes.io/audit-version` | Pin audit policy version |
| `pod-security.kubernetes.io/warn` | Show warnings to kubectl users |
| `pod-security.kubernetes.io/warn-version` | Pin warning policy version |

## Core Operations

### List Namespaces with PSA Labels
```python
namespaces = v1.list_namespace()
for ns in namespaces.items:
    labels = ns.metadata.labels or {}
    enforce = labels.get("pod-security.kubernetes.io/enforce", "none")
    audit = labels.get("pod-security.kubernetes.io/audit", "none")
    warn = labels.get("pod-security.kubernetes.io/warn", "none")
    print(f"{ns.metadata.name}: enforce={enforce} audit={audit} warn={warn}")
```

### Apply PSA Labels to a Namespace
```python
body = {
    "metadata": {
        "labels": {
            "pod-security.kubernetes.io/enforce": "restricted",
            "pod-security.kubernetes.io/enforce-version": "latest",
            "pod-security.kubernetes.io/audit": "restricted",
            "pod-security.kubernetes.io/warn": "restricted",
        }
    }
}
v1.patch_namespace(name="production", body=body)
```

### Audit All Namespaces for Missing PSA Labels
```python
def audit_psa_labels():
    findings = []
    namespaces = v1.list_namespace()
    for ns in namespaces.items:
        name = ns.metadata.name
        labels = ns.metadata.labels or {}
        if name in ("kube-system", "kube-public", "kube-node-lease"):
            continue
        enforce = labels.get("pod-security.kubernetes.io/enforce")
        if not enforce:
            findings.append({"namespace": name, "issue": "no enforce label"})
        elif enforce == "privileged":
            findings.append({"namespace": name, "issue": "enforce=privileged"})
    return findings
```

### Check Pod Violations Against a Level
```python
def check_pod_security(namespace, level="restricted"):
    pods = v1.list_namespaced_pod(namespace=namespace)
    violations = []
    for pod in pods.items:
        for container in pod.spec.containers:
            sc = container.security_context
            if not sc:
                violations.append({
                    "pod": pod.metadata.name,
                    "container": container.name,
                    "issue": "no securityContext defined",
                })
                continue
            if sc.privileged:
                violations.append({
                    "pod": pod.metadata.name,
                    "container": container.name,
                    "issue": "privileged=true",
                })
            if sc.run_as_non_root is not True:
                violations.append({
                    "pod": pod.metadata.name,
                    "container": container.name,
                    "issue": "runAsNonRoot not set",
                })
            caps = sc.capabilities
            if level == "restricted" and (not caps or not caps.drop or "ALL" not in caps.drop):
                violations.append({
                    "pod": pod.metadata.name,
                    "container": container.name,
                    "issue": "capabilities.drop does not include ALL",
                })
    return violations
```

## kubectl Equivalents

```bash
# Label a namespace with restricted enforcement
kubectl label namespace production \
  pod-security.kubernetes.io/enforce=restricted \
  pod-security.kubernetes.io/warn=restricted \
  --overwrite

# Dry-run to test impact before enforcing
kubectl label --dry-run=server --overwrite namespace production \
  pod-security.kubernetes.io/enforce=restricted

# Check which namespaces have PSA labels
kubectl get namespaces -L pod-security.kubernetes.io/enforce
```

## Output Format

```json
{
  "namespace": "production",
  "enforce_level": "restricted",
  "audit_level": "restricted",
  "warn_level": "restricted",
  "pod_violations": [
    {
      "pod": "legacy-app-7f8b9c",
      "container": "app",
      "issue": "privileged=true"
    }
  ],
  "compliant": false
}
```
