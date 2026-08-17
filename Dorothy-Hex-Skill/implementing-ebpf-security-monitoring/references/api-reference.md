# API Reference: Implementing eBPF Security Monitoring with Tetragon

## Tetragon Installation (Helm)

```bash
# Add Cilium Helm repo
helm repo add cilium https://helm.cilium.io
helm repo update

# Install with recommended security settings
helm install tetragon cilium/tetragon -n kube-system \
  --set tetragon.enableProcessCred=true \
  --set tetragon.enableProcessNs=true \
  --set tetragon.exportFilename=/var/log/tetragon/tetragon.log

# Standalone Linux (non-Kubernetes)
curl -LO https://github.com/cilium/tetragon/releases/latest/download/tetragon-linux-amd64.tar.gz
sudo tetragon --btf /sys/kernel/btf/vmlinux
```

## TracingPolicy CRD Schema

```yaml
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy          # or TracingPolicyNamespaced
metadata:
  name: policy-name
spec:
  kprobes:                   # List of kprobe hooks
    - call: "function_name"  # Kernel function to hook
      syscall: true|false    # Whether this is a syscall
      args:                  # Arguments to capture
        - index: 0
          type: "string|int|fd|file|sock|cred|char_buf|size_t"
      selectors:             # In-kernel filtering
        - matchArgs:
            - index: 0
              operator: "Equal|NotEqual|Prefix|Postfix|Mask|In|NotIn"
              values: ["value1", "value2"]
          matchBinaries:
            - operator: "In|NotIn"
              values: ["/usr/bin/binary"]
          matchActions:
            - action: "Post|Sigkill|Signal|Override|FollowFD|CopyFD"
```

## Common Kprobe Hook Points

| Hook Function | Syscall | Use Case |
|---------------|---------|----------|
| `sys_execve` | true | Process execution monitoring |
| `fd_install` | false | File descriptor / file open monitoring |
| `sys_openat` | true | File open with path |
| `sys_write` | true | File write monitoring |
| `tcp_connect` | false | Outbound TCP connections |
| `tcp_sendmsg` | false | TCP data sent |
| `__sys_setuid` | false | Privilege escalation (setuid) |
| `commit_creds` | false | Credential changes |
| `sys_mount` | true | Filesystem mount operations |
| `sys_ptrace` | true | Process tracing / debugging |

## Argument Types

| Type | Description |
|------|-------------|
| `string` | Null-terminated string |
| `int` | Integer value |
| `fd` | File descriptor (resolved to path) |
| `file` | File structure (includes path) |
| `sock` | Socket structure (includes IP/port) |
| `cred` | Credentials structure (uid/gid) |
| `char_buf` | Character buffer (requires sizeArgIndex) |
| `size_t` | Size type |

## Selector Operators

| Operator | Description | Example |
|----------|-------------|---------|
| `Equal` | Exact match | `values: ["0"]` |
| `NotEqual` | Not equal | `values: ["0"]` |
| `Prefix` | String prefix | `values: ["/etc/"]` |
| `Postfix` | String suffix | `values: ["xmrig"]` |
| `Mask` | Bitmask match | `values: ["0x1"]` |
| `In` | Value in set | `values: ["/bin/bash", "/bin/sh"]` |
| `NotIn` | Value not in set | `values: ["/usr/sbin/sshd"]` |

## Match Actions

| Action | Description |
|--------|-------------|
| `Post` | Emit event to userspace (default) |
| `Sigkill` | Kill the process immediately |
| `Signal` | Send specified signal |
| `Override` | Override return value |
| `FollowFD` | Track file descriptor across calls |
| `CopyFD` | Copy file descriptor info |

## tetra CLI Commands

```bash
# Stream events in compact format
tetra getevents -o compact

# Stream events in JSON
tetra getevents -o json

# Filter by namespace
tetra getevents -o compact --namespace production

# Filter by pod
tetra getevents -o compact --pod webapp-7b4d9f8c6-x2k9p

# Health check
tetra status

# Version
tetra version
```

## Tetragon gRPC API

```protobuf
service FineGuidanceSensors {
  rpc GetEvents(GetEventsRequest) returns (stream GetEventsResponse) {}
  rpc GetHealth(GetHealthStatusRequest) returns (GetHealthStatusResponse) {}
}
```

## JSON Event Types

```json
// process_exec event
{
  "process_exec": {
    "process": {
      "exec_id": "abc123",
      "pid": 1234,
      "uid": 1000,
      "binary": "/usr/bin/curl",
      "arguments": "-O https://example.com/file",
      "cwd": "/tmp",
      "start_time": "2026-01-15T10:30:00Z",
      "pod": {"namespace": "default", "name": "webapp-xxx"},
      "parent": {"binary": "/bin/bash", "pid": 1200}
    }
  }
}

// process_kprobe event (triggered by TracingPolicy)
{
  "process_kprobe": {
    "process": {"binary": "/usr/bin/cat", "pid": 5678},
    "policy_name": "monitor-sensitive-file-access",
    "function_name": "fd_install",
    "args": [
      {"file_arg": {"path": "/etc/shadow"}}
    ]
  }
}

// process_exit event
{
  "process_exit": {
    "process": {"binary": "/usr/bin/curl", "pid": 1234},
    "status": 0,
    "signal": ""
  }
}
```

## Log Export Configuration

```yaml
# Helm values for SIEM integration
tetragon:
  exportFilename: /var/log/tetragon/tetragon.log
  exportFileMaxSizeMB: 100
  exportFileMaxBackups: 5
  exportRateLimit: 1000       # events/second
  exportAllowList: ""         # JSON filter for allowed events
  exportDenyList: ""          # JSON filter for denied events
```

### References

- Tetragon Documentation: https://tetragon.io/docs/
- Tetragon GitHub: https://github.com/cilium/tetragon
- eBPF.io: https://ebpf.io/
- Cilium: https://cilium.io/
- TracingPolicy Examples: https://github.com/cilium/tetragon/tree/main/examples/tracingpolicy
- Tetragon gRPC API: https://tetragon.io/docs/reference/grpc-api/
- Isovalent Blog: https://isovalent.com/blog/
