#!/usr/bin/env python3
"""Agent for deploying and managing eBPF security monitoring with Cilium Tetragon."""

import os
import sys
import json
import yaml
import shutil
import argparse
import subprocess
import tempfile
from datetime import datetime, timezone


TRACING_POLICY_TEMPLATE = {
    "apiVersion": "cilium.io/v1alpha1",
    "kind": "TracingPolicy",
    "metadata": {"name": ""},
    "spec": {"kprobes": []},
}

SENSITIVE_FILES = [
    "/etc/shadow",
    "/etc/passwd",
    "/etc/sudoers",
    "/etc/sudoers.d/",
    "/root/.ssh/",
    "/etc/kubernetes/pki/",
    "/var/run/secrets/kubernetes.io/",
    "/etc/ssl/private/",
]

SUSPICIOUS_BINARIES = [
    "/bin/bash",
    "/bin/sh",
    "/usr/bin/python3",
    "/usr/bin/python",
    "/usr/bin/perl",
    "/usr/bin/nc",
    "/usr/bin/ncat",
    "/usr/bin/socat",
    "/usr/bin/curl",
    "/usr/bin/wget",
]

CRYPTO_MINERS = [
    "xmrig",
    "minerd",
    "cpuminer",
    "cryptonight",
    "stratum+tcp",
    "nicehashminer",
    "ethminer",
    "nbminer",
]

CONTAINER_ESCAPE_PATHS = [
    "/proc/1/root",
    "/proc/1/ns",
    "/sys/kernel/security",
    "/proc/sysrq-trigger",
    "/proc/kcore",
    "/sys/fs/cgroup",
]


def check_prerequisites():
    """Verify that required tools are available on the system."""
    results = {}
    for tool in ["kubectl", "helm", "tetra"]:
        results[tool] = shutil.which(tool) is not None
    try:
        result = subprocess.run(
            ["uname", "-r"], capture_output=True, text=True, timeout=5
        )
        kernel_version = result.stdout.strip() if result.returncode == 0 else "unknown"
    except (FileNotFoundError, subprocess.TimeoutExpired):
        kernel_version = "unknown"

    btf_available = os.path.exists("/sys/kernel/btf/vmlinux")
    results["kernel_version"] = kernel_version
    results["btf_available"] = btf_available
    return results


def generate_file_access_policy(
    name="monitor-sensitive-file-access",
    files=None,
    action="Post",
    namespace=None,
):
    """Generate a TracingPolicy for monitoring file access via fd_install kprobe."""
    if files is None:
        files = SENSITIVE_FILES

    policy = {
        "apiVersion": "cilium.io/v1alpha1",
        "kind": "TracingPolicyNamespaced" if namespace else "TracingPolicy",
        "metadata": {"name": name},
        "spec": {
            "kprobes": [
                {
                    "call": "fd_install",
                    "syscall": False,
                    "args": [
                        {"index": 0, "type": "int"},
                        {"index": 1, "type": "file"},
                    ],
                    "selectors": [
                        {
                            "matchArgs": [
                                {
                                    "index": 1,
                                    "operator": "Prefix",
                                    "values": files,
                                }
                            ],
                            "matchActions": [{"action": action}],
                        }
                    ],
                }
            ]
        },
    }
    if namespace:
        policy["metadata"]["namespace"] = namespace
    return policy


def generate_network_monitor_policy(
    name="monitor-tcp-connections",
    binaries=None,
    action="Post",
):
    """Generate a TracingPolicy for monitoring TCP connections via tcp_connect kprobe."""
    kprobe = {
        "call": "tcp_connect",
        "syscall": False,
        "args": [{"index": 0, "type": "sock"}],
        "selectors": [{"matchActions": [{"action": action}]}],
    }
    if binaries:
        kprobe["selectors"][0]["matchBinaries"] = [
            {"operator": "In", "values": binaries}
        ]

    policy = {
        "apiVersion": "cilium.io/v1alpha1",
        "kind": "TracingPolicy",
        "metadata": {"name": name},
        "spec": {"kprobes": [kprobe]},
    }
    return policy


def generate_privilege_escalation_policy(
    name="detect-privilege-escalation",
    action="Post",
):
    """Generate a TracingPolicy for detecting setuid(0) and commit_creds calls."""
    policy = {
        "apiVersion": "cilium.io/v1alpha1",
        "kind": "TracingPolicy",
        "metadata": {"name": name},
        "spec": {
            "kprobes": [
                {
                    "call": "__sys_setuid",
                    "syscall": False,
                    "args": [{"index": 0, "type": "int"}],
                    "selectors": [
                        {
                            "matchArgs": [
                                {
                                    "index": 0,
                                    "operator": "Equal",
                                    "values": ["0"],
                                }
                            ],
                            "matchActions": [{"action": action}],
                        }
                    ],
                },
                {
                    "call": "commit_creds",
                    "syscall": False,
                    "args": [{"index": 0, "type": "cred"}],
                    "selectors": [{"matchActions": [{"action": action}]}],
                },
            ]
        },
    }
    return policy


def generate_crypto_miner_enforcement_policy(
    name="enforce-no-crypto-miners",
    miners=None,
):
    """Generate a TracingPolicy that kills crypto miner processes via Sigkill."""
    if miners is None:
        miners = CRYPTO_MINERS

    policy = {
        "apiVersion": "cilium.io/v1alpha1",
        "kind": "TracingPolicy",
        "metadata": {"name": name},
        "spec": {
            "kprobes": [
                {
                    "call": "sys_execve",
                    "syscall": True,
                    "args": [{"index": 0, "type": "string"}],
                    "selectors": [
                        {
                            "matchArgs": [
                                {
                                    "index": 0,
                                    "operator": "Postfix",
                                    "values": miners,
                                }
                            ],
                            "matchActions": [{"action": "Sigkill"}],
                        }
                    ],
                }
            ]
        },
    }
    return policy


def generate_reverse_shell_detection_policy(
    name="detect-reverse-shells",
    binaries=None,
    action="Post",
):
    """Generate a TracingPolicy for detecting reverse shell network connections."""
    if binaries is None:
        binaries = SUSPICIOUS_BINARIES

    policy = {
        "apiVersion": "cilium.io/v1alpha1",
        "kind": "TracingPolicy",
        "metadata": {"name": name},
        "spec": {
            "kprobes": [
                {
                    "call": "tcp_connect",
                    "syscall": False,
                    "args": [{"index": 0, "type": "sock"}],
                    "selectors": [
                        {
                            "matchBinaries": [
                                {"operator": "In", "values": binaries}
                            ],
                            "matchActions": [{"action": action}],
                        }
                    ],
                }
            ]
        },
    }
    return policy


def generate_container_escape_policy(
    name="detect-container-escape",
    paths=None,
    action="Post",
):
    """Generate a TracingPolicy for detecting container escape attempts."""
    if paths is None:
        paths = CONTAINER_ESCAPE_PATHS

    policy = {
        "apiVersion": "cilium.io/v1alpha1",
        "kind": "TracingPolicy",
        "metadata": {"name": name},
        "spec": {
            "kprobes": [
                {
                    "call": "sys_openat",
                    "syscall": True,
                    "args": [
                        {"index": 0, "type": "int"},
                        {"index": 1, "type": "string"},
                    ],
                    "selectors": [
                        {
                            "matchArgs": [
                                {
                                    "index": 1,
                                    "operator": "Prefix",
                                    "values": paths,
                                }
                            ],
                            "matchActions": [{"action": action}],
                        }
                    ],
                },
                {
                    "call": "sys_mount",
                    "syscall": True,
                    "args": [
                        {"index": 0, "type": "string"},
                        {"index": 1, "type": "string"},
                        {"index": 2, "type": "string"},
                    ],
                    "selectors": [{"matchActions": [{"action": action}]}],
                },
            ]
        },
    }
    return policy


def generate_write_monitoring_policy(
    name="monitor-sensitive-file-writes",
    paths=None,
    action="Post",
):
    """Generate a TracingPolicy for monitoring file writes to sensitive paths."""
    if paths is None:
        paths = [
            "/etc/",
            "/root/",
            "/var/spool/cron/",
            "/etc/cron.d/",
            "/etc/systemd/system/",
            "/usr/lib/systemd/system/",
        ]

    policy = {
        "apiVersion": "cilium.io/v1alpha1",
        "kind": "TracingPolicy",
        "metadata": {"name": name},
        "spec": {
            "kprobes": [
                {
                    "call": "sys_write",
                    "syscall": True,
                    "args": [
                        {"index": 0, "type": "fd"},
                        {"index": 1, "type": "char_buf",
                         "sizeArgIndex": 3, "returnCopy": True},
                        {"index": 2, "type": "size_t"},
                    ],
                    "selectors": [
                        {
                            "matchArgs": [
                                {
                                    "index": 0,
                                    "operator": "Prefix",
                                    "values": paths,
                                }
                            ],
                            "matchActions": [{"action": action}],
                        }
                    ],
                }
            ]
        },
    }
    return policy


def apply_policy(policy, dry_run=False):
    """Apply a TracingPolicy to the Kubernetes cluster or write to file."""
    policy_yaml = yaml.dump(policy, default_flow_style=False)

    if dry_run:
        return {"status": "dry_run", "yaml": policy_yaml}

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".yaml", delete=False
    ) as f:
        f.write(policy_yaml)
        temp_path = f.name

    try:
        result = subprocess.run(
            ["kubectl", "apply", "-f", temp_path],
            capture_output=True,
            text=True,
            timeout=30,
        )
        return {
            "status": "applied" if result.returncode == 0 else "failed",
            "stdout": result.stdout.strip(),
            "stderr": result.stderr.strip(),
            "yaml": policy_yaml,
        }
    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        return {"status": "error", "error": str(e), "yaml": policy_yaml}
    finally:
        os.unlink(temp_path)


def list_tracing_policies():
    """List all TracingPolicy resources in the cluster."""
    try:
        result = subprocess.run(
            ["kubectl", "get", "tracingpolicies", "-o", "json"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode != 0:
            return {"status": "error", "stderr": result.stderr.strip()}
        policies = json.loads(result.stdout)
        return {
            "status": "ok",
            "count": len(policies.get("items", [])),
            "policies": [
                {
                    "name": p["metadata"]["name"],
                    "created": p["metadata"].get("creationTimestamp", ""),
                }
                for p in policies.get("items", [])
            ],
        }
    except (FileNotFoundError, subprocess.TimeoutExpired, json.JSONDecodeError) as e:
        return {"status": "error", "error": str(e)}


def stream_events(output_format="compact", event_filter=None, limit=100):
    """Stream Tetragon events using the tetra CLI."""
    cmd = ["tetra", "getevents", "-o", output_format]
    try:
        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )
        events = []
        for i, line in enumerate(proc.stdout):
            if i >= limit:
                break
            line = line.strip()
            if not line:
                continue
            if output_format == "json":
                try:
                    event = json.loads(line)
                    if event_filter and event_filter not in json.dumps(event):
                        continue
                    events.append(event)
                except json.JSONDecodeError:
                    continue
            else:
                if event_filter and event_filter not in line:
                    continue
                events.append(line)
        proc.terminate()
        return {"status": "ok", "event_count": len(events), "events": events}
    except FileNotFoundError:
        return {"status": "error", "error": "tetra CLI not found"}


def parse_tetragon_log(log_path, event_types=None):
    """Parse a Tetragon JSON log file and extract security-relevant events."""
    if not os.path.exists(log_path):
        return {"status": "error", "error": f"Log file not found: {log_path}"}

    if event_types is None:
        event_types = ["process_exec", "process_kprobe", "process_exit"]

    events = {"total": 0, "by_type": {}}
    alerts = []

    with open(log_path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue

            events["total"] += 1

            for etype in event_types:
                if etype in event:
                    events["by_type"].setdefault(etype, 0)
                    events["by_type"][etype] += 1

                    if etype == "process_kprobe":
                        kprobe_data = event[etype]
                        policy_name = kprobe_data.get("policy_name", "")
                        func = kprobe_data.get("function_name", "")
                        binary = (
                            kprobe_data.get("process", {}).get("binary", "")
                        )
                        alerts.append(
                            {
                                "type": etype,
                                "policy": policy_name,
                                "function": func,
                                "binary": binary,
                                "time": event.get("time", ""),
                            }
                        )

    return {
        "status": "ok",
        "events": events,
        "security_alerts": alerts[:100],
    }


def generate_helm_values(
    enable_process_cred=True,
    enable_process_ns=True,
    export_file="/var/log/tetragon/tetragon.log",
    export_max_size_mb=100,
    export_max_backups=5,
    resources_cpu="500m",
    resources_memory="512Mi",
):
    """Generate Helm values YAML for Tetragon deployment."""
    values = {
        "tetragon": {
            "enableProcessCred": enable_process_cred,
            "enableProcessNs": enable_process_ns,
            "exportFilename": export_file,
            "exportFileMaxSizeMB": export_max_size_mb,
            "exportFileMaxBackups": export_max_backups,
            "resources": {
                "requests": {"cpu": "100m", "memory": "128Mi"},
                "limits": {"cpu": resources_cpu, "memory": resources_memory},
            },
        },
        "tetragonOperator": {
            "enabled": True,
        },
        "export": {
            "stdout": {"enabledCommand": True, "enabledArgs": True},
        },
    }
    return yaml.dump(values, default_flow_style=False)


def generate_full_monitoring_suite(output_dir, dry_run=False):
    """Generate a complete suite of TracingPolicies for security monitoring."""
    os.makedirs(output_dir, exist_ok=True)

    policies = {
        "01-file-access-monitor.yaml": generate_file_access_policy(),
        "02-network-monitor.yaml": generate_network_monitor_policy(),
        "03-privilege-escalation-detect.yaml": generate_privilege_escalation_policy(),
        "04-crypto-miner-enforcement.yaml": generate_crypto_miner_enforcement_policy(),
        "05-reverse-shell-detect.yaml": generate_reverse_shell_detection_policy(),
        "06-container-escape-detect.yaml": generate_container_escape_policy(),
        "07-sensitive-write-monitor.yaml": generate_write_monitoring_policy(),
    }

    results = []
    for filename, policy in policies.items():
        filepath = os.path.join(output_dir, filename)
        policy_yaml = yaml.dump(policy, default_flow_style=False)
        with open(filepath, "w") as f:
            f.write(policy_yaml)
        results.append(
            {
                "file": filepath,
                "policy_name": policy["metadata"]["name"],
                "kprobe_count": len(policy["spec"]["kprobes"]),
            }
        )

    helm_values_path = os.path.join(output_dir, "helm-values.yaml")
    with open(helm_values_path, "w") as f:
        f.write(generate_helm_values())
    results.append({"file": helm_values_path, "type": "helm-values"})

    summary = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "output_dir": output_dir,
        "policy_count": len(policies),
        "policies": results,
        "dry_run": dry_run,
    }
    return summary


def install_tetragon_helm(namespace="kube-system", values_file=None, dry_run=False):
    """Install or upgrade Tetragon via Helm."""
    cmd = [
        "helm", "upgrade", "--install", "tetragon",
        "cilium/tetragon", "-n", namespace,
    ]
    if values_file:
        cmd.extend(["-f", values_file])
    else:
        cmd.extend([
            "--set", "tetragon.enableProcessCred=true",
            "--set", "tetragon.enableProcessNs=true",
        ])
    if dry_run:
        cmd.append("--dry-run")

    try:
        add_repo = subprocess.run(
            ["helm", "repo", "add", "cilium", "https://helm.cilium.io"],
            capture_output=True, text=True, timeout=30,
        )
        subprocess.run(
            ["helm", "repo", "update"],
            capture_output=True, text=True, timeout=60,
        )
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        return {
            "status": "installed" if result.returncode == 0 else "failed",
            "stdout": result.stdout.strip(),
            "stderr": result.stderr.strip(),
        }
    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        return {"status": "error", "error": str(e)}


def verify_installation(namespace="kube-system"):
    """Verify Tetragon is running correctly in the cluster."""
    checks = {}

    try:
        result = subprocess.run(
            ["kubectl", "get", "pods", "-n", namespace,
             "-l", "app.kubernetes.io/name=tetragon",
             "-o", "json"],
            capture_output=True, text=True, timeout=30,
        )
        if result.returncode == 0:
            pods = json.loads(result.stdout)
            items = pods.get("items", [])
            checks["pods"] = {
                "count": len(items),
                "statuses": [
                    {
                        "name": p["metadata"]["name"],
                        "phase": p["status"].get("phase", "Unknown"),
                        "ready": all(
                            c.get("ready", False)
                            for c in p["status"].get("containerStatuses", [])
                        ),
                    }
                    for p in items
                ],
            }
        else:
            checks["pods"] = {"error": result.stderr.strip()}
    except Exception as e:
        checks["pods"] = {"error": str(e)}

    try:
        result = subprocess.run(
            ["kubectl", "api-resources", "--api-group=cilium.io"],
            capture_output=True, text=True, timeout=30,
        )
        checks["crds_available"] = "tracingpolicies" in result.stdout.lower()
    except Exception:
        checks["crds_available"] = False

    return checks


def main():
    parser = argparse.ArgumentParser(
        description="eBPF Security Monitoring Agent - Cilium Tetragon"
    )
    parser.add_argument(
        "--action",
        choices=[
            "check",
            "install",
            "generate",
            "apply",
            "list-policies",
            "stream",
            "parse-log",
            "verify",
        ],
        default="check",
        help="Action to perform",
    )
    parser.add_argument("--output-dir", default="./tetragon-policies",
                        help="Directory for generated policies")
    parser.add_argument("--output", default="ebpf_monitoring_report.json",
                        help="Output report file")
    parser.add_argument("--dry-run", action="store_true",
                        help="Generate without applying")
    parser.add_argument("--log-path", help="Path to Tetragon log file")
    parser.add_argument("--event-filter", help="Filter events by keyword")
    parser.add_argument("--limit", type=int, default=100,
                        help="Max events to stream")
    parser.add_argument("--namespace", default="kube-system",
                        help="Kubernetes namespace")
    parser.add_argument("--values-file", help="Helm values file path")
    parser.add_argument("--policy-type",
                        choices=[
                            "file-access", "network", "privilege-escalation",
                            "crypto-miner", "reverse-shell", "container-escape",
                            "write-monitor", "all",
                        ],
                        default="all",
                        help="Type of policy to generate/apply")
    args = parser.parse_args()

    report = {"generated_at": datetime.now(timezone.utc).isoformat(), "action": args.action}

    if args.action == "check":
        prereqs = check_prerequisites()
        report["prerequisites"] = prereqs
        print(f"[*] Kernel: {prereqs['kernel_version']}")
        print(f"[*] BTF available: {prereqs['btf_available']}")
        for tool in ["kubectl", "helm", "tetra"]:
            status = "found" if prereqs[tool] else "NOT FOUND"
            print(f"[*] {tool}: {status}")

    elif args.action == "install":
        print("[+] Installing Tetragon via Helm...")
        result = install_tetragon_helm(
            namespace=args.namespace,
            values_file=args.values_file,
            dry_run=args.dry_run,
        )
        report["install"] = result
        print(f"[+] Status: {result['status']}")

    elif args.action == "generate":
        print(f"[+] Generating TracingPolicies to {args.output_dir}...")
        suite = generate_full_monitoring_suite(args.output_dir, dry_run=args.dry_run)
        report["suite"] = suite
        print(f"[+] Generated {suite['policy_count']} policies")

    elif args.action == "apply":
        policy_generators = {
            "file-access": generate_file_access_policy,
            "network": generate_network_monitor_policy,
            "privilege-escalation": generate_privilege_escalation_policy,
            "crypto-miner": generate_crypto_miner_enforcement_policy,
            "reverse-shell": generate_reverse_shell_detection_policy,
            "container-escape": generate_container_escape_policy,
            "write-monitor": generate_write_monitoring_policy,
        }
        if args.policy_type == "all":
            policies_to_apply = policy_generators
        else:
            policies_to_apply = {args.policy_type: policy_generators[args.policy_type]}

        report["applied"] = []
        for ptype, generator in policies_to_apply.items():
            policy = generator()
            result = apply_policy(policy, dry_run=args.dry_run)
            report["applied"].append({"type": ptype, "result": result})
            print(f"[+] {ptype}: {result['status']}")

    elif args.action == "list-policies":
        result = list_tracing_policies()
        report["policies"] = result
        if result["status"] == "ok":
            print(f"[+] Found {result['count']} TracingPolicies:")
            for p in result["policies"]:
                print(f"    - {p['name']} (created: {p['created']})")
        else:
            print(f"[-] Error: {result.get('error', result.get('stderr', ''))}")

    elif args.action == "stream":
        print(f"[+] Streaming up to {args.limit} events...")
        result = stream_events(
            output_format="json",
            event_filter=args.event_filter,
            limit=args.limit,
        )
        report["events"] = result
        print(f"[+] Captured {result.get('event_count', 0)} events")

    elif args.action == "parse-log":
        if not args.log_path:
            print("[-] --log-path required for parse-log action")
            sys.exit(1)
        print(f"[+] Parsing log: {args.log_path}")
        result = parse_tetragon_log(args.log_path)
        report["log_analysis"] = result
        if result["status"] == "ok":
            print(f"[+] Total events: {result['events']['total']}")
            for etype, count in result["events"]["by_type"].items():
                print(f"    {etype}: {count}")
            print(f"[+] Security alerts: {len(result['security_alerts'])}")
        else:
            print(f"[-] Error: {result['error']}")

    elif args.action == "verify":
        print("[+] Verifying Tetragon installation...")
        checks = verify_installation(args.namespace)
        report["verification"] = checks
        if "pods" in checks and isinstance(checks["pods"], dict):
            pod_info = checks["pods"]
            if "count" in pod_info:
                print(f"[+] Tetragon pods: {pod_info['count']}")
                for ps in pod_info.get("statuses", []):
                    ready_str = "READY" if ps["ready"] else "NOT READY"
                    print(f"    {ps['name']}: {ps['phase']} ({ready_str})")
            else:
                print(f"[-] Pod check error: {pod_info.get('error', 'unknown')}")
        print(f"[+] TracingPolicy CRDs available: {checks.get('crds_available', False)}")

    with open(args.output, "w") as f:
        json.dump(report, f, indent=2, default=str)
    print(f"[+] Report saved to {args.output}")


if __name__ == "__main__":
    main()
