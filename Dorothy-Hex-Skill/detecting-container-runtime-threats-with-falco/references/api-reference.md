# Falco — Rule Schema & CLI Reference

## Rule Object Fields

| Field | Required | Purpose |
|-------|----------|---------|
| `rule` | yes | Unique rule name |
| `desc` | yes | Human description |
| `condition` | yes | Falco filter expression that triggers the rule |
| `output` | yes | Alert message (supports `%field` interpolation) |
| `priority` | yes | EMERGENCY, ALERT, CRITICAL, ERROR, WARNING, NOTICE, INFO, DEBUG |
| `tags` | no | Categorization (e.g. MITRE IDs) |
| `enabled` | no | Toggle a rule (true/false) |
| `source` | no | Event source (syscall, k8s_audit) |

## Macro and List Objects

| Object | Keys | Purpose |
|--------|------|---------|
| `macro` | `condition` | Reusable condition fragment |
| `list` | `items` | Named value set used with `in (...)` |

## Key CLI Commands

| Command | Purpose |
|---------|---------|
| `falco --validate <file>` | Validate rule syntax without running |
| `falco -r <file>` | Run with a specific rules file |
| `falco -L` | List loaded rules |
| `falco -l <rule>` | Describe a single rule |
| `falco --list` | List supported fields |
| `falcoctl driver config --type modern_ebpf` | Set driver type |
| `falcoctl artifact install <name>` | Install a rules/plugin artifact |
| `falcoctl artifact list` | List available artifacts |

## Driver Types

| Driver | `driver.kind` | Notes |
|--------|---------------|-------|
| Modern eBPF | `modern_ebpf` | Default; built into binary; kernel >= 5.8 |
| Legacy eBPF | `ebpf` | CO-RE eBPF probe |
| Kernel module | `kmod` | Loadable kernel module |
| Auto | `auto` | falcoctl picks best available |

## Important Filter Fields

| Field | Description |
|-------|-------------|
| `evt.type` | Syscall name |
| `evt.dir` | `>` enter, `<` exit |
| `evt.is_open_read` / `evt.is_open_write` | open() intent |
| `proc.name` / `proc.cmdline` / `proc.pname` | Process / cmdline / parent |
| `container.id` / `container.name` / `container.image.repository` | Container identity |
| `container.privileged` | Privileged flag |
| `fd.name` / `fd.type` / `fd.num` | FD path / type / number |
| `user.name` / `user.uid` | Acting user |
| `k8s.pod.name` / `k8s.ns.name` | Kubernetes context |

## Configuration (falco.yaml)

| Key | Purpose |
|-----|---------|
| `rules_files` | List of rule files / dirs to load |
| `json_output` | Emit JSON for SIEM ingest |
| `priority` | Minimum priority to log |
| `outputs` / `http_output` / `program_output` | Alert sinks |

## External References

- Supported fields: https://falco.org/docs/reference/rules/supported-fields/
- Rule examples: https://falco.org/docs/reference/rules/examples/
- Configuration: https://falco.org/docs/reference/daemon/config-options/
