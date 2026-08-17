# Velociraptor Command and VQL Reference

The same `velociraptor` binary is server, client, and CLI. Behavior depends on the subcommand and `--config`.

## Core subcommands

| Command | Description |
|---------|-------------|
| `velociraptor config generate` | Print a default server config to stdout |
| `velociraptor config generate -i` | Interactive config wizard |
| `velociraptor --config server.config.yaml config client` | Derive client config |
| `velociraptor --config server.config.yaml user add <name> --role administrator` | Create GUI admin |
| `velociraptor --config server.config.yaml frontend -v` | Start server frontend + GUI |
| `velociraptor gui` | All-in-one local lab (server + frontend + local client) |
| `velociraptor --config client.config.yaml client -v` | Run as agent |
| `velociraptor --config client.config.yaml service install` | Install agent service (Windows) |
| `velociraptor query "<VQL>"` | Run an ad-hoc VQL query |
| `velociraptor artifacts list` | List artifacts |
| `velociraptor artifacts collect <Name> --output results.zip` | Collect an artifact locally |
| `velociraptor artifacts show <Name>` | Show an artifact definition |

## Useful global flags

| Flag | Purpose |
|------|---------|
| `--config <file>` | Path to config YAML |
| `-v` / `--verbose` | Verbose logging |
| `-q` | Alias usage with `query` |
| `--format json` | Output query results as JSON |

## Common VQL plugins (data sources)

| Plugin | Returns |
|--------|---------|
| `pslist()` | Running processes (Pid, Name, CommandLine, ...) |
| `glob(globs=...)` | Files matching glob patterns |
| `parse_evtx(filename=...)` | Windows event log records |
| `registry(...)` / `read_reg_key()` | Registry keys/values |
| `netstat()` | Network connections |
| `wmi(query=...)` | WMI query results |
| `info()` | Host/system information |
| `execve(argv=...)` | Run an external command |
| `artifact_definitions()` | Enumerate loaded artifacts |
| `hunt(description=..., artifacts=...)` | Create a server-side hunt |

## VQL query shape

```sql
SELECT <columns>
FROM <plugin>(<args>)
WHERE <condition>          -- supports =~ for regex, AND/OR
ORDER BY <column>
LIMIT <n>
```

## Custom artifact YAML structure

```yaml
name: Custom.Category.Name
description: What it does.
parameters:
  - name: param1
    default: value
sources:
  - query: |
      SELECT * FROM plugin() WHERE col =~ param1
```

## Default ports

| Service | Port |
|---------|------|
| Frontend (client comms) | 8000 |
| Admin GUI | 8889 |
