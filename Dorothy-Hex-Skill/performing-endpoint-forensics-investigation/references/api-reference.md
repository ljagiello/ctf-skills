# API Reference — Performing Endpoint Forensics Investigation

## Libraries Used

| Library | Purpose |
|---------|---------|
| `subprocess` | Execute Windows forensic commands (wmic, netstat, reg, schtasks) |
| `hashlib` | Calculate MD5, SHA1, SHA256 hashes for evidence integrity |
| `csv` | Parse WMIC CSV output |
| `json` | Structure and export forensic triage results |
| `datetime` | Timestamp evidence collection |
| `argparse` | CLI argument parsing for triage modes |

## CLI Interface

```bash
python agent.py triage      # Full forensic triage
python agent.py processes   # Running processes with PIDs and command lines
python agent.py network     # Active network connections
python agent.py autoruns    # Persistence entries
python agent.py hash --file <filepath>  # Hash file for evidence
```

## Core Functions

### `full_triage()` — Run all collection functions
```python
def full_triage():
    """Execute full forensic triage and return combined results."""
    return {
        "timestamp": datetime.now().isoformat(),
        "hostname": collect_system_info()["hostname"],
        "system_info": collect_system_info(),
        "processes": collect_running_processes(),
        "network": collect_network_connections(),
        "autoruns": collect_autoruns(),
        "users": collect_user_accounts(),
    }
```

### `collect_system_info()` — Hostname, OS version, network config, uptime
```python
def collect_system_info():
    result = subprocess.run(
        ["systeminfo"], capture_output=True, text=True, timeout=60,
    )
    info = {}
    for line in result.stdout.split("\n"):
        if ":" in line:
            key, _, val = line.partition(":")
            info[key.strip()] = val.strip()
    return {
        "hostname": info.get("Host Name", ""),
        "os_name": info.get("OS Name", ""),
        "os_version": info.get("OS Version", ""),
        "system_boot_time": info.get("System Boot Time", ""),
        "total_physical_memory": info.get("Total Physical Memory", ""),
        "domain": info.get("Domain", ""),
    }
```

### `collect_running_processes()` — Process list via `wmic process get`
```python
def collect_running_processes():
    result = subprocess.run(
        ["wmic", "process", "get",
         "ProcessId,Name,ExecutablePath,CommandLine,ParentProcessId",
         "/format:csv"],
        capture_output=True, text=True, timeout=30,
    )
    processes = []
    reader = csv.DictReader(result.stdout.strip().split("\n"))
    for row in reader:
        if row.get("Name"):
            processes.append({
                "pid": row.get("ProcessId"),
                "name": row.get("Name"),
                "path": row.get("ExecutablePath", ""),
                "cmdline": row.get("CommandLine", ""),
                "ppid": row.get("ParentProcessId"),
            })
    return processes
```

### `collect_network_connections()` — Active connections via `netstat -ano`
```python
def collect_network_connections():
    result = subprocess.run(
        ["netstat", "-ano"], capture_output=True, text=True, timeout=15,
    )
    connections = []
    for line in result.stdout.strip().split("\n")[4:]:
        parts = line.split()
        if len(parts) >= 5:
            connections.append({
                "proto": parts[0],
                "local_address": parts[1],
                "remote_address": parts[2],
                "state": parts[3] if parts[3] != parts[-1] else "",
                "pid": parts[-1],
            })
    return connections
```

### `collect_autoruns()` — Registry Run keys and scheduled tasks
```python
RUN_KEYS = [
    r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
]

def collect_autoruns():
    autoruns = {"registry_run_keys": [], "scheduled_tasks": []}

    for key in RUN_KEYS:
        result = subprocess.run(
            ["reg", "query", key], capture_output=True, text=True, timeout=10,
        )
        for line in result.stdout.strip().split("\n"):
            parts = line.strip().split("    ")
            if len(parts) >= 3:
                autoruns["registry_run_keys"].append({
                    "key": key,
                    "name": parts[0].strip(),
                    "value": parts[-1].strip(),
                })

    result = subprocess.run(
        ["schtasks", "/query", "/fo", "csv", "/v"],
        capture_output=True, text=True, timeout=30,
    )
    reader = csv.DictReader(result.stdout.strip().split("\n"))
    for row in reader:
        if row.get("TaskName") and row.get("Status") == "Ready":
            autoruns["scheduled_tasks"].append({
                "name": row.get("TaskName"),
                "next_run": row.get("Next Run Time"),
                "task_to_run": row.get("Task To Run"),
                "run_as_user": row.get("Run As User"),
            })

    return autoruns
```

### `collect_user_accounts()` — Local user enumeration
```python
def collect_user_accounts():
    result = subprocess.run(
        ["net", "user"], capture_output=True, text=True, timeout=10,
    )
    users = []
    for line in result.stdout.strip().split("\n")[4:]:
        for name in line.split():
            if name and not name.startswith("-"):
                users.append(name)
    return users
```

### `hash_file(filepath)` — MD5/SHA1/SHA256 hash calculation
```python
def hash_file(filepath):
    """Calculate cryptographic hashes for evidence integrity."""
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()

    with open(filepath, "rb") as f:
        while chunk := f.read(8192):
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)

    return {
        "file": filepath,
        "md5": md5.hexdigest(),
        "sha1": sha1.hexdigest(),
        "sha256": sha256.hexdigest(),
    }
```

## Output Format

```json
{
  "timestamp": "2025-01-15T10:30:00",
  "hostname": "WORKSTATION-01",
  "system_info": {
    "os_name": "Microsoft Windows 10 Pro",
    "os_version": "10.0.19045",
    "domain": "CORP"
  },
  "processes": [
    {"pid": "4532", "name": "powershell.exe", "cmdline": "powershell -enc ..."}
  ],
  "network": [
    {"proto": "TCP", "local_address": "10.0.0.5:49721", "remote_address": "198.51.100.42:443", "state": "ESTABLISHED", "pid": "4532"}
  ],
  "autoruns": {
    "registry_run_keys": [
      {"key": "HKCU\\...\\Run", "name": "WindowsUpdate", "value": "C:\\Users\\Public\\update.exe"}
    ],
    "scheduled_tasks": 45
  }
}
```

## Dependencies

No external packages — uses Windows built-in commands and Python standard library.
