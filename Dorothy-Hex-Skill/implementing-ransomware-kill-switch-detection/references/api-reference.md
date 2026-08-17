# API Reference: Ransomware Kill Switch Detection

## Windows Mutex (Mutant) APIs

### CreateMutex (kernel32.dll)
```c
HANDLE CreateMutexW(
  LPSECURITY_ATTRIBUTES lpMutexAttributes,  // NULL for default
  BOOL bInitialOwner,                       // TRUE to own immediately
  LPCWSTR lpName                            // Named mutex string
);
// Returns: Handle to mutex, or NULL on failure
// GetLastError() == ERROR_ALREADY_EXISTS (183) if mutex already exists
```

### OpenMutex (kernel32.dll)
```c
HANDLE OpenMutexW(
  DWORD dwDesiredAccess,  // SYNCHRONIZE (0x00100000)
  BOOL bInheritHandle,    // FALSE
  LPCWSTR lpName          // Named mutex string
);
// Returns: Handle if exists, NULL if not found
```

### PowerShell Mutex Operations
```powershell
# Create a named mutex
$created = $false
$m = New-Object System.Threading.Mutex($true, "Global\MutexName", [ref]$created)

# Check if mutex exists
try {
  $m = [System.Threading.Mutex]::OpenExisting("Global\MutexName")
  "EXISTS"
} catch { "NOT_FOUND" }
```

## Known Ransomware Kill Switch Mutexes

| Mutex Name | Family | Notes |
|-----------|--------|-------|
| Global\MsWinZonesCacheCounterMutexA | WannaCry | Single-instance guard |
| Global\kasKDJSAFJauisiudUASIIQWUA82 | Conti | Instance mutex |
| Global\YOURPRODUCT_MUTEX | Ryuk variant | Instance guard |
| Global\JhbGjhBsSQjz | Maze | Single-instance check |
| Global\{GUID-based} | LockBit | Machine-specific GUID |
| Global\sdjfhksjdhfsd | Generic builders | Common in kits |

## Known Kill Switch Domains

| Domain | Family | Discovered By |
|--------|--------|--------------|
| iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com | WannaCry v1 | MalwareTech (2017) |
| fferfsodp9ifjaposdfjhgosurijfaewrwergwea.com | WannaCry v1 | Secondary switch |

## Sysmon Configuration for Mutex Detection

### Event ID 1 - Process Creation
```xml
<Sysmon schemaversion="4.90">
  <EventFiltering>
    <ProcessCreate onmatch="include">
      <Image condition="excludes">C:\Windows\</Image>
    </ProcessCreate>
  </EventFiltering>
</Sysmon>
```

## Velociraptor Mutex Hunting

### Windows.Detection.Mutants Artifact
```sql
SELECT * FROM glob(globs="\\BaseNamedObjects\\*")
WHERE Name =~ "MsWinZonesCacheCounterMutexA|kasKDJSAF|YOURPRODUCT"
```

### Sysinternals Handle Tool
```cmd
handle.exe -a | findstr /i "Mutant"
handle.exe -a -p <PID> | findstr /i "Mutant"
```

## DNS Kill Switch Monitoring

### Python DNS Resolution Check
```python
import socket

def check_domain(domain):
    try:
        ip = socket.gethostbyname(domain)
        return {"resolves": True, "ip": ip}
    except socket.gaierror:
        return {"resolves": False}
```

### Passive DNS Services
| Service | URL | Notes |
|---------|-----|-------|
| VirusTotal | virustotal.com | Domain resolution history |
| PassiveTotal | community.riskiq.com | DNS record history |
| SecurityTrails | securitytrails.com | Domain intelligence |

## Malware Mutex Database

### albertzsigovits/malware-mutex (GitHub)
```
URL: https://github.com/albertzsigovits/malware-mutex
Format: JSON with mutex name, malware family, source reference
```

### ANY.RUN Mutex Search
```
URL: https://any.run/cybersecurity-blog/mutex-search-in-ti-lookup/
Search: Threat Intelligence Lookup → Synchronization → Mutex name
```

## Mutex Vaccination Deployment Methods

| Method | Persistence | Scope |
|--------|------------|-------|
| GPO Startup Script | Survives reboot | Domain-wide |
| Scheduled Task (at logon) | Survives reboot | Per-machine |
| Windows Service | Survives reboot | Per-machine |
| Manual PowerShell | Until reboot | Current session |

### GPO Startup Script Path
```
Computer Configuration → Policies → Windows Settings →
Scripts (Startup/Shutdown) → Startup → Add Script
```
