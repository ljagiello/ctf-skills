# API Reference: Decoy Files for Ransomware Detection

## watchdog Library (Python)

### Installation
```bash
pip install watchdog
```

### Observer Setup
```python
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

observer = Observer()
observer.schedule(handler, path, recursive=True)
observer.start()
observer.join()
```

### Event Types
| Event Class | Trigger |
|------------|---------|
| `FileCreatedEvent` | New file created in watched directory |
| `FileModifiedEvent` | Existing file content or metadata changed |
| `FileDeletedEvent` | File removed from watched directory |
| `FileMovedEvent` | File renamed or moved (src_path, dest_path) |
| `DirCreatedEvent` | New directory created |
| `DirDeletedEvent` | Directory removed |

### Handler Methods
| Method | Called When |
|--------|-----------|
| `on_created(event)` | File/directory created |
| `on_modified(event)` | File/directory modified |
| `on_deleted(event)` | File/directory deleted |
| `on_moved(event)` | File/directory renamed/moved |
| `on_any_event(event)` | Any file system event |

## Windows ReadDirectoryChangesW API

### Monitored Changes
| Flag | Description |
|------|-------------|
| `FILE_NOTIFY_CHANGE_FILE_NAME` | File created, deleted, or renamed |
| `FILE_NOTIFY_CHANGE_DIR_NAME` | Directory changes |
| `FILE_NOTIFY_CHANGE_SIZE` | File size changed |
| `FILE_NOTIFY_CHANGE_LAST_WRITE` | Last write time changed |
| `FILE_NOTIFY_CHANGE_SECURITY` | Security descriptor changed |

## Linux inotify Events

### Event Masks
| Mask | Description |
|------|-------------|
| `IN_MODIFY` | File was modified |
| `IN_DELETE` | File was deleted |
| `IN_MOVED_FROM` | File was renamed (old name) |
| `IN_MOVED_TO` | File was renamed (new name) |
| `IN_CREATE` | File was created |
| `IN_ATTRIB` | Metadata changed |

## Canarytokens (Thinkst)

### Generate Token
```
URL: https://canarytokens.org/generate
Types: Word document, PDF, DNS, HTTP, AWS key, SQL, SVN
```

### Alert Webhook
```
POST https://canarytokens.org/webhook
Payload: { "token": "...", "src_ip": "...", "time": "..." }
```

## OSSEC/Wazuh File Integrity Monitoring

### Configuration (ossec.conf)
```xml
<syscheck>
  <frequency>60</frequency>
  <directories check_all="yes" realtime="yes">/path/to/canaries</directories>
  <alert_new_files>yes</alert_new_files>
</syscheck>
```

### Alert Rule IDs
| Rule ID | Description |
|---------|-------------|
| 550 | File integrity checksum changed |
| 553 | File deleted |
| 554 | New file added to monitored directory |

## Sysmon File Monitoring

### Event ID 11 - FileCreate
```xml
<FileCreate onmatch="include">
  <TargetFilename condition="contains">_AAAA_</TargetFilename>
  <TargetFilename condition="contains">~zzzz_</TargetFilename>
</FileCreate>
```

### Event ID 23 - FileDelete
Logs file deletions including archived file content.

## Common Ransomware File Extensions

| Extension | Family |
|-----------|--------|
| .locked | LockBit, Generic |
| .encrypted | Generic |
| .wncry | WannaCry |
| .dharma | Dharma/CrySiS |
| .basta | Black Basta |
| .lockbit | LockBit 3.0 |
| .conti | Conti |
| .ryuk | Ryuk |
| .revil | REvil/Sodinokibi |
| .akira | Akira |
