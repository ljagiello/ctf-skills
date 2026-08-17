# API Reference: Detecting Ransomware Encryption Behavior

## Shannon Entropy

Formula: H(X) = -Sum p(x) log2(p(x)). For byte data range is 0.0 to 8.0.

### Python Implementation

```python
import math
from collections import Counter

def shannon_entropy(data):
    freq = Counter(data)
    length = len(data)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())
```

### Entropy Thresholds

| Range | Interpretation | Example |
|-------|---------------|--------|
| 0.0-1.0 | Nearly uniform | Null files |
| 1.0-4.0 | Low entropy | Plain text |
| 4.0-6.0 | Mixed content | Office docs |
| 6.0-7.0 | Compressed | PDF |
| 7.0-7.5 | Highly compressed | ZIP JPEG |
| 7.5-7.9 | Block cipher encrypted | AES-CBC |
| 7.9-8.0 | Stream cipher encrypted | AES-CTR ChaCha20 |

## psutil Process IO Monitoring

```python
import psutil
proc = psutil.Process(pid)
io = proc.io_counters()
# Fields: read_bytes write_bytes read_count write_count
```

## Sysmon Event IDs

| Event ID | Event | Relevance |
|----------|-------|----------|
| 1 | Process Create | Identify encrypting process |
| 2 | File time changed | Timestomping |
| 11 | FileCreate | Ransom notes |
| 15 | FileCreateStreamHash | ADS usage |
| 23 | FileDelete | Shadow copy deletion |
| 26 | FileDeleteDetected | File deletion |

## Windows ETW Providers

Microsoft-Windows-Kernel-File GUID: EDD08927-9CC4-4E65-B970-C2560FB5C289

| Event ID | Description |
|----------|------------|
| 10 | Create (open) |
| 11 | Close |
| 12 | Read |
| 14 | Write |
| 15 | SetInformation |

## Behavioral Scoring

| Signal | Weight | Threshold |
|--------|--------|-----------|
| Files modified per min | 30 pts | Over 50 |
| Entropy delta | 30 pts | Over 3.0 |
| Extension changes | 20 pts | Over 10 |
| Ransom note creation | 20 pts | Any |

### Score Interpretation

| Score | Severity | Action |
|-------|----------|--------|
| 0-25 | INFO | Log |
| 25-50 | LOW | Alert SOC |
| 50-75 | HIGH | Suspend process |
| 75-100 | CRITICAL | Kill and isolate |

## Shadow Copy Deletion

| Command | Method |
|---------|--------|
| vssadmin delete shadows /all /quiet | VSS Admin |
| wmic shadowcopy delete | WMI |
| bcdedit /set recoveryenabled no | Disable recovery |
| wbadmin delete catalog -quiet | Delete backup |

## watchdog Library

| Method | Trigger |
|--------|--------|
| on_created | File created |
| on_modified | File modified |
| on_deleted | File deleted |
| on_moved | File renamed |

## Double Extension Detection

```python
parts = filename.rsplit(".", 2)
if len(parts) >= 3:
    original_ext = "." + parts[-2]
    appended_ext = "." + parts[-1]
```
