# API Reference: USB Device Control Policy Audit

## Libraries Used

| Library | Purpose |
|---------|---------|
| `subprocess` | Execute PowerShell, udevadm, and registry query commands |
| `json` | Parse device inventory and policy status |
| `platform` | Detect operating system for platform-specific checks |
| `re` | Parse device IDs and USB vendor/product codes |

## Installation

```bash
# No external packages — uses standard library and OS tools
```

## Windows USB Device Audit

### List Connected USB Devices (PowerShell)
```python
import subprocess
import json

def list_usb_devices_windows():
    cmd = [
        "powershell", "-Command",
        "Get-PnpDevice -Class USB | Select-Object Status, Class, FriendlyName, InstanceId | ConvertTo-Json"
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    return json.loads(result.stdout) if result.stdout else []
```

### Check USB Storage Policy (Registry)
```python
def check_usb_storage_policy():
    """Check if USB mass storage is disabled via registry."""
    cmd = [
        "powershell", "-Command",
        'Get-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\USBSTOR" -Name Start | Select-Object Start | ConvertTo-Json'
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
    if result.stdout:
        data = json.loads(result.stdout)
        start_value = data.get("Start", 3)
        return {
            "usb_storage_disabled": start_value == 4,
            "registry_value": start_value,
            "policy": "disabled" if start_value == 4 else "enabled",
            "detail": {
                3: "USB storage ENABLED (default)",
                4: "USB storage DISABLED",
            }.get(start_value, f"Unknown value: {start_value}"),
        }
    return {"usb_storage_disabled": False, "error": "Could not read registry"}
```

### Check Group Policy for Removable Storage
```python
def check_gpo_removable_storage():
    """Check GPO settings for removable storage restrictions."""
    policies = {
        "deny_read": r"HKLM\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices\{53f5630d-b6bf-11d0-94f2-00a0c91efb8b}\Deny_Read",
        "deny_write": r"HKLM\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices\{53f5630d-b6bf-11d0-94f2-00a0c91efb8b}\Deny_Write",
        "deny_execute": r"HKLM\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices\{53f5630d-b6bf-11d0-94f2-00a0c91efb8b}\Deny_Execute",
    }
    results = {}
    for name, path in policies.items():
        cmd = ["reg", "query", path.rsplit("\\", 1)[0], "/v", path.rsplit("\\", 1)[1]]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        results[name] = "1" in result.stdout if result.returncode == 0 else False
    return results
```

### USB Device History (Windows)
```python
def get_usb_history_windows():
    """List previously connected USB storage devices from registry."""
    cmd = [
        "powershell", "-Command",
        'Get-ItemProperty "HKLM:\\SYSTEM\\CurrentControlSet\\Enum\\USBSTOR\\*\\*" | Select-Object FriendlyName, DeviceDesc, Mfg | ConvertTo-Json'
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    return json.loads(result.stdout) if result.stdout else []
```

## Linux USB Device Audit

### List USB Devices
```python
def list_usb_devices_linux():
    result = subprocess.run(
        ["lsusb"], capture_output=True, text=True, timeout=10
    )
    devices = []
    for line in result.stdout.strip().split("\n"):
        if line:
            devices.append(line.strip())
    return devices
```

### Check USBGuard Policy
```python
def check_usbguard_status():
    """Check if USBGuard is installed and active."""
    # Check service status
    result = subprocess.run(
        ["systemctl", "is-active", "usbguard"],
        capture_output=True, text=True, timeout=10,
    )
    service_active = result.stdout.strip() == "active"

    # List current policy rules
    rules = []
    if service_active:
        result = subprocess.run(
            ["usbguard", "list-rules"],
            capture_output=True, text=True, timeout=10,
        )
        rules = result.stdout.strip().split("\n") if result.stdout else []

    return {
        "usbguard_installed": service_active or result.returncode != 127,
        "service_active": service_active,
        "policy_rules": len(rules),
        "default_policy": "block" if any("block" in r for r in rules) else "allow",
    }
```

### Check udev Rules for USB Control
```python
def check_udev_rules():
    """Check for USB control udev rules."""
    result = subprocess.run(
        ["find", "/etc/udev/rules.d/", "-name", "*usb*", "-type", "f"],
        capture_output=True, text=True, timeout=10,
    )
    rules_files = result.stdout.strip().split("\n") if result.stdout.strip() else []
    return {"udev_usb_rules": rules_files, "count": len(rules_files)}
```

## Device Whitelist Management

```python
APPROVED_DEVICES = [
    {"vendor_id": "046d", "product_id": "c52b", "name": "Logitech Receiver"},
    {"vendor_id": "0781", "product_id": "5583", "name": "SanDisk Encrypted Drive"},
]

def check_against_whitelist(connected_devices, approved=APPROVED_DEVICES):
    approved_ids = {(d["vendor_id"], d["product_id"]) for d in approved}
    findings = []
    for device in connected_devices:
        vid = device.get("vendor_id", "")
        pid = device.get("product_id", "")
        if (vid, pid) not in approved_ids:
            findings.append({
                "device": device.get("name", "Unknown"),
                "vendor_id": vid,
                "product_id": pid,
                "issue": "Device not in approved whitelist",
                "severity": "medium",
            })
    return findings
```

## Output Format

```json
{
  "platform": "windows",
  "usb_storage_disabled": true,
  "gpo_deny_read": true,
  "gpo_deny_write": true,
  "connected_devices": 3,
  "unapproved_devices": 1,
  "historical_devices": 12,
  "findings": [
    {
      "device": "Unknown USB Mass Storage",
      "vendor_id": "0951",
      "product_id": "1666",
      "issue": "Device not in approved whitelist",
      "severity": "medium"
    }
  ]
}
```
