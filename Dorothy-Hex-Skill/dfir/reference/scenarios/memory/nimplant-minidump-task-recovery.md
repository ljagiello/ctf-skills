# NimPlant Mini DuMP — In-Memory Task Result Recovery

## When to use
PCAP-aware NimPlant engagements typically end before the operator session does. If a Mini DuMP (`.DMP`) of the implant process is also provided, additional task results often live in the heap that were never captured on the wire. This recovers them without volatility, using just the minidump library + a regex.

## The "decoy figlet flag" pattern
Forensics challenges of this family commonly ship a PCAP showing a `screenshot` task whose result is a Notepad window displaying figlet ASCII art that LOOKS like the flag (e.g. `HTB{B1G_Br0Th3r_iS_W4tCh1ng}`). Treat such figlet text as **part 1 of the flag — never the whole flag**. The second half is almost always:
- In the DMP heap as a **later, unseen task result** (most common), OR
- In a side channel (e.g. operator-uploaded `rev.exe` second-stage payload), OR
- In the implant's plaintext config TOML that's decoded at runtime (visible in heap)

If 30+ flag submissions of every leet/case permutation of the figlet text fail, **stop submitting** and switch to DMP excavation.

## Recipe — extract task results from a Mini DuMP

```python
import re, base64, gzip
from minidump.minidumpfile import MinidumpFile

DMP = "DbgInfo.DMP"
with open(DMP, "rb") as f:
    data = f.read()

# 1. Find every task-result JSON envelope in heap memory
# Pattern: {"guid": "<8 alphanum>", "result":"<base64>"}
matches = re.finditer(
    rb'\{"guid":\s*"([A-Za-z0-9]+)",\s*"result":"([A-Za-z0-9+/=]+)',
    data,
)

# 2. For each match, walk forward to the closing quote (results can be MB-sized)
for m in matches:
    guid = m.group(1).decode()
    b64_start = m.end() - len(m.group(2))
    end = b64_start
    while end < len(data) and data[end] != ord('"'):
        end += 1
    blob = data[b64_start:end]

    # 3. NimPlant double-encodes results: outer base64 -> inner base64 -> gzip -> PNG/text
    outer = base64.b64decode(blob + b'=' * (4 - len(blob) % 4))
    inner = base64.b64decode(outer)  # NimPlant nests base64
    if inner[:2] == b'\x1f\x8b':
        content = gzip.decompress(inner)
        ext = '.png' if content[:8] == b'\x89PNG\r\n\x1a\n' else '.bin'
        with open(f'task_{guid}{ext}', 'wb') as out:
            out.write(content)
        print(f'extracted task {guid}: {len(content)} bytes')
```

Also cross-check against PCAP task GUIDs — any GUID in the DMP but not the PCAP is a task that ran AFTER the capture ended.

## Recipe — figlet glyph dictionary template matching

When the screenshot shows figlet ASCII text in Notepad, the **Notepad status bar gives you the file dimensions for free**: `Ln 11, Col N, X characters`. Use this to constrain candidates:
- `chars = (cols_per_line × num_lines) + (num_lines - 1)` for Notepad's LF-only counting
- Render every plausible flag with `pyfiglet.Figlet(font='big_money-ne', width=400)` and filter to matching width

```python
import pyfiglet
f = pyfiglet.Figlet(font='big_money-ne', width=400)

def matches_notepad(text, target_chars=2826, target_cols=256, lines=11):
    r = f.renderText(text)
    rows = r.split('\n')
    while rows and rows[-1] == '':
        rows.pop()
    if len(rows) != lines:
        return False
    width = len(rows[0])
    if width != target_cols:
        return False
    total = sum(len(l) for l in rows) + (len(rows) - 1)  # +LF per line break
    return total == target_chars
```

For per-glyph disambiguation (`r` vs `R`, `1` vs `i`, `a` vs `4`), crop the screenshot to **row 1 only** (the topmost figlet row). Lowercase letters and digit `1` have empty top rows (or partial); capitals have content in row 1. Sample pixel darkness in a thin horizontal strip at y = (figlet_top + 1 to figlet_top + 8).

## Watch-out: pixel-correlation scoring is unreliable
Rendering figlet output via PIL with a monospace screen font then diffing against the Notepad raster yields IoU ~ 0.15-0.20 even for the correct candidate, because Notepad uses ClearType subpixel rendering and the figlet `$` glyph has 4-px-wide pseudo-3D shading that no replica reproduces. Use **column-based emptiness checks** instead (compare predicted empty-column ranges in row 1 to observed dark-pixel-free column ranges in the screenshot).

## Common false-positive: candidate matches dimensions but not glyph row 1
`big_money-ne` smushing rules mean adjacent letters can produce the same total width via different letter combinations. Example: `HTB{B1G_Br0Th3R_iS_W4tCh1ng}` (capital R + lowercase i + digit 4) gives the same 256 cols as `HTB{B1G_Br0Th3r_1S_W4tCh1ng}` (lowercase r + digit 1 + digit 4) padded with 6 trailing spaces per line. The Notepad char count cannot distinguish them — only the row-1 pixel content can. Build the candidate list from dimensions, **then** prune by checking row-1 emptiness at each position.

## When the flag is genuinely two halves
If after exhausting figlet variants you still get rejections:
1. The figlet TEXT alone is part 1 — submit `HTB{<figlet>_<X>}` where `<X>` is the AES key, the implant GUID, a derived MD5, or a string extracted from `rev.exe` (the operator's uploaded binary).
2. **DO NOT** assume the figlet rendering matches the literal flag character-for-character — the challenge designer may have added a leet substitution AFTER the figlet was rendered (so the figlet shows `i` but the flag actually uses `1`, etc.).
3. **DO NOT** waste >20 submissions on letter-case permutations. Switch to dynamic analysis of `rev.exe` in a Win10/11 VM with Procmon + Wireshark.

## Dual-channel redundancy — check ALL TCP streams, not just port 4444

NimPlant implants can register on MULTIPLE listening ports simultaneously. In HTB "Art of Capture", the implant listened on BOTH port 4444 (canonical) AND port 22 (disguised as SSH to evade casual analysis). The port-22 stream had:
- No SSH banner (`SSH-2.0-...` plaintext)
- HTTP traffic with NimPlant `/api/v2/login`, `/api/v2/ping`, `/api/v2/query` endpoints
- Same implant ID across both channels
- **Same AES session key** decrypts both streams (implant generates one key, reuses across channels)

**Diagnostic recipe**:
```bash
# List ALL TCP conversations
tshark -r capture.pcapng -q -z conv,tcp

# For any non-4444 stream, check first non-zero payload for SSH banner:
tshark -r capture.pcapng -Y "tcp.stream==N and tcp.payload" -T fields -e tcp.payload | head -1 | python3 -c "
import sys; b=bytes.fromhex(sys.stdin.read().strip())
print('preview:', ''.join(chr(c) if 32<=c<127 else '.' for c in b[:100]))
"
# No SSH-2.0 prefix + uniform-size packets = custom C2. Look for /api/v2/login.
# If present, decrypt with the SAME AES key recovered from any other channel.
```

The dual-channel pattern is a connectivity-failover technique — both streams carry the SAME tasks, SAME outputs, bit-identical screenshots. Decrypting both is still essential for forensic completeness but rarely yields new intel beyond what one channel reveals. Don't assume "second channel = new data."

## See also
- [c2-traffic-decryption.md](../../c2-traffic-decryption.md) — NimPlant AES-CTR session key recovery from `k` field XOR
- [volatility-process-analysis.md](volatility-process-analysis.md) — when Volatility profile loading fails on minidumps, fall back to `minidump` Python library
