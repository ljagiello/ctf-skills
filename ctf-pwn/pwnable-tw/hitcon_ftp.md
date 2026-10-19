---
tags:
  - heap-buffer-overflow
  - seccomp-bypass
  - rop
platform: pwnable.tw
points: 500
arch: x86-64
libc: glibc-2.27
relro: full
canary: yes
nx: yes
pie: yes
references:
  - https://pwnable.tw/challenge/
description: "Heap corruption in msgpack packet deserialization allows hijacking execution under seccomp, constructing an open-read-write ROP chain."
proof-of-concept: no
---

# HITCON FTP — pwnable.tw (500 pts)

[← Back to pwnable.tw Challenge Index](README.md)

> Nobody find all vulnerabilities in HITCON CTF final 2019. :'(
>
> `nc chall.pwnable.tw 10309`
>
> Flag: `FLAG{c4ptur3_th3_f0rtun3_by_h1tc0n_ftp}`

## Challenge Overview

A custom TFTP-like server (x86-64, Full RELRO, Canary, NX, PIE) running over UDP, using msgpack for packet serialization. The server allocates a UDP port per connection, parses msgpack arrays as commands (RRQ=1, WRQ=2, DATA=3, ACK=4, ERR=5, OACK=6), and supports file read/write with CRC32 verification and block size negotiation. A seccomp sandbox restricts syscalls to file I/O, networking (socket/sendto/recvfrom/bind), memory management (mmap/mprotect/brk), and select. The main loop runs under a `SIGALRM` timer (~60s); when it fires, `select()` fails and `main()` returns.

```
checksec:
  Arch:     amd64-64-little
  RELRO:    Full RELRO           # GOT read-only
  Stack:    Canary found
  NX:       NX enabled
  PIE:      PIE enabled
  Seccomp:  Allowlist (open, read, write, close, stat, fstat, lseek,
            ioctl, openat, brk, mmap, mprotect, select, socket,
            sendto, recvfrom, bind, rt_sigreturn, exit, exit_group)
```

## Vulnerabilities

### V1 — Heap Address Leak via Non-Terminated Filename (Info Leak)

**Root Cause:** The request struct stores `filename` in a 0x100-byte buffer. When the server receives a filename containing `"../"`, it rejects the access and formats an error message using `snprintf` with the full filename. If the filename is exactly 0x100 bytes, `strncpy` does not NUL-terminate it, and the adjacent `FILE *fp` pointer in the struct is concatenated into the error response.

```c
// Simplified: filename is 0x100 bytes, FILE* follows immediately
struct Request {
    // ...
    char filename[0x100];   // +0x010
    FILE *fp;               // +0x110
    // ...
};
strncpy(req->filename, via.str.ptr, via.str.size);  // no NUL if size == 0x100
// error path:
snprintf(buf, ..., "file (%s) access violation", req->filename);
// leaks fp pointer bytes after the filename
```

**Trigger:** Send a first WRQ to initialize `fp`, then send a RRQ with `"../".ljust(0x100, "A")` as filename. The error response includes the `FILE*` heap pointer appended after the 'A' padding.

**Impact:** Leaks a heap address. Heap base = `leaked_ptr - 0x22ad0`.

### V2 — Type Confusion in OACK Options Processing (Arbitrary Read)

**Root Cause:** When processing RRQ/WRQ packets, the server checks if `array[3]` is a `MSGPACK_OBJECT_MAP` — but **only when `array.size == 4`**. If the array has 5+ elements, the check is skipped entirely, and `array[3]` of any type is interpreted as a map of `msgpack_object_kv` entries.

```c
// Simplified condition — note the short-circuit with ==4
if (via.array.size == 4 && via.array.ptr[3].type != MSGPACK_OBJECT_MAP)
    return error;
// When array.size >= 5, array[3] passes unchecked
```

By sending a string or raw bytes as `array[3]`, the attacker controls the in-memory layout interpreted as `msgpack_object_kv` structs. A fake entry with `key.type = MSGPACK_OBJECT_STR`, `key.ptr = target_address`, and `val.type = MSGPACK_OBJECT_POSITIVE_INTEGER` causes the server to read memory at `target_address` and include it as an OACK option key in the response.

**Trigger:**
```python
fake_kv = p64(5) + p64(0x3f) + p64(target_addr) + p64(2) + p64(0x1337)
send([1, "flag", "octet", fake_kv, "pad"])  # array size=5, bypasses check
# Response: OACK with key = memory_at_target_addr (up to 63 bytes)
```

**Impact:** Arbitrary read of up to 63 bytes at any address. Used to leak libc (via `_IO_file_jumps` or GOT), stack (via `environ`), PIE base, and canary.

### V3 — Stack Buffer Overflow in `check_crc32` / `msgpack_object_print_buffer` (Code Execution)

**Root Cause:** The CRC32 verification function calls `msgpack_object_print_buffer(error_buf, payload_len, obj)` where `error_buf` is a 0x204-byte stack buffer but `payload_len` is controlled via the negotiated `blksize` option (up to 0xFFFF). When `blksize` is set large, `snprintf` writes the string representation of the msgpack data object far past the buffer boundary, overwriting the canary, saved RBP, and return address of `main()`.

```c
// check_crc32 — simplified
char error_buf[0x204];  // stack buffer
// obj_len comes from the DATA packet's payload length (controlled via blksize)
msgpack_object_print_buffer(error_buf, obj_len, data_obj);
// snprintf inside print_buffer writes string repr of data_obj to error_buf
// If obj_len > 0x204, this overflows the stack
```

**Complication:** Since `snprintf` is used internally, NUL bytes cannot be written directly. Solvers work around this by writing the payload in reverse order — each write uses `snprintf`'s automatic NUL terminator to place zeros at decreasing offsets.

**Impact:** Full stack buffer overflow. Combined with leaked canary, enables ROP chain or stack pivot.

## Exploit Paths

All 20 solutions use the same three-bug chain (V1 → V2 → V3). They differ in the leak chain specifics and the final payload strategy.

---

### Path A — Stack Pivot to Heap → mprotect + Shellcode (Most Common)

**Used by:** Solutions 370, 821, 2972, 5586, 8153, 31599, 34306, 35463, 36997

1. **V1:** Leak heap via overlong `"../"` filename.
2. **V2:** Leak libc (`_IO_file_jumps` or `_IO_2_1_stderr_` from FILE struct on heap), stack (`environ`), canary (stack+offset+1, skip leading NUL), and optionally PIE base.
3. **V3:** Set `blksize` to 0xFFFF. Repeatedly overflow `check_crc32`'s stack buffer to write backwards:
   - Restore canary (write bytes 1-7, then NUL-terminate byte 0)
   - Overwrite saved RBP with pointer to `datain` buffer (heap) or a controlled region
   - Overwrite return address with `leave; ret` gadget (stack pivot)
4. **Send ROP chain to `datain` buffer:** `pop rdi; heap_page; pop rsi; 0x1000; pop rdx; 7; mprotect; shellcode_addr`
5. **Shellcode:** `open("/home/hitcon_ftp/flag") → read(fd, buf, 0x100) → sendto(0, buf, len, 0, saved_sockaddr, 16)` — sends flag back over UDP to the attacker's address (extracted from the request struct on heap).
6. **Wait ~60s** for SIGALRM → `select()` fails → `main()` returns into ROP.

### Path B — Direct ROP Chain on Stack (No Shellcode)

**Used by:** Solutions 3578, 6748, 28605, 28652, 34817, 36134

Same leak chain, but instead of pivoting:
1. Write the full ROP chain directly onto `main()`'s stack frame via repeated `check_crc32` overflows.
2. ROP: `open(flag_path) → read(fd, buffer, N) → sendto(0, buffer, N, 0, sockaddr, 16)` using libc gadgets and syscall.
3. Some variants call the binary's own `send_err()` / `process_send()` function (at PIE+0x2855 or similar) to send the flag through the existing TFTP protocol.

### Path C — `close(3) + open(flag)` → Reuse Existing FILE (Clever Variant)

**Used by:** Solution 6748

1. ROP chain does: `close(3)` (the server's open file descriptor), then `open("/home/hitcon_ftp/flag")` which reuses fd 3.
2. Then calls the binary's own `process_send(request)` function, which reads from the FILE associated with fd 3 — now pointing to the flag file — and sends the data back through normal TFTP protocol.

### Path D — CRC32 Brute-Force for Initial Leak (No V1 Needed)

**Used by:** Solutions 9251, 11177, 33090, 34817

Instead of using V1 for the heap leak:
1. Exploit the `strlen()` in `check_crc32` — the CRC is computed on the buffer up to the first NUL byte. By padding to known stack offsets and brute-forcing one byte at a time (256 attempts per byte), the attacker can determine stack values by checking whether `CRC32(padding + guess_byte) == expected`.
2. Brute-force 4-5 bytes of a stack pointer (only ~5×256 = 1280 packets). This gives a code/PIE base address.
3. Then use V2 for remaining leaks (libc, canary, heap) and V3 for the overflow.

**Downside:** Slower (~1280 round-trips vs. 1 for V1), requires low-latency connection. Some solvers ran from Japan VPS to avoid timeout.

### Path E — Canary Leak via TLS/ld.so (Alternative to Stack Canary Leak)

**Used by:** Solution 3498

Instead of leaking the canary from the stack:
1. Use V2 to read `_rtld_global` from libc → get `ld.so` base → read TLS block → extract canary from `tcbhead_t.stack_guard` (at TLS+0xba8 or similar offset).
2. This avoids needing to know the exact stack layout for canary position.

### Path F — Auxv Walk for PIE + Canary (exp.py approach)

**Used by:** exp.py (the reference exploit in this directory)

1. **V1:** Leak heap via msgpack ExtType trick (send many map keys to cause realloc, then parse leaked key from reused memory).
2. **V2:** Read `FILE*` from request struct → `_IO_file_jumps` → libc base. Read `environ` → stack. Walk `envp[]` until NUL → find `auxv[]`. Parse `AT_PHDR` → PIE base. Parse `AT_RANDOM` → read 16-byte random blob → extract canary (first 8 bytes, mask low byte to 0).
3. **V3:** Build ROP chain image, split at NUL bytes into stages. Each stage is sent as a WRQ+DATA pair; `snprintf`'s NUL terminator handles the zero bytes. ROP: `open(flag) → read(3, buf, 0x80) → send_data(request, buf, 0x80) → exit(0)`.

## Leak Primitives Summary

| What | How | Source |
|------|-----|--------|
| Heap base | V1: `"../"` filename overflow leaks `FILE*` | All solutions except Path D |
| Heap base (alt) | V3: CRC32 brute-force of stack pointers → V2 read | Path D solutions |
| libc base | V2: Read `_IO_file_jumps` / `_IO_2_1_stderr_` / GOT entry from heap or binary | Universal |
| Stack address | V2: Read `libc.environ` | Universal |
| PIE base | V2: Read return address from stack, or V3: CRC32 brute | Most solutions |
| Stack canary | V2: Read `stack_addr - offset + 1` (skip NUL byte 0) | Most solutions |
| Canary (alt) | V2: Read TLS `stack_guard` via `_rtld_global` chain | Solution 3498 |
| Canary (alt) | V2: Read `AT_RANDOM` from auxv, first 8 bytes | exp.py |

## Execution Trigger

The SIGALRM handler does **not** call `exit()`. Instead, the signal interrupts `select()`, which returns `-1` (EINTR), causing the main loop to break and `main()` to return — into the attacker's ROP chain. All solutions must wait ~60 seconds for this to happen.

## Key Offsets (remote libc, glibc 2.27)

```python
# libc gadgets
pop_rdi     = 0x2155f
pop_rsi     = 0x23e6a
pop_rdx     = 0x1b96
pop_rax     = 0x439c8
pop_rsp     = 0x3960
pop_rdx_r10 = 0x1306b4
syscall_ret = 0xd2975
leave_ret   = 0x54803

# libc symbols / offsets
_IO_file_jumps = 0x3e82a0
_IO_2_1_stderr = 0x3ec680
environ        = 0x3ee098
mprotect       = 0x11bae0

# Binary internals
request_delta  = 0x13b10   # from heap base to first request struct
send_data      = 0x257e    # PIE offset: function to send data via TFTP
send_err       = 0x2855    # PIE offset: function to send error via TFTP
flag_path_bss  = 0x20d160  # PIE offset: "/home/hitcon_ftp/flag" if stored via OACK
```

## Seccomp Policy

Allowlist: `rt_sigreturn`, `exit_group`, `exit`, `open`, `read`, `write`, `close`, `stat`, `fstat`, `lseek`, `ioctl`, `openat`, `brk`, `mmap`, `mprotect`, `select`, `socket`, `sendto`, `recvfrom`, `bind`. All others → KILL.

This blocks `execve`, so all exploits must use open/read + sendto to exfiltrate the flag.

## Solution Write-ups

| File | Primary Path | Key Technique | Notes |
|------|-------------|---------------|-------|
| `370.md` | A | Heap leak → mprotect + shellcode (sendto via saved sockaddr) | Clean, uses pwntools shellcraft |
| `821.md` | A | mprotect + handcrafted shellcode | Detailed DATA_HDR constants, finds datain buffer |
| `2972.md` | A | mprotect + jmp rsp shellcode | Uses `jmp rsp` gadget after mprotect |
| `3498.md` | A + E | Canary via TLS (_rtld_global chain) | Alternative canary leak path |
| `3578.md` | B | Direct ROP: open/read/sendto | Uses binary's `send_err` to return flag |
| `5586.md` | A | mprotect + shellcode | Finds sockaddr from heap request struct |
| `6748.md` | B + C | `close(3) + open(flag)` → reuse fd 3 via `process_send` | Elegant fd-hijack variant |
| `8153.md` | A | leave;ret pivot → mprotect + sendto shellcode | Clean null-byte handling |
| `9251.md` | D | CRC32 brute-force for libc_pthread → heap scan | Brutes 4 bytes of libpthread address |
| `11177.md` | D | CRC32 brute-force for stack pointer | Brutes 5 stack bytes, then arb read for rest |
| `25916.md` | B | Direct ROP: open/read/sendto via syscall | Uses raw syscall gadgets |
| `28605.md` | A | Heap leak → mprotect + asm sendto | Detailed vuln explanation |
| `28652.md` | B | ROP: open → xchg_eax_edi → read → `send_err` | Calls binary's own send function |
| `31599.md` | A | leave;ret pivot → open/read → `send_data` | Uses PIE `send_data` to return flag |
| `33090.md` | D | CRC32 brute-force for PIE base | Brutes 5 bytes across multiple stack offsets |
| `34306.md` | A | mprotect + typed shellcode | Patches `process_new` comparison in memory |
| `34817.md` | D + B | CRC32 brute PIE → arb read → direct ROP | Calls `send_err` at end |
| `35463.md` | A | mprotect + typed shellcode with sendto | 3 bugs: bof, type confusion, argument mismatch |
| `36134.md` | B | Direct ROP: open/read → `send_err` | Cleanest ROP, reuses binary's error-send path |
| `36997.md` | A | mprotect + shellcode, create UDP socket in SC | Shellcode creates new socket to send flag |

## Files

| File | Description |
|------|-------------|
| `exp.py` | Reference exploit (auxv walk + multi-stage NUL-byte-safe overflow) |
| `desc.txt` | Challenge description |
| `artifacts/hitcon_ftp` | Challenge binary |
| `solution/*.md` | Community write-ups (20 solutions) |
