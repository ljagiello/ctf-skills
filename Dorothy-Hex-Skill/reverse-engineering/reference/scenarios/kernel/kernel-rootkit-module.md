# Kernel Rootkit / Linux Module — Reverse + Runtime Bypass

## When this applies

- Target is a Linux Kernel Module (`.ko`, `file` reports `ELF 64-bit LSB relocatable`).
- Module hooks system calls (`hook_read`, `hook_write`, `hook_syslog`, ftrace `register_ftrace_function`, `register_kprobe`).
- A live VM/container is provided where the module is loaded; flag is hidden by the rootkit at runtime.
- Static `strings` shows an obvious fake/decoy flag in `.rodata` (e.g. `<PREFIX>{fake_flag_for_reversing_only}`) — the real flag is **runtime-only**.

## Core principle

The rootkit filters reads from specific kernel pseudo-files (`/proc/kallsyms`, `/dev/kmsg`, `/proc/modules`, `/sys/kernel/tracing/enabled_functions`). It compares the dentry name of the read fd to a hard-coded list (`kmsg`, `kallsyms`, `enabled_functions` etc.) and strips lines matching a substring (typically the module's own name, like `malware`).

**Bypass: read kernel memory via a filename NOT in the filter list.** `/proc/kcore` is virtually never filtered and exposes the full kernel virtual address space. The module's `.rodata` (including the real flag string) lives there in plaintext.

## Steps

### 1. Static triage of the `.ko`

```bash
file malware.ko                                  # ELF relocatable, vermagic shows target kernel
strings malware.ko | grep -E '^(FLAG|flag|<PREFIX>)\{'   # decoy flag if any
objdump -t malware.ko | grep -E 'hook_|fh_'     # hook function symbols
objdump -d malware.ko --section=.text           # disassemble hooks
objdump -s -j .rodata.str1.1 -j .rodata.str1.8 malware.ko  # filter targets
objdump -r --section=.rela.text malware.ko      # which strings each hook references
```

Map each hook's `rep cmpsb` length to a string in `.rodata` — that's the filter target. Map the `strstr` reference to the substring being scrubbed from output (usually the module name).

### 2. Connect to the VM and confirm runtime hooks

```bash
ls -la /sys/module/<modname>           # hidden -> rootkit confirmed
cat /proc/modules                      # empty/missing module -> hide() succeeded
cat /proc/sys/kernel/tainted           # bits 12 (OOT) + 13 (UNSIGNED) = 12288 -> module loaded
grep <modname> /proc/kallsyms          # 0 matches -> read hook is filtering
grep '\[' /proc/kallsyms | head        # only ftrace_trampolines visible -> module symbols filtered
```

### 3. Parse `/proc/kcore` program headers to find module memory range

`/proc/kcore` is an ELF64 with one `PT_LOAD` segment per kernel virtual memory region. The **module/vmalloc** segment is the one with `vaddr ≈ 0xffffffffc0000000`:

```bash
dd if=/proc/kcore bs=4096 count=1 2>/dev/null | xxd | head -40
```

Parse `e_phoff`, `e_phnum`, and each `Elf64_Phdr` (56 bytes). For each segment:
- `p_offset` = file offset
- `p_vaddr` = virtual address
- `p_filesz` = segment size

To translate a kernel VA to a kcore file offset: `f = ph.p_offset + (va - ph.p_vaddr)`.

The visible `[__builtin__ftrace] ftrace_trampoline` symbols in `/proc/kallsyms` give a hint of the module load address (the trampolines are allocated near the hooked module).

### 4. Dump the module memory range and grep for the flag

The module's `.rodata` is in the same `vaddr ≈ 0xffffffffc0000000` segment. Dump it via `perl` (always present, supports `sysseek` to 64-bit offsets):

```bash
perl -e '
open(my $f, "<", "/proc/kcore") or die;
open(my $o, ">", "/tmp/modarea") or die;
binmode $f; binmode $o;
sysseek($f, 0x7fffc0003000, 0);  # use the actual p_offset of the PT_LOAD covering 0xc0000000
my $size = 16 * 1024 * 1024;
my $total = 0;
while ($total < $size) {
  my $buf;
  my $n = sysread($f, $buf, 1024*1024);
  last if $n <= 0;
  syswrite($o, $buf, $n);
  $total += $n;
}'
strings /tmp/modarea | grep -E '<FLAG_PREFIX>\{|<modname>|<author_tag>'
```

The real flag pops out next to other module strings (the module name, module description, etc.).

### 5. Submit the flag

The `read` hook only intercepts reads from the filenames in its compare list (`kmsg`, `kallsyms`, `enabled_functions`). `/proc/kcore`, `/dev/mem`, `/proc/vmallocinfo`, plus any file you `cp`-to-tmp first remain unfiltered.

## Why the bypass works

The `hook_read` checks happen inside the hooked syscall: it calls `fget()` on the fd, walks `file->f_path.dentry->d_name.name`, and compares against a fixed list. It does **not** trace the inode, mount, or open() path. So any read where the dentry name isn't in the list passes through to the original `sys_read` unchanged — including `kcore`, which by default contains the entire kernel mapping (`CAP_SYS_RAWIO` required, satisfied as root).

## Quick sanity table

| File | Hooked? | Why |
|------|---------|-----|
| `/dev/kmsg` | yes | `kmsg` in filter list |
| `/proc/kallsyms` | yes | `kallsyms` in filter list |
| `/sys/kernel/tracing/enabled_functions` | yes | `enabled_functions` in filter list |
| `/proc/modules` | no (but `hide()` removes the module from the kernel list) | rootkit `list_del`s itself |
| `/sys/module/<modname>` | no (but `kobject_del`'d by rootkit) | rootkit `kobject_del`s the sysfs entry |
| `/proc/kcore` | **no** | dentry name `kcore` not in filter list |
| `/proc/vmallocinfo` | no | not filtered, but addresses are obfuscated as `(____ptrval____)` on modern kernels |
| `cp /proc/kallsyms /tmp/x; cat /tmp/x` | yes (cp uses read on kallsyms) | `cp` invokes hooked read on kallsyms |
| any file you write to and re-read | no | once data is in a non-filtered file, reads pass through |

## Related techniques

- Module unloading not possible (`rmmod` not present; rootkit also hooks ftrace control files to prevent unregister).
- `sys_init_module` / `delete_module` syscalls would also be useful if unhooking is the goal.
- If `/proc/kcore` is empty/restricted, fall back to `kexec_load` (needs kernel support) or read `/dev/mem` (often mmap-only and restricted to 1MB).
- If the module is signed/encrypted (CONFIG_MODULE_SIG_FORCE), inspect the kernel's `module_layout` symbols.

## Crib for the persistent serial console

Single-shot QEMU serial-over-TCP boot challenges typically work like this:
- Each new TCP connection boots a fresh VM.
- The shell is launched via `setsid cttyhack /bin/sh`; on shell exit, `init` runs `poweroff -f`.
- All exploit steps must happen in **one** socket session.
- Shell echoes input back — when capturing output, your sync marker must be constructed at runtime (e.g., `printf '%s%s' SCRIPT 'DONE'` produces `SCRIPTDONE`) so it doesn't appear in the typed command itself.
