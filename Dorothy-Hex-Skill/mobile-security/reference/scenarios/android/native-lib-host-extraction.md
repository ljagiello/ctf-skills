# Android Native Lib — Host-Side Extraction via LD_PRELOAD

When an Android APK ships its logic in a stripped C/C++ `.so` (libc++ `__ndk1::basic_string`, SSE-vectorized derivations, hex-encoded literals), reproducing the math is expensive. If the lib ultimately compares your input to a constructed value via libc `strcmp` / `memcmp`, intercepting that comparison gives the expected value for free — no emulator, no Frida, no ARM cross-compilation.

## When to use

- APK has `lib/x86_64/lib<name>.so` (or any host-arch variant) — extract that copy.
- Native check funnels through `strcmp` / `memcmp` / `strncmp` (verify with `objdump -R lib<name>.so | grep -E 'strcmp|memcmp'`).
- Static-analysis port of the derivation looks costly (libc++ `std::string` + SSE intrinsics).
- Frida path is blocked (no device, anti-debug, ARM-only build).

## Recipe

1. **Extract the `.so`** from the APK and identify undefined LIBC symbols:
   ```bash
   unzip -j app.apk lib/x86_64/lib<name>.so
   objdump -T lib<name>.so | awk '/LIBC/ && /UND/ {print $NF}' | sort -u > syms.txt
   ```
2. **Generate a forwarder `libc.so`** (Bionic SONAME). Each undefined symbol becomes a thin proxy that `dlsym`s into glibc's `libc.so.6`. Publish each via `__asm__(".symver _proxy_FOO, FOO@@LIBC")`.
3. **Special-case the comparison** — give `strcmp` (or `memcmp`) a real body that prints both args to stderr before forwarding.
4. **Stub the other Bionic-only NEEDED libs** (`liblog.so`, `libm.so`, `libdl.so`) with empty shared objects bearing the right SONAME. `liblog` needs no-op `__android_log_print` / `__android_log_write`.
5. **Map Bionic→glibc symbols** that don't exist in glibc — see table below.
6. **Write a tiny `loader.c`** that `dlopen`s the lib and calls the comparison entry point with `char const*` only (avoid passing/returning libc++ `std::string` from your harness — ABI mismatch).
7. **Run inside `--platform linux/amd64` Docker.** The expected target value prints to stderr. If it looks like ASCII hex, decode with `bytes.fromhex(...)`.

## Bionic → glibc symbol remap

| Bionic | glibc replacement | Notes |
|---|---|---|
| `__errno` | `__errno_location` | `errno` macro impl |
| `__memcpy_chk` | `memcpy` | `_FORTIFY_SOURCE` checked variant |
| `__memmove_chk` | `memmove` | same |
| `__strlen_chk` | `strlen` | same |
| `__vsnprintf_chk` | `vsnprintf` | same |
| `__sprintf_chk` | `sprintf` | same |
| `__open_2` | `open` | Bionic-specific 2-arg form |
| `__read_chk` | `read` | same |
| `arc4random` / `arc4random_buf` / `arc4random_uniform` | `rand` | weakened, OK for RE |
| `gettid` | `getpid` | OK if not used for thread identity |
| `android_set_abort_message` | `abort` (or no-op) | log-only, safe to drop |
| `__sF` | `stdin` | bionic stdio array — close-enough placeholder |
| `__libc_init` | `getpid` (no-op) | only called from `_init` |
| `__system_property_get` / `__system_property_find` | no-op | return 0 |

If the loader segfaults inside the proxied call, look for missing symbols in stderr (`missing: FOO->BAR`) and add the mapping.

## Forwarder version-script

```ld
LIBC {
    global: *;
};
```

This makes every exported symbol bear the `LIBC` version, satisfying the `.so`'s `Verneed` table. Without it, the dynamic linker rejects the surrogate.

## Loader skeleton

```c
#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>

int main(int argc, char** argv) {
    void* h = dlopen("./lib<name>.so", RTLD_NOW);
    if (!h) { fprintf(stderr, "dlopen: %s\n", dlerror()); return 1; }
    typedef void (*entry_t)(const char*);
    entry_t entry = (entry_t)dlsym(h, "_Z<mangled_entry>");
    if (!entry) { fprintf(stderr, "no entry sym\n"); return 1; }
    entry(argc > 1 ? argv[1] : "probe");
    return 0;
}
```

Find the entry symbol via `nm -D lib<name>.so | grep ' T ' | c++filt` — pick the one taking `char const*` that's reachable from the JNI export.

## Caveats

- **libc++ ABI mismatch.** `__ndk1::basic_string` differs from libstdc++. Pass through `char const*` only; hook the underlying libc primitive (`strcmp` / `memcmp`) — never a function whose signature includes a C++ standard-library type.
- **Versioned symbols are mandatory.** A surrogate `libc.so` without `--version-script LIBC` fails the linker's `Verneed` check.
- **Docker on macOS breaks ptrace** under qemu emulation — gdb won't attach. The LD_PRELOAD recipe needs no debugger, so this is fine; just avoid trying to debug through it.
- **Multi-library setups.** If the comparison happens in a second `.so` that the first one `dlopen`s, hook there instead — the surrogate scope is global by default.
- **Non-libc compares.** If the lib uses an inlined / vectorized compare (no PLT entry), this technique fails — fall back to `frida-hooking.md` or in-process patching.

## Cross-references

- `scenarios/dynamic-analysis/frida-hooking.md` — alternative when device + ARM build is available.
- `scenarios/dynamic-analysis/ltrace-strace.md` — same idea via `ltrace -e strcmp`, but typically too noisy on full Android runtime; this recipe extracts to a minimal harness.
- `scenarios/static-analysis/elf-analysis.md` — for finding the entry symbol and verifying which libc primitive the `.so` actually calls.

## Anti-Patterns

- Trying to call a function returning `std::string` directly from the harness — silent corruption, segfault, or wrong output.
- Skipping the version-script — the `.so` loads partially, then the first PLT call traps.
- Using `LD_PRELOAD` of a separate hook library while also providing a forwarder `libc.so` — pick one resolution path; the surrogate `libc.so` strategy already wins because it sits in `NEEDED`.
