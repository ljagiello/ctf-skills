# Exploit-Relevant Static Signals

Use this reference only when the task asks for exploitability or security impact. State the primitive supported by evidence and the additional runtime condition required. Never turn absence of a static artifact into a proof of absence.

| Observed evidence | Security-relevant meaning |
| --- | --- |
| Libc version/build | Narrows offsets, gadget set, heap implementation, and known hardening behavior; confirm the mapped libc at runtime when possible. |
| Seccomp filter or policy evidence | May restrict available syscalls; derive actual allowed/blocked syscalls from the filter or observed behavior, not from presence alone. |
| `GNU_STACK RWE` | An executable stack is requested; shellcode feasibility still depends on runtime enforcement, input placement, and control-flow primitive. |
| `GNU_STACK` missing | Stack executability is unknown and depends on ABI/kernel policy. |
| NX disabled, when runtime evidence confirms it | Shellcode becomes more feasible, but still requires a way to redirect execution into attacker-controlled memory. |
| Non-PIE plus partial RELRO | Fixed ELF base and writable GOT make GOT overwrite a stronger candidate, subject to a write primitive and layout constraints. |
| PIE candidate confirmed as PIE | Exploits generally need an ELF base leak or another way to bridge to known absolute locations. |
| Full RELRO evidence | GOT is intended to be read-only after relocation; seek another target rather than assuming GOT overwrite. |
| Statically linked | Conventional external libc is not mapped separately; use the embedded libc/symbols and assess GOT/PLT differently. |
| Stripped | Named logic and boundaries are missing, requiring reconstruction from dynamic symbols, strings, code, and xrefs. |
| Canary instrumentation observed | Selected code has canary checks; coverage must be checked function by function. |
| No canary artifact observed | Canary status is not established, especially in stripped/static/inlined code; inspect the relevant write paths before claiming a stack overflow route. |
| Canary absence proven for a reachable function | Stack overflow, return-address overwrite, or stack pivot may be viable if an attacker-controlled overflow reaches that frame. |
