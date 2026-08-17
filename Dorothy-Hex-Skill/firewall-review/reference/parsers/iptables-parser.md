---
name: iptables-parser
description: Parse Linux netfilter / iptables-save dumps into NormalizedRule objects. Use when the engagement's Pre-requisites folder contains `iptables-save` output or equivalent `-A CHAIN` rule lists.
---

# iptables / netfilter Parser

**Reference implementation:** `fwrr.parsers.iptables.IptablesParser` in [firewall-review](https://github.com/ipunithgowda/firewall-review)
**Version pin:** `iptables:0.1.0`

## When this skill fires
The `fwrr launch` orchestrator dispatches this parser when a `.cfg` / `.conf` / `.txt` file in `Pre-requisites/iptables/` contains either a table sentinel (`*filter`, `*nat`, `*mangle`, `*raw`, `*security`) or a line matching `^\s*-A\s+(INPUT|OUTPUT|FORWARD)\b`. This is the 7th shipped vendor parser (after PAN-OS, Cisco ASA, Cisco IOS, FortiGate, AWS SG, Azure NSG).

## Inputs it accepts
- `iptables-save` output (canonical — full dump with sentinels and `COMMIT` markers)
- Fragmentary `-A CHAIN ...` rule lists without sentinels (detected via regex fallback)
- Mixed-table dumps (non-filter tables are skipped — audit scope is connectivity, not NAT/mangle rewriting)

## Gotchas (v0.1 limitations)
- **`-i lo` and state-established markers** are preserved in `scope` as `in:lo` and `state:established,related` / `conntrack:established,related`. Detectors use these via the `is_infrastructure_rule` context filter to suppress false-positives on loopback and return-traffic return paths.
- **`implicit_src` / `implicit_dst` scope markers** are appended when the rule did not specify `-s` / `-d` (defaults to `any`). Detectors that care about source/destination intent can distinguish "operator wrote `any`" from "operator omitted the flag."
- `LOG`, `RETURN`, `MARK` targets do **not** emit rules — they are log/flow-control actions, not filter decisions. Count persisted as `scope_metadata["log_only_rule_count"]`.
- Custom-chain jumps (`-j MY_CHAIN`) are recorded as `action=allow` with a manual-review marker — detectors flag via object-group expansion logic in v0.2.
- Default-chain policies (`:INPUT DROP [0:0]`) are captured in `scope_metadata` as `default_policy_INPUT` etc. — v0.2 detectors read these for terminal-deny assertions.
- `--sports` / `--dports` (multiport) are split on commas; single-port `--sport` / `--dport` accepts `n` or `n:m` range syntax.
- `-m comment --comment "..."` is robust to interleaved module options (e.g. `-m comment --limit 1 --comment "X"`).

## Normalized schema it emits
See `fwrr.schema.NormalizedRule`. Rule IDs have the form `iptables-<chain>:<lineno>`. `priority = lineno` because source-order is the iptables evaluation order. `scope` format: `table:filter;chain:<CHAIN>[;in:<iface>][;out:<iface>][;state:<csv>][;implicit_src][;implicit_dst]`.

## Failure modes
- `UnsupportedFormatError` when no filter-table rules AND no default policies are found, or when `shlex.split` fails on a malformed line.
- Raw text preserved on the `raw` attribute for every rule — citation-verifier uses this for the audit-grade evidence trail.
