# Output Discipline

Single canonical OUTPUT_DIR rule + directory tree.

## Rule

Never write any file to the repo root or current working directory. Every file an agent produces — tool output, downloads, scripts, evidence — goes inside an engagement's `OUTPUT_DIR`.

Create the full tree at the start of any engagement, before any tool invocation:

```bash
mkdir -p $OUTPUT_DIR/{recon,findings,logs,artifacts,tools,reports}
```

## Tree

```
OUTPUT_DIR/
├── recon/              # Scans, fingerprinting, source dumps, share spiders
├── findings/
│   └── finding-NNN/
│       ├── description.md
│       ├── poc.py
│       ├── poc_output.txt
│       └── evidence/
│           ├── raw-source.txt
│           └── validation/   # Validator writes here
├── logs/               # NDJSON activity logs, mission reports
├── artifacts/          # Tool-generated files (.crt, .key, dumps, hashes, configs)
│   ├── validated/      # Finding validator JSONs
│   ├── false-positives/
│   ├── engagement-validation.json
│   └── engagement-validation-summary.md
├── tools/              # Per-invocation tool archive (input + output)
├── reports/            # Final PDF, completion report
├── attack-chain.md     # Coordinator's living theory
├── experiments.md      # Append-only experiment ledger
├── stats.json          # Engagement metrics (parent orchestrator finalizes)
└── flags.txt           # Submitted flags (if applicable)
```

## Naming

- `OUTPUT_DIR` is named `YYMMDD_<engagement-tag>/` or similar timestamp + tag.
- Findings monotonically increment: `finding-001`, `finding-002`, …
- Tool logs monotonically increment: `tools/001_nmap.md`, `tools/002_curl.md`, …

## Why this discipline matters

- The engagement-validator (P5) reads the directory tree to judge thoroughness. A missing `recon/` or empty `tools/` directory means the engagement skipped phases.
- The PostToolUse hook (W6) increments `stats.json` counters by detecting writes to `findings/finding-NNN/` etc. The path shape is part of the contract.
- Skill linter and CI use this tree to validate runs.

## Anti-patterns

- Writing `nmap_output.txt` in the repo root.
- Reusing one `output/` directory across engagements (clobbers prior runs).
- Putting validator artifacts in `findings/{id}/` directly instead of `findings/{id}/evidence/validation/`.
- Putting `attack-chain.md` inside a subdirectory — it lives at the OUTPUT_DIR root.
