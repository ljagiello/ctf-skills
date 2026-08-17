# Logging

## Dirs

```
{OUTPUT_DIR}/
├── challenge-log.ndjson    # Master timeline
├── challenge-meta.json     # Challenge metadata
├── recon/                  # Scans, tech-stack
├── exploits/               # Scripts, payloads
├── evidence/               # Screenshots, HTTP captures
├── findings/               # Vuln write-ups, attack-chain.md
└── flag.txt                # Captured flags
```

## NDJSON Format

One JSON per line in challenge-log.ndjson. Keep entries minimal:

```json
{"ts":"2025-01-15T10:30:00Z","phase":"recon","act":"nmap","target":"<TARGET_IP>:80","result":"open","file":"recon/nmap.txt"}
```

Fields: `ts` (ISO8601), `phase` (recon|exploit|post-exploit|flag), `act`, `target`, `result` (success|failure|partial), `file` (optional output ref).

## challenge-meta.json

```json
{"name":"...","type":"machine","target":"<TARGET_IP>","started":"...","completed":null,"flag":null,"techniques":[]}
```

## Rules

1. Log before + after executing
2. Log failures — they inform next steps
3. No secrets in logs
4. Reference files, don't inline large output
5. Be terse. One line per action.
