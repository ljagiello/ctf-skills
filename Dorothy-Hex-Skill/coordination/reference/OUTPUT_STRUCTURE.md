# Output Structure

`OUTPUT_DIR` = `YYMMDD_hhmmss_<target>/`. Created at engagement start.

```
OUTPUT_DIR/
├── recon/              # Scans, fingerprints
├── findings/finding-NNN/  # description.md, poc.py, poc_output.txt, evidence/, evidence/validation/
├── logs/               # NDJSON activity logs
├── artifacts/          # Tool output, certs, dumps, configs
│   ├── validated/      # Approved findings
│   └── false-positives/# Rejected findings
├── tools/              # Tool invocation archive (input + output per run)
├── attack-chain.md     # Living theory doc (max 50 lines)
├── experiments.md      # Experiment registry (append-only)
└── reports/            # Final PDF, completion reports
```

## Format Mapping

| Dir | Spec |
|-----|------|
| recon/ | formats/reconnaissance.md |
| findings/ | formats/data.md |
| logs/ | formats/logs.md |
| tools/ | formats/logs.md |
| reports/ | formats/transilience-report-style/pentest-report.md |
