# Hayabusa — Command & Flag Reference

## Subcommands

| Command | Purpose |
|---------|---------|
| `csv-timeline` | Build a CSV forensic timeline |
| `json-timeline` | Build a JSON/JSONL timeline |
| `update-rules` | Sync the latest Sigma/Hayabusa rules |
| `search` | Keyword/regex search across event logs |
| `level-tuning` | Customize alert severity per rule |
| `computer-metrics` | Event counts per computer |
| `eid-metrics` | Event counts/percentages per Event ID |
| `log-metrics` | File metadata (timestamps, channels, providers) |
| `pivot-keywords-list` | Extract suspicious keywords for correlation |

## Common Timeline Flags

| Flag | Description |
|------|-------------|
| `-d, --directory <DIR>` | Directory of `.evtx` files |
| `-f, --file <FILE>` | Single `.evtx` file |
| `-l, --live-analysis` | Analyze local Windows event logs (admin) |
| `-o, --output <FILE>` | Output path |
| `-p, --profile <PROFILE>` | Output profile (see below) |
| `-m, --min-level <LEVEL>` | Minimum alert level |
| `-w, --no-wizard` | Skip interactive wizard (scripting) |
| `-U, --UTC` | Output timestamps in UTC |
| `-L` (json-timeline) | JSONL (one object per line) |

## Output Profiles

`minimal`, `standard` (default), `verbose`, `all-field-info`,
`all-field-info-verbose`, `super-verbose`, `timesketch-minimal`, `timesketch-verbose`

## Alert Levels

`informational`, `low`, `medium`, `high`, `critical`

## search Flags

| Flag | Description |
|------|-------------|
| `-k, --keyword <KW>` | Keyword to match |
| `-r, --regex <RE>` | Regex to match |
| `-i, --ignore-case` | Case-insensitive |
| `-d, --directory <DIR>` | Logs directory |

## Examples

```bash
hayabusa update-rules
hayabusa csv-timeline -d ./evtx -o tl.csv -p verbose -m high -U -w
hayabusa json-timeline -d ./evtx -L -o tl.jsonl -w
hayabusa search -d ./evtx -k "mimikatz" -i
hayabusa eid-metrics -d ./evtx -o eid.csv
hayabusa pivot-keywords-list -d ./evtx -m medium -o pivots
```

## External References

- Hayabusa Wiki: https://github.com/Yamato-Security/hayabusa/wiki
- Releases: https://github.com/Yamato-Security/hayabusa/releases
