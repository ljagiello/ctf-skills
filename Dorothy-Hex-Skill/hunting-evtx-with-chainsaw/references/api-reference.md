# Chainsaw — Command & Flag Reference

## Subcommands

| Command | Purpose |
|---------|---------|
| `hunt` | Detect threats using Sigma and Chainsaw rules |
| `search` | Keyword/regex/Tau search across artifacts |
| `analyse` | shimcache / srum / gaps artifact analysis |
| `dump` | Dump raw artifact content |
| `lint` | Validate rule files |

## hunt Flags

| Flag | Description |
|------|-------------|
| `-s, --sigma <DIR>` | SigmaHQ rules directory |
| `-r, --rule <DIR>` | Chainsaw rules directory |
| `-m, --mapping <FILE>` | Sigma->event field mapping (e.g. `mappings/sigma-event-logs-all.yml`) |
| `--level <LEVEL>` | Filter by Sigma rule level |
| `--status <STATUS>` | Filter by rule status (e.g. `stable`) |
| `--kind <KIND>` | Filter by detection kind (e.g. `evtx`) |
| `--json` / `--csv` | Output format |
| `-o, --output <PATH>` | Output file/directory |

```bash
chainsaw hunt ./evtx -s ./sigma/rules \
  --mapping ./mappings/sigma-event-logs-all.yml --level high --json
```

## search Flags

| Flag | Description |
|------|-------------|
| `-e, --regex <RE>` | Regex pattern |
| `-i, --ignore-case` | Case-insensitive |
| `-t, --tau <EXPR>` | Tau expression query |
| `--from` / `--to` | Timestamp bounds |
| `--json` | JSON output |

```bash
chainsaw search "mimikatz" -i ./evtx
chainsaw search -e "-enc\s+[A-Za-z0-9+/=]{20,}" ./evtx --json
chainsaw search ./evtx -t 'Event.System.EventID: =4624'
```

## analyse Subcommands

```bash
# Shimcache with Amcache timestamp pairing
chainsaw analyse shimcache ./SYSTEM --regexfile ./patterns.txt \
  --amcache ./Amcache.hve --tspair --output ./out.csv

# SRUM database
chainsaw analyse srum --software ./SOFTWARE ./SRUDB.dat -o srum.json

# Event-log gaps
chainsaw analyse gaps ./Logs/ --min-time-gap-minutes 30 --json
```

## dump / lint

```bash
chainsaw dump ./SOFTWARE --json --output dump.json
chainsaw lint -r ./rules --kind sigma
```

## Install

```bash
git clone https://github.com/WithSecureLabs/chainsaw.git
cd chainsaw && cargo build --release
# or: nix profile install github:WithSecureLabs/chainsaw
```

## External References

- Chainsaw: https://github.com/WithSecureLabs/chainsaw
- Sigma: https://github.com/SigmaHQ/sigma
