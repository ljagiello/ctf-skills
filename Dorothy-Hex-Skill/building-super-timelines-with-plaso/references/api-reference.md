# Plaso / log2timeline Command Reference

Plaso ships four CLI tools. Run them directly or via the Docker image
(`log2timeline/plaso`).

## log2timeline.py (extraction)

| Flag | Purpose |
|------|---------|
| `--storage-file <file>` | Output `.plaso` storage file |
| `<source>` | Source: `.E01`, raw image, mount point, directory, device |
| `--parsers <list>` | Restrict parsers (presets `win7`, `webhist`, etc.; `!name` excludes) |
| `--partitions <spec>` | Select partitions (e.g. `all`) |
| `--vss-stores <spec>` | Process Volume Shadow Copies |
| `--hashers <list>` | Compute file hashes (e.g. `sha256`) |
| `-z <tz>` | Source timezone |
| `--workers <n>` | Number of extraction workers |

```bash
log2timeline.py --storage-file timeline.plaso /cases/image.E01
log2timeline.py --parsers "win7,!filestat" --storage-file timeline.plaso /cases/image.E01
```

## pinfo.py (inspect)

```bash
pinfo.py timeline.plaso          # summary
pinfo.py -v timeline.plaso       # verbose
```

## psort.py (post-process / export)

| Flag | Purpose |
|------|---------|
| `-o <module>` | Output module: `l2tcsv`, `json_line`, `dynamic`, `elastic`, `timesketch` |
| `-w <file>` | Write output to file |
| `--output-time-zone <tz>` | Normalize output timezone (e.g. `UTC`) |
| `<storage>` | The `.plaso` file |
| `"<filter>"` | Event filter expression (trailing argument) |

```bash
psort.py --output-time-zone 'UTC' -o l2tcsv -w supertimeline.csv timeline.plaso \
  "date > datetime('2026-01-01T00:00:00') AND date < datetime('2026-01-27T00:00:00')"
psort.py --output-time-zone 'UTC' -o json_line -w supertimeline.jsonl timeline.plaso
```

## psteal.py (extract + export wrapper)

```bash
psteal.py --source /cases/image.E01 -o l2tcsv -w supertimeline.csv
```

## Common event filter fields

| Field | Example |
|-------|---------|
| `date` | `date > datetime('2026-01-01T00:00:00')` |
| `data_type` | `data_type == 'windows:evtx:record'` |
| `parser` | `parser contains 'winreg'` |
| `timestamp_desc` | `timestamp_desc contains 'Creation'` |

## Timesketch import

```bash
timesketch_importer \
  --host http://127.0.0.1:5000 \
  --username admin \
  --timeline_name "host01" \
  --sketch_id 1 \
  timeline.plaso
```

`timesketch_importer` accepts `.plaso`, `.csv`, and `.jsonl` inputs.
