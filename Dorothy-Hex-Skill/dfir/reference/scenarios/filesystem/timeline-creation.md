# Filesystem Timeline Creation

## When this applies

Multi-source incident reconstruction: you have disk images, EVTX, registry hives, browser history, antivirus logs, and need a single chronological view to align attacker actions across artifacts.

## Technique

Plaso (`log2timeline`) parses 100+ artifact types into the L2T body format. `psort` (or `psteal`) filters, sorts by timestamp, and renders human-readable output (CSV, ELK, dynamic JSON). Build a "super timeline": MFT + USN journal + Prefetch + EVTX + registry + browser + AV gives second-level fidelity over multi-day incidents.

## Steps

1. Process the entire image (or mounted directory):
   ```bash
   log2timeline.py --storage-file case.plaso evidence/   # or path to .E01/.dd
   # Multi-disk: pass --partitions all and --vss-stores all to include shadow copies
   ```
2. Inspect parser coverage:
   ```bash
   pinfo.py case.plaso | head -50
   ```
3. Render full CSV:
   ```bash
   psort.py -o l2tcsv -w timeline.csv case.plaso
   ```
   Columns: date, time, timezone, MACB, source, sourcetype, type, user, host, short, desc, version, filename, inode, notes, format, extra.
4. Filter to the incident window:
   ```bash
   psort.py -o l2tcsv -w incident.csv case.plaso \
     "date > '2024-09-01 12:00:00' AND date < '2024-09-02 18:00:00'"
   ```
5. Pivot on a specific user / process / IP:
   ```bash
   awk -F, 'tolower($0) ~ /malicious\.exe|attacker_user/' timeline.csv | head -200
   ```
6. Visual analysis — load into Timesketch:
   ```bash
   psteal.py --source evidence/ --output_format timesketch -w sketch.json
   timesketch_importer -t mycase sketch.json
   ```
7. Targeted lighter-weight option (no plaso) — `MFTECmd` + `RegRipper` + `EvtxECmd`:
   ```bash
   MFTECmd.exe -f $MFT --csv ./out --csvf mft.csv
   EvtxECmd.exe -d C:\Windows\System32\winevt\Logs --csv ./out
   # Combine via Timeline Explorer or python
   ```

## Verifying success

- Timeline rows count matches `pinfo` event count.
- Known events (EVTX 4624 logon, file create) appear at the expected UTC time.
- Filtered window contains both attacker-side and defender-side artifacts (e.g., `psexesvc.exe` install in MFT + 7045 in EVTX).

## Common pitfalls

- Timezone mismatches dominate. Use `--timezone UTC` consistently and convert host-local times before correlation.
- Plaso multi-process workers can OOM on large E01 images; lower `--workers`.
- VSS contents duplicate timestamps — useful for reconstruction but inflates row counts. Deduplicate by `(filename, MACB, inode)`.
- $STANDARD_INFORMATION timestamps can be stomped. Always pull $FILE_NAME timestamps from MFT for high-confidence ordering.
- Browser history TZ is sometimes user-local, sometimes UTC — verify per browser version.

## Tools

- `plaso` (log2timeline / psort / psteal / pinfo)
- `Timesketch` — collaborative timeline UI with search and tagging
- `MFTECmd`, `EvtxECmd`, `RECmd`, `Timeline Explorer` (Eric Zimmerman tools)
- `analyzeMFT`, `usn` (USN journal parser), `mactime` (Sleuthkit)
- `dfir-orc` — large-scale collection that feeds into plaso
