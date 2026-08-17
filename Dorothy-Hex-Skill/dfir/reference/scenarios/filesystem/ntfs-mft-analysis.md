# NTFS $MFT Analysis

## When this applies

You have access to `$MFT` (extracted from disk image, FTK collection, or live triage) and need to enumerate every file's metadata: timestamps, sizes, parent directories, alternate data streams, deleted entries, and small-file content.

## Technique

The Master File Table records 1024-byte entries per file. Each entry stores `$STANDARD_INFORMATION` and `$FILE_NAME` timestamps, parent record number (for path reconstruction), and a `$DATA` attribute that is either resident (file content < ~700 bytes embedded in the MFT) or non-resident (data run pointers to clusters).

## Steps

1. Parse the MFT to CSV:
   ```bash
   pip install analyzeMFT
   analyzeMFT.py -f '$MFT' -o mft.csv
   # Or Eric Zimmerman:
   MFTECmd.exe -f '$MFT' --csv ./out --csvf mft.csv
   ```
2. Reconstruct full paths (parent record links):
   ```python
   import csv
   records = {}
   with open('mft.csv', errors='replace') as f:
       r = csv.reader(f); next(r)
       for row in r:
           records[row[0]] = row
   def fullpath(rn, max_depth=64):
       parts = []
       cur = rn; seen=set()
       while cur in records and cur not in seen and len(parts) < max_depth:
           seen.add(cur)
           parts.append(records[cur][7])      # filename
           cur = records[cur][5]              # parent
       return 'C:\\' + '\\'.join(reversed(parts))
   ```
3. Hunt for sensitive dumps:
   ```bash
   grep -iE 'ntds\.dit|SAM|SYSTEM|SECURITY|lsass|\.kirbi|\.ccache' mft.csv | head
   ```
4. Detect timestomping — compare $SI vs $FN timestamps (columns 9-12 vs 13-16):
   ```python
   if abs((si_created - fn_created).total_seconds()) > 60:
       print("Timestomp candidate", row)
   ```
   $FN is updated only on file create/move/rename; $SI tracks every modify and is freely settable via API.
5. Recover small (<700 B) resident files:
   ```bash
   python3 -c "print(hex(<record_num> * 1024))"
   xxd -s 0xOFFSET -l 1024 '$MFT'
   # Locate $DATA attribute (type 0x80, resident flag = 0) and extract content bytes
   ```
6. Carve deleted entries — MFT records of deleted files retain metadata until reused. `analyzeMFT` flags them in the `Active` column; recovery of unallocated content depends on cluster reuse.
7. Alternate Data Streams (ADS): MFT records show multiple `$DATA` attributes; second `$DATA` with a name (e.g. `:Zone.Identifier`, `:malware`) is suspicious for Mark-of-the-Web or hidden payload.

## Verifying success

- Path reconstruction yields valid Windows paths (root `C:\` or volume guid).
- $SI/$FN comparison surfaces the same files flagged by other artifacts (Prefetch, EVTX 4663).
- Resident content reads as a recognizable text/script/config file.

## Common pitfalls

- Records are 1024 B by default but volume metadata may set a different size. Read `$Boot` for `BytesPerFileRecordSegment`.
- Timestamps are FILETIME (100-ns since 1601-01-01) — convert to UTC explicitly.
- `analyzeMFT` reports `content_size=None` for non-resident — read the real size from the `$DATA` attribute header (offset +48 in the attribute).
- USN journal (`$Extend\$UsnJrnl:$J`) provides a *second* view of file changes with reasons (USN_REASON_FILE_CREATE etc.); pair MFT with USN for a high-fidelity write timeline.
- Deleted MFT entries can have stale parent references → path reconstruction may produce orphans (`<orphaned>`).

## Tools

- `analyzeMFT.py` — Python parser, CSV output
- `MFTECmd` — Eric Zimmerman, fast and accurate, optional JSON
- `mft2bodyfile` — Sleuthkit body file for plaso ingestion
- `usn` parser (`UsnJrnl2Csv`) — pairs with MFT
- `Velociraptor` `Windows.NTFS.MFT` artifact for live triage
