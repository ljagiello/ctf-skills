# Command Reference — ESP Bootkit Hunting

## ESP discovery and mounting

| Command | Purpose |
|---------|---------|
| `lsblk -o NAME,FSTYPE,PARTTYPENAME,MOUNTPOINT` | List partitions with type names to find the ESP |
| `fdisk -l \| grep -i "EFI System"` | Identify the ESP partition device |
| `mount -o ro,umask=077 /dev/sdXN /mnt/esp` | Mount the ESP read-only (evidence-safe) |
| `umount /mnt/esp` | Unmount after analysis |

## sbverify (sbsigntool) — Secure Boot signatures

| Command | Purpose |
|---------|---------|
| `sbverify --list <binary.efi>` | List all embedded signatures on an EFI binary |
| `sbverify --cert <ca.pem> <binary.efi>` | Verify a binary against a known-good signing certificate |
| `sbverify --detached <sig> <binary.efi>` | Verify a detached signature |

## pesign — PE/COFF signature inspection

| Command | Purpose |
|---------|---------|
| `pesign -S -i <binary.efi>` | Show signatures / certificate chain on a PE binary |
| `pesign -h -i <binary.efi>` | Print the PE authenticode hash |

## efitools / efibootmgr / mokutil — Secure Boot state

| Command | Purpose |
|---------|---------|
| `efi-readvar -v db -o db.esl` | Dump the Secure Boot allow-list (db) |
| `efi-readvar -v dbx -o dbx.esl` | Dump the Secure Boot revocation list (dbx) |
| `efibootmgr -v` | List boot entries and boot order with loader paths |
| `mokutil --sb-state` | Report whether Secure Boot is enabled |
| `mokutil --list-enrolled` | List enrolled Machine Owner Keys |

## YARA — bootkit scanning

| Command | Purpose |
|---------|---------|
| `yara -r -w <rules.yar> /mnt/esp/` | Recursively scan the ESP, suppress warnings |
| `yara -r -s <rules.yar> /mnt/esp/EFI/` | Scan with matched-string output |

## tpm2-tools — measured boot

| Command | Purpose |
|---------|---------|
| `tpm2_pcrread sha256:0,2,4,7` | Read firmware/boot-loader/Secure-Boot PCRs |
| `tpm2_eventlog /sys/kernel/security/tpm0/binary_bios_measurements` | Parse the TCG measured-boot event log |

## Hashing and baseline diff

| Command | Purpose |
|---------|---------|
| `find /mnt/esp -type f \( -iname '*.efi' -o -iname '*.sys' \) -print0 \| xargs -0 sha256sum` | Inventory and hash all boot binaries |
| `comm -23 live.sha256 base.sha256` | Show hashes present live but absent from baseline |
| `dd if=/dev/sdXN of=esp.img bs=4M conv=noerror,sync` | Forensically image the ESP |

## Velociraptor artifacts (fleet hunting)

| Artifact | Purpose |
|----------|---------|
| `Windows.Forensics.UEFI` | Parse the ESP partition table and FAT to enumerate files |
| `Windows.Detection.Yara.UEFI` | YARA-scan ESP contents at scale |
| `Generic.System.EfiSignatures` | Collect EFI signature data |
| `Windows.Forensics.UEFI.BootApplication` | Parse Measured Boot TCG logs |
