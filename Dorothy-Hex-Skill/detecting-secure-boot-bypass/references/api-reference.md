# Command Reference

## mokutil (Linux Secure Boot state)

| Command | Description |
|---------|-------------|
| `mokutil --sb-state` | Report whether Secure Boot is enabled. |
| `mokutil --list-enrolled` | List enrolled MOK (Machine Owner Keys). |
| `mokutil --db` | Show platform db entries (via shim). |
| `mokutil --dbx` | Show dbx (revoked) entries via shim. |

## efitools

| Command | Description |
|---------|-------------|
| `efi-readvar` | Dump PK, KEK, db, dbx. |
| `efi-readvar -v dbx -o dbx.esl` | Export dbx to an EFI signature list file. |

## dbxtool

| Command | Description |
|---------|-------------|
| `dbxtool --list` | List current dbx entries and count. |
| `dbxtool --dbx DBXUpdate.bin --apply --dry-run` | Show revocations a given update would add (no write). |
| `dbxtool --dbx DBXUpdate.bin --apply` | Apply a dbx update (write — caution). |

## CHIPSEC

| Command | Description |
|---------|-------------|
| `chipsec_main -m common.secureboot.variables` | Verify SB key variables are authenticated/protected. |
| `chipsec_main -m common.secureboot.variables -a modify` | Attempt to write/corrupt SB vars (destructive test). |
| `chipsec_main -m common.uefi.s3bootscript` | Check S3 resume boot-script protections. |
| `chipsec_util spi dump rom.bin` | Dump SPI flash for offline analysis. |

## Signature verification

| Command | Description |
|---------|-------------|
| `sbverify --list <file.efi>` | List signatures on an EFI binary. |
| `sbverify --cert db.crt <file.efi>` | Verify a binary against a db cert. |
| `pesign -S -i <file.efi>` | Show signatures (RHEL family). |

## Windows PowerShell

| Cmdlet | Description |
|--------|-------------|
| `Confirm-SecureBootUEFI` | Returns `$true` if Secure Boot is enabled. |
| `Get-SecureBootUEFI dbx` | Retrieve the raw dbx variable bytes. |
| `Get-SecureBootUEFI db` | Retrieve the allowed-signatures database. |

## TPM corroboration

| Command | Description |
|---------|-------------|
| `tpm2_pcrread sha256:7` | Read PCR[7] (Secure Boot policy measurement). |

## Key references

- UEFI revocation list files: https://uefi.org/revocationlistfile
- Microsoft KB5025885 (CVE-2023-24932): https://support.microsoft.com/topic/kb5025885
