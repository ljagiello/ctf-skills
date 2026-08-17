# API Reference: UEFI Bootkit Analysis Tools

## chipsec - Platform Security Assessment Framework

### SPI Flash Operations
```bash
python chipsec_util.py spi info                          # SPI flash info
python chipsec_util.py spi dump firmware.rom             # Dump entire SPI flash
python chipsec_util.py spi read 0x700000 0x100000 bios.bin  # Read specific region
python chipsec_util.py spi write 0x0 0x1000 data.bin     # Write to SPI flash
```

### UEFI Variable Operations
```bash
python chipsec_util.py uefi var-list                     # List all UEFI variables
python chipsec_util.py uefi var-list-spi firmware.rom    # List vars from dump
python chipsec_util.py uefi var-read <name> <GUID>       # Read specific variable
python chipsec_util.py uefi var-find <name>              # Find variable by name
python chipsec_util.py uefi keys                         # Dump Secure Boot keys
python chipsec_util.py uefi tables                       # List UEFI tables
python chipsec_util.py uefi decode firmware.rom          # Decode firmware image
```

### Security Assessment Modules
```bash
python chipsec_main.py -m <module>                       # Run security module
python chipsec_main.py -m common.secureboot.variables    # Secure Boot check
python chipsec_main.py -m common.bios_wp                 # BIOS write protection
python chipsec_main.py -m common.spi_lock                # SPI flash lock bits
python chipsec_main.py -m common.spi_access              # SPI region permissions
python chipsec_main.py -m common.spi_desc                # SPI descriptor check
python chipsec_main.py -m common.smm                     # SMM protection
python chipsec_main.py -m common.bios_smi                # SMI suppression
```

### Firmware Whitelist Module
```bash
# Generate whitelist from known-good firmware
python chipsec_main.py -m tools.uefi.whitelist -a generate,baseline.json,vendor.rom

# Check firmware against whitelist
python chipsec_main.py -m tools.uefi.whitelist -a check,baseline.json,suspect.rom
```

### Key Modules Reference
| Module | Purpose |
|--------|---------|
| `common.secureboot.variables` | Verify Secure Boot PK, KEK, db, dbx variables |
| `common.bios_wp` | Check BIOS region write protection (BIOSWE, BLE, SMM_BWP) |
| `common.spi_lock` | Verify SPI flash controller lock (FLOCKDN) |
| `common.spi_access` | Check SPI flash region read/write permissions |
| `common.spi_desc` | Verify SPI flash descriptor is write-protected |
| `common.smm` | Verify SMRAM range register protection (SMRR) |
| `common.bios_smi` | Check SMI event configuration and suppression |
| `tools.uefi.whitelist` | Generate and verify firmware module whitelists |
| `tools.uefi.scan_image` | Scan firmware image for known vulnerabilities |
| `tools.uefi.uefivar_fuzz` | Fuzz UEFI variable interface for vulnerabilities |

## UEFITool / UEFIExtract

### UEFIExtract CLI
```bash
UEFIExtract firmware.rom all                             # Extract all modules
UEFIExtract firmware.rom <GUID> body                     # Extract specific module
UEFIExtract firmware.rom report                          # Generate report
```

### Output Structure
Extracted firmware is organized by GUID into a directory tree containing:
- PEI modules (Pre-EFI Initialization)
- DXE drivers (Driver Execution Environment)
- SMM drivers (System Management Mode)
- Option ROMs
- NVRAM variables

## Secure Boot Variable GUIDs

| Variable | GUID | Description |
|----------|------|-------------|
| `SecureBoot` | `8BE4DF61-93CA-11D2-AA0D-00E098032B8C` | Secure Boot enable status |
| `SetupMode` | `8BE4DF61-93CA-11D2-AA0D-00E098032B8C` | Setup mode (keys not enrolled) |
| `PK` | `8BE4DF61-93CA-11D2-AA0D-00E098032B8C` | Platform Key (root of trust) |
| `KEK` | `8BE4DF61-93CA-11D2-AA0D-00E098032B8C` | Key Exchange Key |
| `db` | `D719B2CB-3D3A-4596-A3BC-DAD00E67656F` | Signature database (allowed) |
| `dbx` | `D719B2CB-3D3A-4596-A3BC-DAD00E67656F` | Forbidden signature database |
| `MokList` | `605DAB50-E046-4300-ABB6-3DD810DD8B23` | Machine Owner Key list |

## flashrom - SPI Flash Programmer

### Syntax
```bash
flashrom -p internal -r firmware.rom                     # Read/dump flash
flashrom -p internal -w clean.rom                        # Write/reflash
flashrom -p internal --verify clean.rom                  # Verify contents
flashrom -p internal --flash-size                        # Show flash size
flashrom -L                                              # List supported chips
```

## sigcheck - Signature Verification (Windows)

### Syntax
```bash
sigcheck -a file.efi                                     # Full signature info
sigcheck -u -e C:\Windows\System32\drivers\              # Find unsigned drivers
sigcheck -c -h file.efi                                  # CSV output with hashes
```

## bcdedit - Boot Configuration (Windows)

### Syntax
```bash
bcdedit /enum firmware                                   # List firmware entries
bcdedit /v                                               # Verbose boot config
bcdedit | findstr /i "testsigning nointegritychecks"      # Check bypass flags
```

## YARA - Firmware Pattern Scanning

### UEFI Bootkit Rules
```bash
yara -r uefi_bootkits.yar firmware.rom                   # Scan firmware dump
yara -s -r rules.yar firmware.rom                        # Show matching strings
```

### Example UEFI Detection Rule
```yara
rule BlackLotus_ESP_Indicator {
    meta:
        description = "Detects BlackLotus ESP-based bootkit artifacts"
        reference = "ESET Research 2023"
    strings:
        $mok_enroll = { 4D 00 6F 00 6B 00 4C 00 69 00 73 00 74 }
        $esp_path = "\\EFI\\Microsoft\\Boot\\grubx64.efi"
        $hvci_disable = "HypervisorEnforcedCodeIntegrity"
    condition:
        any of them
}
```
