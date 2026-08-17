# API Reference: Binwalk Firmware Extraction Tools

## binwalk - Firmware Analysis Tool

### Signature Scan
```bash
binwalk firmware.bin                      # Basic signature scan
binwalk -v firmware.bin                   # Verbose output
binwalk -B firmware.bin                   # Explicit signature scan flag
binwalk -A firmware.bin                   # Opcode/architecture scan
binwalk -R "string" firmware.bin          # Raw string search
```

### Extraction
```bash
binwalk -e firmware.bin                   # Extract known file types
binwalk -Me firmware.bin                  # Recursive (matryoshka) extraction
binwalk -Me -d 5 firmware.bin             # Recursive with depth limit
binwalk -C /output/dir -e firmware.bin    # Custom output directory
binwalk -D "type:ext:cmd" firmware.bin    # Custom extraction rule
```

### Entropy Analysis
```bash
binwalk -E firmware.bin                   # Entropy analysis with plot
binwalk -E -K 256 firmware.bin            # Custom block size
binwalk -BE firmware.bin                  # Combined signature + entropy
```

### Key Flags
| Flag | Description |
|------|-------------|
| `-B, --signature` | Scan for file signatures |
| `-e, --extract` | Extract identified file types |
| `-M, --matryoshka` | Recursive extraction |
| `-d, --depth=N` | Matryoshka recursion depth (default: 8) |
| `-E, --entropy` | Entropy analysis |
| `-K, --block=N` | Entropy block size in bytes |
| `-A, --opcodes` | Scan for CPU opcode signatures |
| `-R, --raw=STR` | Search for raw byte string |
| `-y, --include=STR` | Include only matching results |
| `-x, --exclude=STR` | Exclude matching results |
| `-m, --magic=FILE` | Use custom magic signature file |
| `-C, --directory=DIR` | Output directory for extraction |
| `-v, --verbose` | Verbose output |
| `--threads=N` | Number of worker threads |

## unsquashfs - SquashFS Extraction

### Syntax
```bash
unsquashfs -d /output/dir image.squashfs          # Extract to directory
unsquashfs -l image.squashfs                       # List contents
unsquashfs -ll image.squashfs                      # Long listing
unsquashfs -s image.squashfs                       # Show superblock info
unsquashfs -f -d /output image.squashfs            # Force overwrite
```

### Key Flags
| Flag | Description |
|------|-------------|
| `-d DIR` | Extract to specified directory |
| `-l` | List filesystem contents |
| `-ll` | Detailed listing with permissions |
| `-s` | Display superblock information |
| `-f` | Overwrite existing files |
| `-n` | No progress bar |
| `-e FILE` | Extract only specified files |

## jefferson - JFFS2 Extraction

### Syntax
```bash
jefferson image.jffs2 -d /output/dir              # Extract JFFS2
jefferson -v image.jffs2 -d /output/dir            # Verbose extraction
```

## sasquatch - Vendor SquashFS

### Syntax
```bash
sasquatch -d /output/dir image.squashfs            # Extract non-standard SquashFS
sasquatch -p 1 -d /output image.squashfs           # Single-threaded extraction
```

Handles vendor-modified SquashFS variants from TP-Link, D-Link, Netgear, and others that use non-standard compression or block sizes.

## strings - String Extraction

### Syntax
```bash
strings firmware.bin                               # Default (4+ chars)
strings -n 12 firmware.bin                         # Minimum 12 chars
strings -a firmware.bin                            # Scan entire file
strings -t x firmware.bin                          # Show hex offsets
strings -e l firmware.bin                          # Little-endian 16-bit
```

### Key Flags
| Flag | Description |
|------|-------------|
| `-n N` | Minimum string length |
| `-a` | Scan entire file (not just data sections) |
| `-t x` | Print offset in hexadecimal |
| `-t d` | Print offset in decimal |
| `-e l` | 16-bit little-endian encoding |
| `-e b` | 16-bit big-endian encoding |

## dd - Manual Extraction

### Syntax
```bash
dd if=firmware.bin of=output.bin bs=1 skip=OFFSET count=SIZE
dd if=firmware.bin of=output.bin bs=1 skip=$((0x120000)) count=$((0x2A0000))
```

### Key Parameters
| Parameter | Description |
|-----------|-------------|
| `if=FILE` | Input file |
| `of=FILE` | Output file |
| `bs=N` | Block size (use 1 for byte-precise extraction) |
| `skip=N` | Skip N blocks from input start |
| `count=N` | Copy only N blocks |

## Python binwalk Module (v2 API)

### Programmatic Usage
```python
import binwalk

# Signature scan
for module in binwalk.scan(firmware_path, signature=True, quiet=True):
    for result in module.results:
        print(f"0x{result.offset:08X}  {result.description}")

# Extract files
binwalk.scan(firmware_path, signature=True, extract=True, quiet=True)

# Entropy analysis
for module in binwalk.scan(firmware_path, entropy=True, quiet=True):
    for result in module.results:
        print(f"0x{result.offset:08X}  entropy={result.entropy}")

# Recursive extraction
binwalk.scan(firmware_path, signature=True, extract=True,
             matryoshka=True, depth=5, quiet=True)
```
