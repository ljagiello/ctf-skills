# ICS/SCADA & Modbus Testing Quickstart

**Attack Type**: Industrial Control System Protocol Exploitation
**MITRE**: T0801 (Monitor Process State), T0855 (Unauthorized Command Message), T0836 (Modify Parameter)

## Modbus TCP Fundamentals

- **Port 502** (default), often non-standard in CTFs
- **Unit/Slave ID**: 1 byte (0x00-0xFF) — brute-force all 256 to find connected PLCs
- **Function Codes**: FC01 (Read Coils), FC03 (Read Holding Registers), FC05 (Write Single Coil), FC06 (Write Single Register), FC15 (Write Multiple Coils), FC16 (Write Multiple Registers), FC43/0x2B (Read Device Identification)
- **No authentication** in standard Modbus — any client can read/write if network-reachable

## Enumeration Phase

### 1. Slave ID Discovery
```python
# Brute-force all 256 slave IDs with FC 0x2B (device identification)
for sid in range(256):
    resp = client.read_device_identification(slave=sid)  # or send raw FC 0x2B
    # Non-error response = active PLC. Check ProductName, VendorName fields
```

### 2. Function Code Enumeration
```python
# Try all standard FCs to discover what's supported
for fc in [1,2,3,4,5,6,15,16,0x2B]:
    # Non-error response = supported FC on this slave
```

### 3. Coil/Register Mapping
- Read coils 0-1000 in batches to find active ones
- Read holding registers 0-500 to find data (flags often in registers as ASCII)
- Read input registers and discrete inputs similarly

## Custom Function Codes

Vendors wrap proprietary session protocols inside custom FCs (e.g., FC 0x66):
- **Structure**: `[Session_ID][Sub-FC/Command][Data...]`
- **Sub-FC enumeration**: try all 256 sub-FC values to map available commands
- **Session management**: sessions are typically 1-byte tokens — brute-force 0x00-0xFF
- **Common sub-FC patterns**: reserve/release (session lifecycle), start/stop PLC logic, enable/disable write access, read status/device info

### pymodbus Custom FC Template
```python
from pymodbus.client import ModbusTcpClient
from pymodbus.pdu import ModbusRequest, ModbusResponse
from pymodbus.transaction import ModbusSocketFramer
import struct

class CustomRequest(ModbusRequest):
    function_code = 0x66  # Replace with target FC
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

## Attack Patterns

### Session Hijacking
1. Brute-force session token (0x00-0xFF) using a command that succeeds on valid sessions
2. Release/kill the existing operator session to stop their program
3. Take a new reservation under your own operator name
4. Enable write access (may require multiple enable commands)
5. Proceed with coil/register writes

### PLC Logic Override
- **Problem**: PLC ladder logic runs in cycles (~1s) and continuously resets coils/registers
- **Solution**: Kill the operator program (release its session), OR stop PLC logic execution before writing coils
- Coil writes that get immediately reverted = PLC logic is overriding them

### Sensor Spoofing
- Write to sensor coils to fake conditions (manual mode ON, force sensor states)
- Common coil roles: manual/auto mode, start/stop, high/low level sensors, valve open/close

### Flag Extraction
- Holding registers often store flags as ASCII (one char per register)
- Read 50-100 registers starting at suspected flag address
- Decode: `''.join(chr(r) for r in registers if 32 <= r < 127)`

## PCAP Analysis

When challenge includes traffic captures:
1. Filter on Modbus TCP (port 502 or custom)
2. Map the session flow: reserve → auth → commands → release
3. Extract session tokens, operator names, sub-FC sequences
4. Identify coil/register addresses from read/write operations
5. Replay or adapt the observed sequence with modifications
