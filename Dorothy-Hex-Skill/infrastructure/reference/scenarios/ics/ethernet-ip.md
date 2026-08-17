# EtherNet/IP — Allen-Bradley / CIP Discovery

## When this applies

- Target speaks EtherNet/IP / CIP (Common Industrial Protocol) over TCP/44818 and UDP/2222.
- Common on Rockwell Automation / Allen-Bradley ControlLogix / CompactLogix / MicroLogix PLCs.
- Goal is to enumerate connected devices, read identity/CPU info, walk the CIP object model, and (when authorized) read tags.

## Technique

EtherNet/IP encapsulates CIP messages. CIP defines a class/instance/attribute object model. Common services: `Get_Attributes_All` (1 = lists every attribute of an object), `Get_Attribute_Single`, `Read_Tag` (for ControlLogix tag-based programming), `Forward_Open` (establishes an explicit messaging connection). Identity Object (Class 0x01) reveals vendor, product code, revision, serial number, product name.

## Steps

### 1. Discover EtherNet/IP devices

```bash
# nmap NSE
nmap -p 44818 --script enip-info TARGET
nmap -sU -p 2222 --script enip-info TARGET_RANGE     # UDP discovery

# cpppo / pylogix discovery
python3 -c "
from pylogix import PLC
with PLC() as comm:
    devices = comm.Discover()
    for d in devices.Value:
        print(d.IPAddress, d.ProductName, d.Revision, d.SerialNumber)
"
```

Discovery sends a UDP `ListIdentity` request to broadcast address — every EtherNet/IP device replies with its Identity Object.

### 2. Identity Object enumeration (Class 0x01, Instance 1)

```python
from cpppo.server.enip.client import client

with client(host="TARGET") as conn:
    # Service 0x01 = Get_Attributes_All on Identity Object
    req = conn.get_attributes_all(class_id=0x01, instance=1)
    for resp in conn.harvest():
        # Parse the response — vendor, product code, rev, serial, name
        print(resp)
```

Identity Object attributes:
1. Vendor ID
2. Device Type
3. Product Code
4. Revision (major.minor)
5. Status word
6. Serial Number
7. Product Name (ASCII string)

### 3. Read tags from Logix-family PLCs (ControlLogix, CompactLogix)

```python
from pylogix import PLC

with PLC() as comm:
    comm.IPAddress = "TARGET"
    comm.ProcessorSlot = 0       # default for CompactLogix; for ControlLogix specify slot
    info = comm.GetPLCInfo()
    print(info.Value.Name, info.Value.Revision, info.Value.ProductName)

    # Read a specific tag
    tag = comm.Read("MyTagName")
    print(tag.Value)

    # Read all tags (Logix-family only — exposes the full tag database)
    tags = comm.GetTagList()
    for t in tags.Value:
        print(t.TagName, t.DataType)
```

`GetTagList()` returns the entire user-program tag database without authentication on most CompactLogix/ControlLogix unless configured otherwise.

### 4. CIP class/instance walking

For non-Logix devices (e.g., MicroLogix, drives), walk standard CIP objects:

| Class ID | Object | Notes |
|---|---|---|
| 0x01 | Identity | Always present |
| 0x02 | Message Router | Routing info |
| 0x04 | Assembly | I/O data |
| 0x06 | Connection Manager | Forward_Open / Forward_Close |
| 0xF5 | TCP/IP Interface | Network config |
| 0xF6 | Ethernet Link | Interface stats |

```python
# Walk Class 0xF5 to read TCP/IP config
req = conn.get_attributes_all(class_id=0xF5, instance=1)
```

The TCP/IP Interface object discloses IP, mask, gateway, hostname.

### 5. Forward_Open for explicit messaging

```python
# pylogix establishes Forward_Open automatically. With cpppo:
from cpppo.server.enip import client as enip_client
with enip_client.connector(host="TARGET") as conn:
    conn.forward_open(...)
    # then read/write
```

Forward_Open creates a CIP connection with a specified RPI (Requested Packet Interval). For data exfiltration, use unconnected explicit messaging (no Forward_Open).

### 6. Stop / start CPU (DESTRUCTIVE — lab only)

```python
# Service 0x06 (Start), 0x07 (Stop) on Identity Object — vendor-specific
# pylogix high-level (some Logix processors only)
# CIP RUN/PROG mode change is typically gated behind keyswitch or password
```

ControlLogix Mode change requires either physical keyswitch on RUN/REM/PROG or a privileged session — usually fails on production.

### 7. Allen-Bradley specific — RSLogix / Studio 5000 default protections

- **Trusted Slots** in chassis define which slots can program the CPU. Defaults often allow any chassis slot.
- **CPU Password** for source/program protection — read attempts return CIP error 0x10 (insufficient privilege).
- **Logix Designer download** authentication is via the password set in project properties.

### 8. Sniff EtherNet/IP traffic for tag access patterns

```bash
# Wireshark with EtherNet/IP / CIP dissector
wireshark -i eth0 -f 'tcp port 44818 or udp port 2222'
```

Implicit messaging (Class 1 connections, RPI-driven) carries cyclic I/O on UDP/2222. Explicit messaging (Class 3 connections) carries on-demand reads/writes on TCP/44818.

## Verifying success

- Discovery returns one or more devices with vendor, product, serial.
- `GetPLCInfo()` succeeds → vendor, OS revision, product name printed.
- `GetTagList()` returns a non-empty tag list (only on Logix-family PLCs).
- Specific tag reads return expected values.

## Common pitfalls

- **Wrong slot number** — ControlLogix in modular chassis: CPU is usually in slot 0, but can be elsewhere. CompactLogix / MicroLogix don't use slot.
- **`pylogix` only fully supports Logix family** — for SLC-500, MicroLogix, ControlLogix Classic, use `cpppo` with raw CIP.
- **Tag list size limits** — large programs return tag lists in pages; pylogix paginates automatically.
- **Forward_Open RPI errors** — request a slow RPI (e.g., 100 ms) for low-priority discovery; aggressive RPIs get denied.
- **Source/program protection** blocks tag reads on protected projects — only Identity remains.
- **Some firmware versions** drop unsolicited CIP (e.g., MicroLogix 1100 firmware ≥ B) requiring an established session.
- **EtherNet/IP** is distinct from "industrial Ethernet" — many vendors call their proprietary protocols "EtherNet/IP" loosely. Confirm via TCP/44818 banner.

## Tools

- pylogix (Allen-Bradley Logix family — easiest for tag access)
- cpppo (CIP/EtherNet/IP, more flexible, supports lower-level CIP)
- nmap NSE: `enip-info`, `enip-enumerate`
- Wireshark (CIP/EtherNet/IP dissector built-in)
- ENIP-DiscoverDLL.py / various Rockwell scanner scripts
- Metasploit `auxiliary/scanner/scada/multi_cip_command`
