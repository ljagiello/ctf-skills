# VLAN Hopping — Double Tagging (802.1Q QinQ)

## When this applies

- Target switch has a trunk port with the native VLAN equal to the access VLAN (a misconfiguration).
- Attacker is on an access port whose native VLAN matches the trunk's native.
- Goal is to inject frames that traverse the trunk into a different VLAN, bypassing L2 segmentation.

## Technique

Native VLAN frames are untagged on a trunk. A double-tagged frame `[Outer=native_vlan][Inner=victim_vlan]` is processed as follows: the first switch strips the outer tag (matches the trunk's native VLAN) and forwards the frame with the inner tag still attached. The second switch sees a normally-tagged frame with `victim_vlan` and delivers it to the victim's port.

Limitation: only works one-way (attacker → victim). The victim's reply has no VLAN tag knowledge of the original sender's VLAN, so this is useful for blind injection — packet floods, DoS, certain ARP/spoof attacks — not for full TCP sessions.

## Steps

### 1. Discover the native VLAN

```bash
# Listen for CDP/DTP/LLDP to learn switch config
sudo tcpdump -i eth0 -nn -e 'ether host 01:00:0c:cc:cc:cc'   # CDP
sudo tcpdump -i eth0 -nn -e 'ether host 01:80:c2:00:00:0e'   # LLDP

# yersinia GUI mode listens to all L2 protocols
sudo yersinia -G
```

CDP packets disclose: native VLAN ID, allowed VLANs, switch model, IOS version, port name.

If CDP/LLDP is disabled, sniff for tagged frames bleeding across the trunk to infer VLAN IDs.

### 2. Identify the target VLAN

Map the network — common conventions:
- VLAN 1 = default (often native)
- VLAN 10 = users
- VLAN 20 = servers
- VLAN 30 = management
- VLAN 99 = guest

Sniffing or `show vlan` output (if you have any switch read access) reveals the topology.

### 3. Craft the double-tagged frame

```python
# scapy double-tag injection
from scapy.all import *

native_vlan = 1
target_vlan = 100
victim_ip = "10.0.100.5"

pkt = (
    Ether(dst="ff:ff:ff:ff:ff:ff")
    / Dot1Q(vlan=native_vlan)
    / Dot1Q(vlan=target_vlan)
    / IP(dst=victim_ip)
    / ICMP()
    / b"VLAN-HOP-TEST"
)
sendp(pkt, iface="eth0", count=10)
```

### 4. Yersinia / dot1q-vlan injection

```bash
# Yersinia interactive mode
sudo yersinia -G
# Select 802.1Q → "sending double 802.1Q packet" attack
```

Yersinia handles the same crafting visually and supports continuous floods.

### 5. Verify with a victim listener

If you control or can monitor a host on the target VLAN:

```bash
# Victim side
sudo tcpdump -i eth0 -nn icmp and host VICTIM
```

The injected ICMP echo arrives even though the attacker's port is on a different VLAN.

### 6. Useful payloads (one-way blind injection only)

- **Crafted ARP** to poison the victim VLAN's gateway entry
- **DHCP DISCOVER** to enumerate DHCP servers in the victim VLAN
- **Custom multicast/broadcast** floods for DoS
- **Wake-on-LAN** magic packets

Two-way exploitation is impossible because the victim's reply travels only inside its VLAN. If you need bidirectional traffic, escalate to switch spoofing (DTP) instead — see `scenarios/vlan-hopping/dtp-spoofing.md`.

## Verifying success

- Victim host's interface receives the injected frame (capture confirms it).
- Switch logs (if available) show a frame forwarded across the trunk into the target VLAN.
- ARP cache or DHCP server log on the victim VLAN shows entries originating from the attacker's MAC.

## Common pitfalls

- **Native VLAN must match attacker's access VLAN** — if the trunk's native is something else, the outer tag isn't stripped.
- **Native VLAN tagging** (Cisco `vlan dot1q tag native` global config) defeats the attack — every native frame is explicitly tagged, so the outer tag isn't dropped.
- **No reply path** — single-direction only. Don't try to TCP-handshake; the victim's RST reply never reaches you.
- **Switches with strict 802.1Q ingress checking** drop double-tagged frames on access ports. Test with single-tag injection first to baseline behavior.
- **Hypervisor virtual switches** (vSwitch, OVS) often don't honor double tagging by default — only physical switches with traditional trunk config are typically vulnerable.
- **PVST+/PVST or Q-in-Q tunneling** changes the meaning of double tags — testing on a service-provider QinQ link will produce different behavior.

## Tools

- scapy (manual frame crafting)
- yersinia (interactive L2 protocol attack tool)
- tcpdump / Wireshark (sniffing CDP/LLDP/DTP)
- VoIPHopper (specifically for VLAN hopping into voice VLANs via CDP spoofing)
- frogger / frogger.py (older VLAN-hopping helper)
