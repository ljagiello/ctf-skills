# Port Scanning

## When this applies

A live host or netblock is in scope and the goal is to inventory open TCP/UDP ports and the services behind them. Run this after subdomain enumeration has narrowed down live hosts, or directly when given an IP/CIDR.

## Technique

Three scan profiles cover most situations:

1. **Focused scan** - a curated port list based on the host's archetype. Fastest; preferred opening move.
2. **Top-1000 / Top-10000 TCP** - default `nmap` profiles; reasonable coverage for unknown hosts.
3. **Full TCP (`-p-`)** and **UDP (`-sU`)** - exhaustive; only when the lighter profiles missed everything actionable.

Service version detection (`-sV`) and default scripts (`-sC`) should run after the port list is known so the heavy probes only hit confirmed-open ports.

## Steps

1. **Output structure**

   ```bash
   mkdir -p recon/{raw,inventory}
   TARGET=$1
   ```

2. **Recognise the archetype before scanning**

   - Hostnames containing `dc`, `ad`, `ldap` -> Windows DC.
   - Subdomain prefixes `www`, `app`, `api`, `cdn` -> web tier.
   - Mail-related (`mx`, `mail`, `smtp`) -> mail infrastructure.
   - When unknown, run a quick top-100 TCP scan first.

3. **Focused scan: Active Directory profile**

   ```bash
   nmap -Pn -sC -sV \
     -p 53,88,135,139,389,445,464,593,636,3268,3269,5985,5986,9389 \
     -oA recon/raw/ad-focused-${TARGET} ${TARGET}
   ```

   Port rationale: 53 DNS, 88 Kerberos, 135 RPC, 139/445 SMB, 389/636 LDAP/LDAPS, 464 kpasswd, 593 RPC-over-HTTPS, 3268/3269 GC/GC-LDAPS, 5985/5986 WinRM, 9389 AD Web Services. Probe both 5985 and 5986: when 5985 is filtered, 5986 with client-cert auth is a common foothold.

4. **Focused scan: web tier profile**

   ```bash
   nmap -Pn -sC -sV \
     -p 80,81,443,4443,8000,8008,8080,8081,8443,8888,9000,9090 \
     -oA recon/raw/web-focused-${TARGET} ${TARGET}
   ```

5. **Top-1000 TCP for unknown hosts**

   ```bash
   nmap -Pn --top-ports 1000 -sV -sC -oA recon/raw/top1k-${TARGET} ${TARGET}
   ```

6. **Full TCP fallback**

   Only run when the focused or top-1000 scan returned no exploitable surface, or when a non-standard application is suspected.

   ```bash
   # Two-stage: fast SYN sweep, then service detection on hits
   nmap -Pn -p- --min-rate 5000 -oA recon/raw/full-syn-${TARGET} ${TARGET}
   PORTS=$(grep -oP "^\d+/tcp\s+open" recon/raw/full-syn-${TARGET}.nmap \
     | awk -F/ '{print $1}' | paste -sd,)
   nmap -Pn -sC -sV -p ${PORTS} -oA recon/raw/full-svc-${TARGET} ${TARGET}
   ```

7. **UDP scan (selective)**

   UDP is slow and noisy; scan only common service ports unless there's a specific reason for full coverage.

   ```bash
   nmap -Pn -sU --top-ports 50 -sV \
     -oA recon/raw/udp-${TARGET} ${TARGET}
   ```

   Common UDP services: 53 DNS, 67/68 DHCP, 69 TFTP, 123 NTP, 137/138 NetBIOS, 161 SNMP, 500 IKE, 1900 SSDP, 5353 mDNS.

8. **masscan for large ranges**

   When the input is a CIDR, masscan finds candidates much faster, then nmap fingerprints them.

   ```bash
   masscan -p1-65535 --rate 10000 -oG recon/raw/masscan-${TARGET}.gnmap ${TARGET}
   awk '/Ports:/ {print $2}' recon/raw/masscan-${TARGET}.gnmap \
     | sort -u > recon/inventory/live-hosts.txt
   ```

9. **Build the port inventory**

   ```bash
   # Convert nmap XML to JSON for downstream tools
   for x in recon/raw/*.xml; do
     base=$(basename "$x" .xml)
     xmlstarlet sel -t -m "//port[state/@state='open']" \
       -v "../../address/@addr" -o ":" -v "@portid" -o ":" \
       -v "service/@name" -o ":" -v "service/@product" -n "$x" \
       >> recon/inventory/ports.tsv
   done
   sort -u recon/inventory/ports.tsv -o recon/inventory/ports.tsv
   ```

## Verifying success

- `recon/raw/*.nmap` and `*.xml` files exist for each profile that was run.
- `recon/inventory/ports.tsv` lists `host:port:service:product` for every open port.
- Service version is recorded for every web/AD/database port (anything that will be tested in a follow-up).
- Archetype is documented in `recon/analysis/attack-surface.md`.

## Common pitfalls

- Skipping `-Pn` against firewalled hosts that drop ICMP - nmap then skips the host as "down".
- Running `-p-` immediately on a host with an obvious archetype, burning 30+ minutes for no extra information.
- Forgetting UDP entirely - SNMP/IKE/TFTP findings are easy wins on infrastructure targets.
- Misinterpreting filtered as closed; filtered means a packet was likely dropped, not that nothing listens.
- Running `-sV` against every port found in masscan output simultaneously; rate-limit per-host to avoid skewed banners.

## Tools

- `nmap` - service detection (`-sV`), default scripts (`-sC`), output formats (`-oA`).
- `masscan` - high-rate SYN scanner for large ranges.
- `rustscan` - quick port discovery wrapper around nmap.
- `naabu` - lightweight scanner from ProjectDiscovery.
- `xmlstarlet`, `jq` - parse nmap XML/JSON for inventory builds.
