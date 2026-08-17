# Platform VPN Pool Routing — Critical Pre-Flight Check

The platform uses **multiple isolated VPN lab pools**. They all advertise overlapping
lab subnets (typically `10.10.0.0/16` and `10.129.0.0/16`), but **traffic does not
cross between pools**. A common silent failure is having an active VPN to one pool
while the target machine lives in another — every reachability test fails with no
clear explanation.

## Pools observed in production

| Pool | `vpn_server_id` | What it serves |
|------|------------------|----------------|
| `release_arena` | 671 | Release-Arena machines (newly released, before retirement). Also Seasonal sometimes. |
| `dedivip_lab`   | 704 | **All retired machines** — Easy/Medium/Hard/Insane archives, including every Active Directory track machine. |
| `eulab` / others | varies | EU regional pools — same lab content, different geo. |

Other pool names exist for ProLabs, Endgames, Fortresses, Starting Point, etc.
The principle is the same: each pool is a separate network.

## Symptoms of pool mismatch

- Machine spawned successfully via API; the platform reports an IP under the lab subnet (e.g. `10.129.x.x`).
- `ping <TARGET_IP>` → "Destination host unreachable" from the VPN gateway.
- `nmap -Pn -sT --top-ports 100 <TARGET_IP>` → all ports `filtered` (no responses, not RST).
- VPN tunnel itself looks healthy: gateway pings work, platform API reachable.
- `GET /api/v4/connection/status` lists **two** registered connections — one of
  them shows `down=0, up=0` (the one you don't have a tunnel for).

## Pre-flight check (mandatory before spawning)

```bash
# 1. Get the lab the machine actually deploys to
HTB_TOKEN=$(python3 .claude/tools/env-reader.py HTB_TOKEN | awk -F= '/^HTB_TOKEN=eyJ/{print $2}')
curl -s -H "Authorization: Bearer $HTB_TOKEN" \
  "https://labs.hackthebox.com/api/v4/machine/profile/<NAME>" \
  | python3 -c "import sys,re;t=sys.stdin.read();print('lab_server:',re.search(r'\"lab_server\":\"([^\"]+)\"',t).group(1) if re.search(r'\"lab_server\"',t) else 'NA');print('vpn_server_id:',re.search(r'\"vpn_server_id\":(\d+)',t).group(1) if re.search(r'\"vpn_server_id\"',t) else 'NA')"

# 2. Inspect the running VPN config and confirm it matches
ps aux | grep -v grep | grep openvpn   # find --config <ovpn>
head -5 <ovpn>                          # remote line shows server hostname
```

If `lab_server` doesn't match the running tunnel, **stop and switch the VPN
before spawning**. Spawning first is wasteful — the API will hold the slot for
several minutes after you "terminate".

## Switching pools

The platform API `POST /connections/servers/switch/<server_id>` updates server-side
preference but **does not move the machine** — `vm/spawn` re-routes retired
machines to `dedivip_lab` regardless of the `lab` parameter. To actually reach
the new pool you must:

1. Download the new pool's ovpn from `/api/v4/access/ovpnfile/<server_id>/0`
   (returns the ovpn file directly; save to `<engagement>/artifacts/`).
2. Stop the existing tunnel (sudo required on macOS for utun teardown).
3. Start the new tunnel from the saved ovpn.

## Coordinator/orchestrator rule

Before any `vm/spawn`, the **orchestrator** (not the coordinator) must:

1. Resolve the target machine's `lab_server` and `vpn_server_id`.
2. Compare against the running OpenVPN config.
3. If mismatched → save the correct ovpn under
   `<engagement>/artifacts/<pool>_<server>.ovpn` and prompt the user to switch
   (workflow rule: **agents do not start/stop VPN**, the user manages it).
4. Only proceed to `vm/spawn` once the running tunnel matches.

This avoids the long blind-debug cycle of "machine spawned but unreachable" that
otherwise burns 15-30 minutes of agent time per machine.
