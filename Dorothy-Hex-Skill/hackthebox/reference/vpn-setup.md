# VPN Setup — Split-Tunnel OpenVPN

## Download Config

1. Via Playwright: navigate to the platform → Access → Connection Pack
2. Download `.ovpn` file to `{OUTPUT_DIR}/artifacts/vpn/`

## Split-Tunnel Connection

```bash
# Start OpenVPN with split-tunnel (no default route hijack)
sudo openvpn --config {OUTPUT_DIR}/artifacts/vpn/lab.ovpn \
  --route-nopull \
  --route 10.10.0.0 255.255.0.0 \
  --route 10.129.0.0 255.255.0.0 \
  --daemon --log {OUTPUT_DIR}/artifacts/vpn/openvpn.log

# Verify tunnel is up
ip addr show tun0 2>/dev/null || ifconfig tun0

# Verify split-tunnel: lab traffic goes through VPN
ping -c 1 10.10.10.1   # any known lab gateway in the routed range

# Verify internet unaffected
curl -s --max-time 5 ifconfig.me
```

## Network Ranges

| Range | Purpose |
|-------|---------|
| 10.10.10.0/24 | Retired-machine lab pool |
| 10.10.11.0/24 | Active-machine lab pool |
| 10.129.0.0/16 | Starting-point / seasonal lab pool |

## Troubleshooting

| Issue | Fix |
|-------|-----|
| `tun0` not created | Check `sudo` permissions, kill stale openvpn processes |
| Can't reach target | Verify route: `ip route get <target-ip>` should show tun0 |
| Internet broken | Kill openvpn, restart with `--route-nopull` |
| DNS resolution fails | Add `--dhcp-option DNS 1.1.1.1` to preserve system DNS |
| Auth failure | Re-download .ovpn from the platform (tokens expire) |

## Disconnect

```bash
sudo killall openvpn
# Verify tun0 is gone
ip addr show tun0 2>/dev/null && echo "STILL UP" || echo "Disconnected"
```

## macOS Specifics

```bash
# Install
brew install openvpn

# macOS may need full path
sudo /opt/homebrew/sbin/openvpn --config {OUTPUT_DIR}/artifacts/vpn/lab.ovpn \
  --route-nopull \
  --route 10.10.0.0 255.255.0.0 \
  --route 10.129.0.0 255.255.0.0
```

Note: macOS uses `utun*` interfaces instead of `tun0`. Check with `ifconfig | grep utun`.
