---
name: ctf-osint
description: Open Source Intelligence techniques for CTF challenges. Use when gathering information from public sources, social media, geolocation, DNS records, username enumeration, reverse image search, Google dorking, Wayback Machine, Tor relays, FEC filings, or identifying unknown data like hashes and coordinates.
license: MIT
allowed-tools: Bash Read Write Edit Glob Grep Task WebFetch WebSearch
metadata:
  user-invocable: "false"
---

# CTF OSINT

Quick reference for OSINT CTF challenges. Each technique has a one-liner here; see supporting files for full details.

## Additional Resources

- [social-media.md](social-media.md) - Twitter/X (user IDs, Snowflake timestamps, Nitter, memory.lol, Wayback CDX), Tumblr (blog checks, post JSON, avatars), BlueSky search, Discord API, username OSINT (namechk, whatsmyname), platform false positives, multi-platform chains
- [geolocation-and-media.md](geolocation-and-media.md) - Image analysis, reverse image search, geolocation techniques (railroad signs, infrastructure maps, MGRS), EXIF/metadata, hardware identification, newspaper archives, IP geolocation
- [web-and-dns.md](web-and-dns.md) - Google dorking, Google Docs/Sheets enumeration, DNS recon (TXT, zone transfers), Wayback Machine, FEC research, Tor relay lookups, GitHub repository analysis, Telegram bot investigation

---

## String Identification

- 40 hex chars -> SHA-1 (Tor fingerprint)
- 64 hex chars -> SHA-256
- 32 hex chars -> MD5

## Twitter/X Account Tracking

- Persistent numeric User ID: `https://x.com/i/user/<id>` works even after renames.
- Snowflake timestamps: `(id >> 22) + 1288834974657` = Unix ms.
- Wayback CDX, Nitter, memory.lol for historical data. See [social-media.md](social-media.md).

## Tumblr Investigation

- Blog check: `curl -sI` for `x-tumblr-user` header. Avatar at `/avatar/512`. See [social-media.md](social-media.md).

## Username OSINT

- [whatsmyname.app](https://whatsmyname.app) (741+ sites), [namechk.com](https://namechk.com). Watch for platform false positives. See [social-media.md](social-media.md).

## Image Analysis & Reverse Image Search

- Google Images, TinEye, Yandex (faces). Check corners for visual stego. Twitter strips EXIF. See [geolocation-and-media.md](geolocation-and-media.md).

## Geolocation

- Railroad signs, infrastructure maps (OpenRailwayMap, OpenInfraMap), process of elimination. See [geolocation-and-media.md](geolocation-and-media.md).

## MGRS Coordinates

- Grid format "4V FH 246 677" -> online converter -> lat/long -> Google Maps. See [geolocation-and-media.md](geolocation-and-media.md).

## Metadata Extraction

```bash
exiftool image.jpg           # EXIF data
pdfinfo document.pdf         # PDF metadata
mediainfo video.mp4          # Video metadata
```

## Google Dorking

```
site:example.com filetype:pdf
intitle:"index of" password
```

See [web-and-dns.md](web-and-dns.md).

## Google Docs/Sheets

- Try `/export?format=csv`, `/pub`, `/gviz/tq?tqx=out:csv`, `/htmlview`. See [web-and-dns.md](web-and-dns.md).

## DNS Reconnaissance

```bash
dig -t txt subdomain.ctf.domain.com
dig axfr @ns.domain.com domain.com  # Zone transfer
```

Always check TXT, CNAME, MX for CTF domains. See [web-and-dns.md](web-and-dns.md).

## Tor Relay Lookups

- `https://metrics.torproject.org/rs.html#simple/<FINGERPRINT>` -- check family, sort by "first seen". See [web-and-dns.md](web-and-dns.md).

## GitHub Repository Analysis

- Check issue comments, PR reviews, commit messages, wiki edits via `gh api`. See [web-and-dns.md](web-and-dns.md).

## Telegram Bot Investigation

- Find bot references in browser history, interact via `/start`, answer verification questions. See [web-and-dns.md](web-and-dns.md).

## FEC Political Donation Research

- FEC.gov for committee receipts; 501(c)(4) orgs obscure original funders. See [web-and-dns.md](web-and-dns.md).

## IP Geolocation

```bash
curl "http://ip-api.com/json/103.150.68.150"
```

See [geolocation-and-media.md](geolocation-and-media.md).

## Resources

- **Shodan** - Internet-connected devices
- **Censys** - Certificate and host search
- **VirusTotal** - File/URL reputation
- **WHOIS** - Domain registration
- **Wayback Machine** - Historical snapshots
