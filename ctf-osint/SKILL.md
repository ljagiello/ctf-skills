---
name: ctf-osint
description: Open Source Intelligence techniques for CTF challenges. Use when gathering information from public sources, social media, geolocation, or identifying unknown data.
user-invocable: false
allowed-tools: ["Bash", "Read", "Write", "Edit", "Glob", "Grep", "Task", "WebFetch", "WebSearch"]
---

# CTF OSINT

## String Identification

- 40 hex chars → SHA-1 (Tor fingerprint)
- 64 hex chars → SHA-256
- 32 hex chars → MD5

## Tor Relay Lookups

```
https://metrics.torproject.org/rs.html#simple/<FINGERPRINT>
```
Check family members and sort by "first seen" date for ordered flags.

## Image Analysis

- Discord avatars: Screenshot and reverse image search
- Identify objects in images (weapons, equipment) → find character/faction
- No EXIF? Use visual features (buildings, signs, landmarks)
- **Visual steganography**: Flags hidden as tiny/low-contrast text in images (not binary stego)
  - Always view images at full resolution and check ALL corners/edges
  - Black-on-dark or white-on-light text, progressively smaller fonts
  - Profile pictures/avatars are common hiding spots
- **Twitter strips EXIF** on upload - don't waste time on stego for Twitter-served images
- **Tumblr preserves more metadata** in avatars than in post images

## Geolocation Techniques

- Railroad crossing signs: white X with red border = Canada
- Use infrastructure maps:
  - [Open Infrastructure Map](https://openinframap.org) - power lines
  - [OpenRailwayMap](https://www.openrailwaymap.org/) - rail tracks
  - High-voltage transmission line maps
- Process of elimination: narrow by country first, then region
- Cross-reference multiple features (rail + power lines + mountains)
- MGRS coordinates: grid-based military system (e.g., "4V FH 246 677") → convert online

## Social Media OSINT

- Check Wayback Machine for deleted posts on Bluesky, Twitter, etc.
- Unlisted YouTube videos may be linked in deleted posts
- Bio links lead to itch.io, personal sites with more info
- Search `"username"` with quotes on platform-specific searches
- Challenge titles are often hints (e.g., "Linked Traces" → LinkedIn / linked accounts)

## Twitter/X Account Tracking

**Persistent numeric User ID (key technique):**
- Every Twitter/X account has a permanent numeric ID that never changes
- Access any account by ID: `https://x.com/i/user/<numeric_id>` — works even after username changes
- Find user ID from archived pages (JSON-LD `"author":{"identifier":"..."}`)
- Useful when username is deleted/changed but you have the ID from forensic artifacts

**Username rename detection:**
- Twitter User IDs persist across username changes; t.co shortlinks point to OLD usernames
- Wayback CDX API to find archived profiles: `http://web.archive.org/cdx/search/cdx?url=twitter.com/USERNAME*&output=json`
- Archived pages contain JSON-LD with user ID, creation date, follower/following counts
- t.co links in archived tweets reveal previous usernames (the redirect URL contains the username at time of posting)
- Same tweet ID accessible under different usernames = confirmed rename

**Alternative Twitter data sources:**
- Nitter instances (e.g., `nitter.poast.org/USERNAME`) show tweets without login
- Syndication API: `https://syndication.twitter.com/srv/timeline-profile/screen-name/USERNAME`
- Twitter Snowflake IDs encode timestamps: `(id >> 22) + 1288834974657` = Unix ms
- memory.lol and twitter.lolarchiver.com track username history

**Wayback Machine for Twitter:**
```bash
# Find all archived URLs for a username
curl "http://web.archive.org/cdx/search/cdx?url=twitter.com/USERNAME*&output=json&fl=timestamp,original,statuscode"

# Also check profile images
curl "http://web.archive.org/cdx/search/cdx?url=pbs.twimg.com/profile_images/*&output=json"

# Check t.co shortlinks
curl "http://web.archive.org/cdx/search/cdx?url=t.co/SHORTCODE&output=json"
```

## Tumblr Investigation

**Blog existence check:**
- `curl -sI "https://USERNAME.tumblr.com"` → look for `x-tumblr-user` header (confirms blog exists even if API returns 401)
- Tumblr API may return 401 (Unauthorized) but the blog is still publicly viewable via browser

**Extracting post content from Tumblr HTML:**
- Tumblr embeds post data as JSON in the page HTML
- Search for `"content":[` to find post body data
- Posts contain `type: "text"` with `text` field, and `type: "image"` with media URLs
- Avatar URL pattern: `https://64.media.tumblr.com/HASH/HASH-XX/s512x512u_c1/FILENAME.jpg`

**Avatar as flag container:**
- Direct avatar endpoint: `https://api.tumblr.com/v2/blog/USERNAME.tumblr.com/avatar/512`
- Or simply: `https://USERNAME.tumblr.com/avatar/512` (redirects to CDN URL)
- Available sizes: 16, 24, 30, 40, 48, 64, 96, 128, 512
- Flags may be hidden as small text in avatar images (visual stego, not binary stego)
- Always download highest resolution (512) and zoom in on all areas

## Historical Research

- Scout Life magazine archive: https://scoutlife.org/wayback/
- Library of Congress: https://www.loc.gov/ (newspaper search)
- Use advanced search with date ranges

## DNS Reconnaissance

Flags often in TXT records of subdomains, not root domain:
```bash
dig -t txt subdomain.ctf.domain.com
dig -t any domain.com
dig axfr @ns.domain.com domain.com  # Zone transfer
```

## Google Docs/Sheets in OSINT

- Suspects may link to Google Sheets/Docs in tweets or posts
- Try public access URLs:
  - `/export?format=csv` - Export as CSV
  - `/pub` - Published version
  - `/gviz/tq?tqx=out:csv` - Visualization API CSV export
  - `/htmlview` - HTML view
- Private sheets require authentication; flag may be in the sheet itself
- Sheet IDs are stable identifiers even if sharing settings change

## MGRS (Military Grid Reference System)

**Pattern (On The Grid):** Encoded coordinates like "4V FH 246 677".

**Identification:** Challenge title mentions "grid", code format matches MGRS pattern.

**Conversion:** Use online MGRS converter → lat/long → Google Maps for location name.

## FEC Political Donation Research

**Pattern (Shell Game):** Track organizational donors through FEC filings.

**Key resources:**
- [FEC.gov](https://www.fec.gov/data/) - Committee receipts and expenditures
- 501(c)(4) organizations can donate to Super PACs without disclosing original funders
- Look for largest organizational donors, then research org leadership (CEO/President)

## BlueSky Advanced Search

**Pattern (Ms Blue Sky):** Find target's posts on BlueSky social media.

**Search filters:**
```
from:username        # Posts from specific user
since:2025-01-01     # Date range
has:images           # Posts with images
```

**Reference:** https://bsky.social/about/blog/05-31-2024-search

## Resources

- **Shodan** - Internet-connected devices
- **Censys** - Certificate and host search
- **VirusTotal** - File/URL reputation
- **WHOIS** - Domain registration
- **Wayback Machine** - Historical snapshots

## Reverse Image Search

- Google Images (most comprehensive)
- TinEye (exact match)
- Yandex (good for faces, Eastern Europe)
- Bing Visual Search

## Username OSINT

- [namechk.com](https://namechk.com) - Check username across platforms
- [whatsmyname.app](https://whatsmyname.app) - Username enumeration (741+ sites)
- Search `"username"` in quotes on major platforms

**Username chain tracing (account renames):**
1. Start with known username → find Wayback archives
2. Look for t.co links or cross-references to other usernames in archived pages
3. Discovered new username → enumerate across ALL platforms again
4. Repeat until you find the platform with the flag

**Platform false positives (return 200 but no real profile):**
- Telegram (`t.me/USER`): Always returns 200 with "Contact @USER" page; check for "View" vs "Contact" in title
- TikTok: Returns 200 with "Couldn't find this account" in body
- Smule: Returns 200 with "Not Found" in page content
- linkin.bio: Redirects to Later.com product page for unclaimed names
- Instagram: Returns 200 but shows login wall (may or may not exist)

**Priority platforms for CTF username enumeration:**
- Twitter/X, Tumblr, GitHub, Reddit, Bluesky, Mastodon
- Spotify, SoundCloud, Steam, Keybase
- Pastebin, LinkedIn, YouTube, TikTok
- bio-link services (linktr.ee, bio.link, about.me)

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
inurl:admin
"confidential" filetype:doc
```

## Telegram Bot Investigation

**Pattern:** Forensic artifacts (browser history, chat logs) may reference Telegram bots that require active interaction.

**Finding bot references in forensics:**
```python
# Search browser history for Telegram URLs
import sqlite3
conn = sqlite3.connect("History")  # Edge/Chrome history DB
cur = conn.cursor()
cur.execute("SELECT url FROM urls WHERE url LIKE '%t.me/%'")
# Example: https://t.me/comrade404_bot
```

**Bot interaction workflow:**
1. Visit `https://t.me/<botname>` → Opens in Telegram
2. Start conversation with `/start` or bot's custom command
3. Bot may require verification (CTF-style challenges)
4. Answers often require knowledge from forensic analysis

**Verification question patterns:**
- "Which user account did you use for X?" → Check browser history, login records
- "Which account was modified?" → Check Security.evtx Event 4781 (rename)
- "What file did you access?" → Check MRU, Recent files, Shellbags

**Example bot flow:**
```
Bot: "TIER 1: Which account used for online search?"
→ Answer from Edge history showing Bing/Google searches

Bot: "TIER 2: Which account name did you change?"
→ Answer from Security event log (account rename events)

Bot: [Grants access] "Website: http://x.x.x.x:5000, Username: mehacker, Password: flaghere"
```

**Key insight:** Bot responses may reveal:
- Attacker's real identity/handle
- Credentials to secondary systems
- Direct flag components
- Links to hidden web services

## MetaCTF OSINT Challenge Patterns

**Common flow:**
1. Start image with hidden EXIF/metadata → extract username
2. Username enumeration (Sherlock/WhatsMyName) across platforms
3. Find profile on platform X with clues pointing to platform Y
4. Flag hidden on the final platform (Spotify bio, BlueSky post, Tumblr avatar, etc.)

**Platform-specific flag locations:**
- Spotify: playlist names, artist bio
- BlueSky: post content
- Tumblr: avatar image, post text
- Reddit: post/comment content
- Smule: song recordings or bio
- SoundCloud: track description

**Key techniques:**
- Account rename tracking via Wayback + t.co links
- Cross-platform username correlation
- Visual inspection of all profile images at max resolution
- Song lyric identification → artist/song as flag component

## IP Geolocation & Attribution

**Free geolocation services:**
```bash
# IP-API (no key required)
curl "http://ip-api.com/json/103.150.68.150"

# ipinfo.io
curl "https://ipinfo.io/103.150.68.150/json"
```

**Bangladesh IP ranges (common in KCTF):**
- `103.150.x.x` - Bangladesh ISPs
- Mobile prefixes: +880 13/14/15/16/17/18/19

**Correlating location with evidence:**
- Windows telemetry (imprbeacons.dat) contains `CIP` field
- Login history APIs may show IP + OS correlation
- VPN/proxy detection via ASN lookup
