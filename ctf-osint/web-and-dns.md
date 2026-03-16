# Web and DNS OSINT

## Table of Contents
- [Google Dorking](#google-dorking)
- [Google Docs/Sheets in OSINT](#google-docssheets-in-osint)
- [DNS Reconnaissance](#dns-reconnaissance)
- [DNS TXT Record OSINT](#dns-txt-record-osint)
- [Tor Relay Lookups](#tor-relay-lookups)
- [GitHub Repository Comments](#github-repository-comments)
- [Telegram Bot Investigation](#telegram-bot-investigation)
- [FEC Political Donation Research](#fec-political-donation-research)
- [Wayback Machine](#wayback-machine)
- [WHOIS Investigation](#whois-investigation)
- [Resources](#resources)

---

## Google Dorking

```text
site:example.com filetype:pdf
intitle:"index of" password
inurl:admin
"confidential" filetype:doc
```

**Google Image TBS (To Be Searched) parameters:**

Append `&tbs=` filters to Google Image search URLs for precision filtering:

| Filter | Parameter | Example |
|--------|-----------|---------|
| Faces only | `itp:face` | Find profile photos |
| Clipart | `itp:clipart` | Logos, icons |
| Animated GIF | `itp:animated` | Animated images |
| Specific color | `ic:specific,isc:green` | Dominant color filter |
| Transparent BG | `ic:trans` | PNGs with transparency |
| Large images | `isz:l` | High resolution only |
| Min resolution | `isz:lt,islt:2mp` | Greater than 2 megapixels |

**Combined example:** Search LinkedIn for face photos of interns at a company:
```text
https://www.google.com/search?q="orange"+"alternant"+site:linkedin.com&tbm=isch&tbs=itp:face
```

**Key insight:** The `itp:face` filter is especially useful for OSINT — it strips out logos, banners, and UI screenshots from results, leaving only profile photos. Combine with `site:` and date range (`after:YYYY-MM-DD`) for targeted reconnaissance.

## Google Docs/Sheets in OSINT

- Suspects may link to Google Sheets/Docs in tweets or posts
- Try public access URLs:
  - `/export?format=csv` - Export as CSV
  - `/pub` - Published version
  - `/gviz/tq?tqx=out:csv` - Visualization API CSV export
  - `/htmlview` - HTML view
- Private sheets require authentication; flag may be in the sheet itself
- Sheet IDs are stable identifiers even if sharing settings change

## DNS Reconnaissance

Flags often in TXT records of subdomains, not root domain:
```bash
dig -t txt subdomain.ctf.domain.com
dig -t any domain.com
dig axfr @ns.domain.com domain.com  # Zone transfer
```

## DNS TXT Record OSINT

```bash
dig TXT ctf.domain.org
dig TXT _dmarc.domain.org
dig ANY domain.org
```

**Lesson:** DNS TXT records are publicly queryable. Always check TXT, CNAME, MX for CTF domains and subdomains.

## Tor Relay Lookups

```text
https://metrics.torproject.org/rs.html#simple/<FINGERPRINT>
```
Check family members and sort by "first seen" date for ordered flags.

## GitHub Repository Comments

**Pattern (Rogue, VuwCTF 2025):** Hidden information in GitHub repo comments (issue comments, PR reviews, commit messages, wiki edits).

**Check:** `gh api repos/OWNER/REPO/issues/comments`, `gh api repos/OWNER/REPO/commits`, wiki edit history.

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
1. Visit `https://t.me/<botname>` -> Opens in Telegram
2. Start conversation with `/start` or bot's custom command
3. Bot may require verification (CTF-style challenges)
4. Answers often require knowledge from forensic analysis

**Verification question patterns:**
- "Which user account did you use for X?" -> Check browser history, login records
- "Which account was modified?" -> Check Security.evtx Event 4781 (rename)
- "What file did you access?" -> Check MRU, Recent files, Shellbags

**Example bot flow:**
```text
Bot: "TIER 1: Which account used for online search?"
-> Answer from Edge history showing Bing/Google searches

Bot: "TIER 2: Which account name did you change?"
-> Answer from Security event log (account rename events)

Bot: [Grants access] "Website: http://x.x.x.x:5000, Username: mehacker, Password: flaghere"
```

**Key insight:** Bot responses may reveal:
- Attacker's real identity/handle
- Credentials to secondary systems
- Direct flag components
- Links to hidden web services

## FEC Political Donation Research

**Pattern (Shell Game):** Track organizational donors through FEC filings.

**Key resources:**
- [FEC.gov](https://www.fec.gov/data/) - Committee receipts and expenditures
- 501(c)(4) organizations can donate to Super PACs without disclosing original funders
- Look for largest organizational donors, then research org leadership (CEO/President)

## Wayback Machine

```bash
# Find all archived URLs for a site
curl "http://web.archive.org/cdx/search/cdx?url=example.com*&output=json&fl=timestamp,original,statuscode"
```

- Check for deleted posts, old profiles, cached pages
- CDX API for programmatic access to archive index

## WHOIS Investigation

```bash
# Basic WHOIS lookup
whois example.com

# Key fields to extract:
# - Registrant name/email/org (often redacted by privacy services)
# - Creation/expiration dates (timeline correlation)
# - Name servers (shared hosting identification)
# - Registrar (can indicate sophistication level)

# Historical WHOIS (before privacy was enabled)
# Use SecurityTrails, WhoisXML API, or DomainTools
curl "https://api.securitytrails.com/v1/domain/example.com/whois" \
  -H "APIKEY: YOUR_KEY"

# Reverse WHOIS — find all domains registered by same entity
# Search by registrant email, org name, or phone number
curl "https://reverse-whois-api.whoisxmlapi.com/api/v2" \
  -d '{"searchType":"current","mode":"purchase","basicSearchTerms":{"include":["target@email.com"]}}'

# IP WHOIS (find network owner)
whois 1.2.3.4
# Look for: NetName, OrgName, CIDR range, abuse contact

# ASN lookup
whois -h whois.radb.net AS12345
# Or use bgp.tools: https://bgp.tools/as/12345
```

**Key insight:** WHOIS data is most useful for timeline correlation (when was the domain registered relative to CTF events?), reverse lookups (what other domains share the same registrant?), and identifying shared infrastructure. Historical WHOIS via SecurityTrails or Wayback Machine can reveal pre-privacy registrant details.

---

## Resources

- **Shodan** - Internet-connected devices
- **Censys** - Certificate and host search
- **VirusTotal** - File/URL reputation
- **WHOIS** - Domain registration
- **Wayback Machine** - Historical snapshots
