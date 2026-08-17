# Threat Intel, Crypto, Media, Geo, Regional, Telegram OSINT

> Reference content for the `offensive-osint` skill. Originally §29 + §30 + §31 + §32 + §37 + §38 of the monolithic SKILL.md (refactored 2026-05-02 for size/load efficiency).

## 29. Threat Intel & IOCs

- Vendor / CERT advisories: CISA/NSA/CSA joint advisories, CERT-EU, NCSC-UK, JPCERT/CC, CERT-UA.
- [MISP Project](https://www.misp-project.org/) and public MISP feeds.
- [OpenCTI](https://www.opencti.io/) — CTI knowledge graph.
- [Malpedia](https://malpedia.caad.fkie.fraunhofer.de/) — malware families, YARA, references.
- [ThreatFox](https://threatfox.abuse.ch/), [URLHaus](https://urlhaus.abuse.ch/), [SSLBL](https://sslbl.abuse.ch/).
- [MalwareBazaar](https://bazaar.abuse.ch/) — hash-based sample sharing.
- [PhishTank](https://www.phishtank.com/), [OpenPhish](https://openphish.com/).

### 29.1 Malware Analysis & Sandboxes

- Static: [pefile](https://github.com/erocarrera/pefile), [FLOSS](https://github.com/mandiant/flare-floss), [capa](https://github.com/mandiant/capa).
- Similarity: SSDEEP, TLSH.
- Sandboxes: [ANY.RUN](https://any.run/), [Hybrid Analysis](https://www.hybrid-analysis.com/), [CAPE](https://capesandbox.com/), [Tria.ge](https://tria.ge/).
- Intelligence: [Intezer](https://analyze.intezer.com/) (code reuse), [VirusTotal](https://www.virustotal.com/) — **caution: uploads become public**.
- TLS: [JA3](https://github.com/salesforce/ja3), [JA4](https://github.com/FingerprinTLS/ja4).

### 29.2 Vulnerability Prioritization Data Sources

Methodology in companion skill §28. Concrete data sources here.

| Source | URL | What it tells you |
|---|---|---|
| **NVD** | `https://nvd.nist.gov/vuln/search` (or API `services.nvd.nist.gov/rest/json/cves/2.0`) | Base CVE catalog with CVSS v2/v3 scores. |
| **EPSS** | `https://www.first.org/epss/` (CSV at `https://epss.cyentia.com/epss_scores-current.csv.gz`) | 0.0-1.0 probability of exploit in next 30 days. Updated daily. |
| **CISA KEV** | `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` | CVEs proven exploited in the wild + federal-agency due-by dates. |
| **ExploitDB** | `https://www.exploit-db.com/`; offline DB via `searchsploit` | POC code presence (Metasploit, Python, shell). |
| **Metasploit module catalog** | `https://www.rapid7.com/db/modules/` (or `msfconsole > search cve:CVE-2024-XXXX`) | Automation availability. |
| **InTheWild.io** | `https://inthewild.io/` | Community-curated "actively exploited" tracker. |
| **OpenCVE** | `https://www.opencve.io/` | Timeline + watchlist + alerts. |
| **Trickest CVE → POC mapping** | `https://github.com/trickest/cve` | Auto-generated CVE → public POC repo links. |
| **GitHub Security Advisories** | `https://github.com/advisories` | Per-language / per-ecosystem advisories. |
| **MITRE CVE List** | `https://cve.mitre.org/cve/` | Official CVE registry. |
| **VulnDB** | `https://vulndb.cyberriskanalytics.com/` | Paid; commercial enrichment. |
| **OSV.dev** | `https://osv.dev/` | Open-source vulnerability DB; JSON API. |
| **Vulncheck KEV** | `https://vulncheck.com/kev` | Expanded KEV feed (more than CISA). |
| **Tenable Research** | `https://www.tenable.com/research` | Tenable's CVE detail enrichment. |
| **Qualys ThreatPROTECT** | `https://threatprotect.qualys.com/` | Qualys' threat-context enrichment. |

**Workflow:**
```bash
# 1. Get EPSS score for a CVE
curl -sk "https://api.first.org/data/v1/epss?cve=CVE-2024-3400" | jq '.data[0]'

# 2. Check if in CISA KEV
curl -sk https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json | \
  jq '.vulnerabilities[] | select(.cveID == "CVE-2024-3400")'

# 3. Check ExploitDB
searchsploit cve 2024-3400

# 4. Check Metasploit
msfconsole -q -x "search cve:2024-3400; exit"
```

**Bulk prioritization** (given a Nuclei scan output with N CVEs):
```bash
# Extract CVEs from nuclei JSON output
jq -r '.info.classification.["cve-id"][]?' nuclei-results.json | sort -u > cves.txt

# Annotate each with EPSS + KEV
while IFS= read -r CVE; do
  EPSS=$(curl -sk "https://api.first.org/data/v1/epss?cve=$CVE" | jq -r '.data[0].epss // "N/A"')
  KEV=$(curl -sk https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json | \
    jq --arg c "$CVE" '.vulnerabilities[] | select(.cveID == $c) | .vulnerabilityName // empty')
  KEV_FLAG=$([ -n "$KEV" ] && echo "KEV" || echo "")
  echo "$CVE | EPSS:$EPSS | $KEV_FLAG"
done < cves.txt | sort -t: -k2 -nr

---

## 30. Cryptocurrency OSINT

### 30.1 Blockchain Explorers

| Chain | Explorer |
|-------|---------|
| Bitcoin | [Blockchain.com](https://www.blockchain.com/explorer), [Blockchair](https://blockchair.com/) |
| Ethereum | [Etherscan](https://etherscan.io/) |
| BNB Chain | [BSCScan](https://bscscan.com/) |
| Polygon PoS | [PolygonScan](https://polygonscan.com/) |
| Solana | [Solscan](https://solscan.io/) |
| Multi-chain | [OKLink](https://www.oklink.com/) (freemium), [Cielo](https://cielo.io/) |

### 30.2 L2 / Rollup Explorers

| L2 | Explorer | Notes |
|---|---|---|
| Arbitrum | [Arbiscan](https://arbiscan.io/) | Optimistic rollup; 7-day challenge window. |
| Optimism | [Optimistic Etherscan](https://optimistic.etherscan.io/) | Optimistic rollup; 7-day challenge window. |
| Base | [BaseScan](https://basescan.org/) | OP Stack. |
| Blast | [Blastscan](https://blastscan.io/) | OP Stack derivative. |
| Scroll | [Scrollscan](https://scrollscan.com/) | zkEVM. |
| zkSync Era | [zkSync Era Block Explorer](https://explorer.zksync.io/) | zkRollup; faster finality. |
| Polygon zkEVM | [PolygonScan zkEVM](https://zkevm.polygonscan.com/) | zkEVM. |
| StarkNet | [Voyager](https://voyager.online/), [StarkScan](https://starkscan.co/) | Cairo VM; different address derivation. |
| Cross-L2 | [L2Beat](https://l2beat.com/) | Risk framework + TVL comparison. |

### 30.3 Transaction Tracking & Analytics

- [Arkham](https://www.arkhamintelligence.com/) — multichain, entity labels, graphs, alerts.
- [TRM](https://www.trmlabs.com/) — address/tx graphs.
- [MetaSleuth](https://metasleuth.io/) — visual flow.
- [Breadcrumbs](https://www.breadcrumbs.app/) (freemium) — visual graphing + labels.
- [Bubblemaps](https://bubblemaps.io/) — holder concentration.
- [Whale Alert](https://whale-alert.io/) — large transaction monitoring.
- [Chainalysis](https://www.chainalysis.com/) / [Crystal Blockchain](https://crystalblockchain.com/) — pro analytics.
- [GraphSense](https://graphsense.info/) — open-source crypto analytics.
- [Nansen](https://www.nansen.ai/) — Smart Money labels (paid).
- [Dune](https://dune.com/) — custom queries.
- [Token Sniffer](https://tokensniffer.com/) — honeypot/scam detection.

### 30.4 NFT / Exchange / Bridges

- [OpenSea](https://opensea.io/), [NFTScan](https://www.nftscan.com/), [DappRadar](https://dappradar.com/), [CoinGecko](https://www.coingecko.com/), [CoinMarketCap](https://coinmarketcap.com/), [Glassnode](https://glassnode.com/).
- Bridges: [Socketscan](https://socketscan.io/), [L2Beat Bridges](https://l2beat.com/bridges), [Pulsy](https://pulsy.io/).

---

## 31. Media Intelligence

### 31.1 Reverse Image & Facial Search

- [Google Images](https://images.google.com/), [TinEye](https://tineye.com/), [Yandex Images](https://yandex.com/images/) (Russian/East European strong), [PimEyes](https://pimeyes.com/en), [FaceCheck](https://facecheck.id/).

### 31.2 Image Forensics

- [Forensically](https://29a.ch/photo-forensics/), [ExifTool](https://exiftool.org/), [Jimpl](https://jimpl.com/), [Jeffrey's EXIF Viewer](http://exif.regex.info/exif.cgi), [FOCA](https://www.elevenpaths.com/labstools/foca), [Metagoofil](https://www.edge-security.com/metagoofil.php), [C2PA Verify](https://verify.contentauthenticity.org/).

### 31.3 Video Analysis

- [YouTube Data Viewer](https://citizenevidence.amnestyusa.org/), [InVID & WeVerify](https://www.invid-project.eu/tools-and-services/invid-verification-plugin/), [YouTube Geo Tag](https://mattw.io/youtube-geofind/location), [MediaInfo](https://mediaarea.net/en/MediaInfo), Snap Map.

### 31.4 Browser Extensions for Media

- [Fake News Debunker (InVID & WeVerify)](https://chrome.google.com/webstore/detail/fake-news-debunker-by-inv/mhccpoafgdgbhnjfhkcmgknndkeenfhe).
- [RevEye Reverse Image Search](https://chrome.google.com/webstore/detail/reveye-reverse-image-sear/kejaocbebojdmebagkjghljkeefgimdj).
- [EXIF Viewer Pro](https://chrome.google.com/webstore/detail/exif-viewer-pro/mmbhfeiddhndihdjeganjggkmjapkffm).
- [Wayback Machine Extension](https://chrome.google.com/webstore/detail/wayback-machine/fpnmgdkabkmnadcjpehmlllkndpkmiak).
- [Search by Image](https://chromewebstore.google.com/detail/search-by-image/cnojnbdhbhnkbcieeekonklommdnndci).

---

## 32. Geospatial Intelligence

### 32.1 Satellite & Mapping

- [Google Maps](https://www.google.com/maps), [Bing Maps](https://www.bing.com/maps/).
- [Sentinel Hub EO Browser](https://apps.sentinel-hub.com/eo-browser/), [NASA Worldview](https://worldview.earthdata.nasa.gov/), [Zoom Earth](https://zoom.earth/).
- [Wayback Imagery](https://livingatlas.arcgis.com/wayback/) — historical satellite.
- [NASA FIRMS](https://firms.modaps.eosdis.nasa.gov/map/), [Open Infrastructure Map](https://openinframap.org/), [Windy](https://www.windy.com/).

### 32.2 Geolocation Tools

- [Mapillary](https://www.mapillary.com/app), [KartaView](https://kartaview.org/), [Overpass Turbo](https://overpass-turbo.eu/), [SunCalc](https://www.suncalc.org/), [GeoNames](https://www.geonames.org/), [PeakVisor](https://peakvisor.com/), [GeoGuesser tips](https://somerandomstuff1.wordpress.com/2019/02/08/geoguessr-the-top-tips-tricks-and-techniques/).

**Street View:** Google Street View, [Apple Maps](https://maps.apple.com/), [Yandex Maps](https://yandex.com/maps/), [Baidu Maps](https://map.baidu.com/).

### 32.3 Flight OSINT

- [FlightRadar24](https://www.flightradar24.com/), [FlightAware](https://www.flightaware.com/), [RadarBox](https://www.radarbox.com/).
- [ADSBExchange](https://www.adsbexchange.com/) — unfiltered.
- [Planespotters](https://www.planespotters.net/) — fleet/airframe history.
- [AirFrames](https://www.airframes.org/), [JetPhotos](https://www.jetphotos.com/).

### 32.4 Maritime OSINT

- [MarineTraffic](https://www.marinetraffic.com/), [VesselFinder](https://www.vesselfinder.com/), [FleetMon](https://www.fleetmon.com/).
- [Global Fishing Watch](https://globalfishingwatch.org/map/) — vessel behavior + AIS gap analysis.

---


## 37. Regional Search Engines

- **Russia / CIS:** [Yandex](https://yandex.com/), [Mail.ru Search](https://go.mail.ru/).
- **China:** [Baidu](https://www.baidu.com/), [Sogou](https://www.sogou.com/), [360 Search](https://www.so.com/).
- **Russia social:** [VK](https://vk.com/), [OK.ru](https://ok.ru/).
- **China social:** [Weibo](https://weibo.com/), [Bilibili](https://www.bilibili.com/), [Zhihu](https://www.zhihu.com/), [Douyin](https://www.douyin.com/).

---

## 38. Telegram & Messaging Intelligence

- [TGStat](https://tgstat.com/) — channel analytics + search.
- [Telemetr](https://telemetr.io/) — channel growth, overlaps, forwards.
- [Combot](https://combot.org/) — group analytics (partial paid).
- [TelegramDB Search Bot](https://t.me/TGdb_bot) — basic Telegram OSINT.
- [Discord ID](https://discord.id/) — basic Discord account info.
- [Sogou Weixin search](https://weixin.sogou.com/) — WeChat Official Accounts.
- View public Telegram channels: `https://t.me/s/<channel>`.

---

