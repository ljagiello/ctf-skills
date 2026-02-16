# Geolocation and Media Analysis

## Table of Contents

- [Image Analysis](#image-analysis)
- [Reverse Image Search](#reverse-image-search)
- [Geolocation Techniques](#geolocation-techniques)
- [MGRS (Military Grid Reference System)](#mgrs-military-grid-reference-system)
- [Metadata Extraction](#metadata-extraction)
- [Hardware/Product Identification](#hardwareproduct-identification)
- [Newspaper Archives and Historical Research](#newspaper-archives-and-historical-research)
- [IP Geolocation and Attribution](#ip-geolocation-and-attribution)

---

## Image Analysis

- Discord avatars: Screenshot and reverse image search
- Identify objects in images (weapons, equipment) -> find character/faction
- No EXIF? Use visual features (buildings, signs, landmarks)
- **Visual steganography**: Flags hidden as tiny/low-contrast text in images (not binary stego)
  - Always view images at full resolution and check ALL corners/edges
  - Black-on-dark or white-on-light text, progressively smaller fonts
  - Profile pictures/avatars are common hiding spots
- **Twitter strips EXIF** on upload - don't waste time on stego for Twitter-served images
- **Tumblr preserves more metadata** in avatars than in post images

## Reverse Image Search

- Google Images (most comprehensive)
- TinEye (exact match)
- Yandex (good for faces, Eastern Europe)
- Bing Visual Search

## Geolocation Techniques

- Railroad crossing signs: white X with red border = Canada
- Use infrastructure maps:
  - [Open Infrastructure Map](https://openinframap.org) - power lines
  - [OpenRailwayMap](https://www.openrailwaymap.org/) - rail tracks
  - High-voltage transmission line maps
- Process of elimination: narrow by country first, then region
- Cross-reference multiple features (rail + power lines + mountains)
- MGRS coordinates: grid-based military system (e.g., "4V FH 246 677") -> convert online

## MGRS (Military Grid Reference System)

**Pattern (On The Grid):** Encoded coordinates like "4V FH 246 677".

**Identification:** Challenge title mentions "grid", code format matches MGRS pattern.

**Conversion:** Use online MGRS converter -> lat/long -> Google Maps for location name.

## Metadata Extraction

```bash
exiftool image.jpg           # EXIF data
pdfinfo document.pdf         # PDF metadata
mediainfo video.mp4          # Video metadata
```

## Hardware/Product Identification

**Pattern (Computneter, VuwCTF 2025):** Battery specifications -> manufacturer identification. Cross-reference specs (voltage, capacity, form factor) with manufacturer databases.

## Newspaper Archives and Historical Research

- Scout Life magazine archive: https://scoutlife.org/wayback/
- Library of Congress: https://www.loc.gov/ (newspaper search)
- Use advanced search with date ranges

**Pattern (It's News, VuwCTF 2025):** Combine newspaper archive date search with EXIF GPS coordinates for location-specific identification.

**Tools:** Library of Congress newspaper archive, Google Maps for GPS coordinate lookup.

## IP Geolocation and Attribution

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
