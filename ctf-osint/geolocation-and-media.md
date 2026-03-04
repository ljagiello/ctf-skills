# Geolocation and Media Analysis

## Table of Contents

- [Image Analysis](#image-analysis)
- [Reverse Image Search](#reverse-image-search)
- [Geolocation Techniques](#geolocation-techniques)
- [MGRS (Military Grid Reference System)](#mgrs-military-grid-reference-system)
- [Metadata Extraction](#metadata-extraction)
- [Hardware/Product Identification](#hardwareproduct-identification)
- [Newspaper Archives and Historical Research](#newspaper-archives-and-historical-research)
- [Google Street View Panorama Matching (EHAX 2026)](#google-street-view-panorama-matching-ehax-2026)
- [Road Sign Language and Driving Side Analysis (EHAX 2026)](#road-sign-language-and-driving-side-analysis-ehax-2026)
- [Post-Soviet Architecture and Brand Identification (EHAX 2026)](#post-soviet-architecture-and-brand-identification-ehax-2026)
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

## Google Street View Panorama Matching (EHAX 2026)

**Pattern (amnothappyanymore):** Challenge image is a cropped section of a Google Street View panorama. Must identify the exact panorama ID and coordinates.

**Approach:**
1. **Extract visual features:** Identify distinctive landmarks (road type, vehicles, containers, mountain shapes, building styles, vegetation)
2. **Narrow the region:** Use visual clues to identify country/region (e.g., Greenland landscape, specific road infrastructure)
3. **Compile candidate panoramas:** Use Google Street View coverage maps to find panoramas in the identified region
4. **Feature matching:** Compare challenge image features against candidate panoramas:
   ```python
   import cv2
   import numpy as np

   # Load challenge image and candidate panorama
   challenge = cv2.imread('challenge.jpg')
   candidate = cv2.imread('panorama.jpg')

   # ORB feature detection and matching
   orb = cv2.ORB_create(nfeatures=5000)
   kp1, des1 = orb.detectAndCompute(challenge, None)
   kp2, des2 = orb.detectAndCompute(candidate, None)

   bf = cv2.BFMatcher(cv2.NORM_HAMMING, crossCheck=True)
   matches = bf.match(des1, des2)
   score = sum(1 for m in matches if m.distance < 50)
   ```
5. **Ranking systems:** Use multiple scoring methods (global feature match, local patch comparison, color histogram analysis) and combine rankings
6. **API submission:** Submit panorama ID with coordinates in required format (e.g., `lat/lng/sessionId/nonce`)

**Google Street View API patterns:**
```python
# Street View metadata API (check if coverage exists)
# GET https://maps.googleapis.com/maps/api/streetview/metadata?location=LAT,LNG&key=KEY

# Street View image API
# GET https://maps.googleapis.com/maps/api/streetview?size=640x480&location=LAT,LNG&heading=90&key=KEY

# Panorama ID from page source (parsed from JavaScript):
# Look for panoId in page data structures
```

**Key insights:**
- Challenge images are often crops of panoramas — the crop region may not include horizon or sky, making geolocation harder
- Distinctive elements: road surface type, vehicle makes, signage language, utility poles, container colors
- Greenland, Iceland, Faroe Islands have limited Street View coverage — enumerate all panoramas in the region
- Image similarity ranking with multiple metrics (feature matching + color analysis + patch comparison) is more robust than any single method

---

## Road Sign Language and Driving Side Analysis (EHAX 2026)

**Pattern (date_spot):** Street view image of a coastal location. Identify exact coordinates from road infrastructure.

**Systematic approach:**
1. **Driving side:** Left-hand traffic → right-hand drive countries (Japan, UK, Australia, etc.)
2. **Sign language/script:** Kanji → Japan; Cyrillic → Russia/CIS; Arabic → Middle East/North Africa
3. **Road sign style:** Blue directional signs with white text and route numbers → Japanese expressways
4. **Sign OCR:** Extract text from directional signs to identify town/city names and route designations
5. **Route tracing:** Search identified route number + town names to find the road corridor
6. **Terrain matching:** Match coastline, harbors, lighthouses, bridges against satellite view

**Japanese infrastructure clues:**
- Blue highway signs with white Kanji + route numbers (e.g., E59)
- Distinctive guardrail style (galvanized steel, wavy profile)
- Concrete seawalls on coastal roads
- Small fishing harbors with white lighthouse structures

**General country identification shortcuts:**
| Feature | Country/Region |
|---------|---------------|
| Kanji + blue highway signs | Japan |
| Cyrillic + wide boulevards | Russia/CIS |
| White X-shape crossing signs | Canada |
| Yellow diamond warning signs | USA/Canada |
| Green autobahn signs | Germany |
| Brown tourist signs | France |
| Bollards with red reflectors | Netherlands |

---

## Post-Soviet Architecture and Brand Identification (EHAX 2026)

**Pattern (idinahui):** Coastal parking lot image. Identify location from architectural style, vehicle types, signage, and local brands.

**Recognition chain:**
1. **Architecture:** Brutalist concrete buildings → post-Soviet region
2. **Vehicles:** Reverse image search vehicle models to narrow to Russian/CIS market cars
3. **Script:** Cyrillic signage confirms Russian-language region
4. **Flags:** Regional government flags alongside national tricolor → identify specific federal subject
5. **Brands:** Named restaurants/chains (e.g., "Mimino" — Georgian-themed chain popular across Russia) → search for geographic distribution
6. **Coastal features:** Caspian Sea coastline + North Caucasus architecture → Dagestan/Makhachkala

**Key technique — restaurant/brand geolocation:**
- Identify any readable business name or brand logo
- Search for that business + "locations" or "branches"
- Cross-reference with other visual clues (coastline, terrain) to pinpoint exact branch
- Google Maps business search is highly effective for named establishments

**Post-Soviet visual markers:**
- Panel apartment blocks (khrushchyovka/brezhnevka)
- Wide boulevards with central medians
- Concrete bus stops
- Distinctive utility pole designs
- Soviet-era monuments and mosaics

---

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
