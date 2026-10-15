# CTF OSINT - MCP Server Integration

OSINT is browser-heavy: reverse-image search, map/Street View exploration,
social-media profiles, archived pages, and JS-rendered sites that `curl` cannot
read. **Playwright MCP** drives a real browser from the agent so it can navigate,
screenshot, read rendered content, and step through interactive search flows.

## Table of Contents
- [Setup](#setup)
- [Rendered-Page Reading & Screenshots](#rendered-page-reading--screenshots)
- [Reverse-Image & Map Search Flows](#reverse-image--map-search-flows)
- [Social Media & Archived Pages](#social-media--archived-pages)
- [When to Use Playwright MCP vs curl/API](#when-to-use-playwright-mcp-vs-curlapi)

Full tool list and the general browser workflow live in
[../ctf-web/tools-mcp.md](../ctf-web/tools-mcp.md#playwright-mcp-browser-automation).

---

## Setup

Repository: `https://github.com/microsoft/playwright-mcp` (Apache-2.0, official
Microsoft, tested v0.0.78+).

```bash
npx @playwright/mcp@latest        # most MCP clients auto-launch this
# The browser binary is a separate download; without it every call errors with
# 'Browser "chrome-for-testing" is not installed':
npx @playwright/mcp@latest install-browser chrome-for-testing
```

Snapshots, console logs and non-text response bodies are written to
`.playwright-mcp/` in the working directory and returned as file paths — read the
file, and keep that directory out of version control.

---

## Rendered-Page Reading & Screenshots

Modern OSINT targets render content with JavaScript — a raw fetch returns an empty
shell. Playwright reads the page *after* JS runs.

```text
browser_navigate "https://example.com/profile/target"
browser_snapshot                # rendered text/links/roles as an accessibility tree
browser_take_screenshot         # capture the visual for geolocation clues
browser_evaluate "() => document.body.innerText"   # full rendered text dump
```

**Key insight:** For any site that shows a blank page or a loading spinner under
`curl`, Playwright MCP is the fix — `browser_snapshot` returns the content the way
a human sees it, after client-side rendering, so names, timestamps, and hidden
metadata become readable.

---

## Reverse-Image & Map Search Flows

Reverse-image search and map exploration are multi-step interactive flows the
agent can script end to end.

```text
# Reverse image search
browser_navigate "https://images.google.com"
browser_click <camera / "Search by image" ref from snapshot>
browser_type <url field ref> "https://example.com/clue.jpg"
browser_press_key Enter
browser_snapshot                # read the visual-match results + candidate locations

# Map / Street View narrowing (cross-ref geolocation-and-media.md)
browser_navigate "https://www.google.com/maps/@<lat>,<lon>,3a,75y/data=..."
browser_take_screenshot         # compare panorama landmarks against the target photo
```

**Key insight:** Geolocation challenges are iterative — search, read candidates,
refine, re-search. Playwright MCP lets the agent run that loop autonomously:
submit the image, read the top matches from the snapshot, then pivot to maps to
confirm landmarks. Pair with the manual techniques in
[geolocation-and-media.md](geolocation-and-media.md).

---

## Social Media & Archived Pages

```text
browser_navigate "https://web.archive.org/web/*/example.com"
browser_snapshot                # list all snapshots; open one to read content deleted from the live site
browser_navigate "https://example.com/@target"
browser_evaluate "() => document.body.innerText"   # bio, post timestamps, geotags
browser_network_requests static=false filter="/api/"   # find the profile JSON endpoint
browser_network_request index=<n> part="response-body" # read the JSON itself
```

**Key insight:** a social site's profile JSON API is where the real intelligence
is — IDs, exact timestamps, coordinates that the rendered HTML rounds off or
omits. But `browser_network_requests` only *lists* the endpoints; the structured
data comes from `browser_network_request part="response-body"`. Take both steps,
then pivot to username/metadata mining (see [social-media.md](social-media.md)
and [web-and-dns.md](web-and-dns.md)).

---

## When to Use Playwright MCP vs curl/API

| Situation | Use |
|-----------|-----|
| JS-rendered page, infinite scroll, or login wall | Playwright MCP |
| Interactive reverse-image / map search flow | Playwright MCP |
| Reading archived (Wayback) snapshots visually | Playwright MCP |
| Bulk WHOIS / DNS / cert transparency lookups | CLI/API (see [web-and-dns.md](web-and-dns.md)) |
| Structured API with a documented endpoint | `requests`/API — faster, no browser |

**Key insight:** Use Playwright MCP when the intelligence is locked behind
client-side rendering or an interactive UI. For structured lookups (DNS, WHOIS,
cert transparency, platform APIs) the direct CLI/API path stays faster and more
scriptable.
