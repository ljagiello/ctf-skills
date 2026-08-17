# Cloudflare Bot Protection Bypass

Techniques for bypassing Cloudflare's anti-bot detection during authorized testing. Applicable to any Cloudflare-protected target (CTF platforms, bug bounty, pentests).

## How Cloudflare Detects Automation

| Signal | What It Checks | Detection Risk |
|--------|---------------|----------------|
| `navigator.webdriver` | `true` when CDP-controlled | Critical |
| WebGL renderer | "SwiftShader"/"llvmpipe" = no GPU | High |
| TLS/JA3 fingerprint | TLS ClientHello hash per library | High |
| IP reputation | Datacenter IPs penalized heavily | High |
| Behavioral biometrics | Mouse movement, typing cadence, scroll | Medium |
| CDP side effects | `Runtime.enable` traces in Error.stack | Medium |
| Canvas fingerprint | Pixel hash differs headless vs headed | Medium |
| `window.chrome` | Missing `chrome.app`, `chrome.csi` | Low |
| Plugins/mimeTypes | Empty = headless | Low |

## Bypass Strategy (Priority Order)

### 1. Use Headed Browser (Most Important)

Headless browsers are trivially detected. ALWAYS use headed mode.

**In Docker/server (no display):**
```bash
# Start Xvfb BEFORE Claude Code (the kali-claude-setup.sh script does this automatically)
Xvfb :99 -screen 0 1920x1080x24 &>/dev/null &
export DISPLAY=:99
```

**IMPORTANT**: Do NOT use `xvfb-run` as the MCP command — it wraps stdin/stdout and breaks MCP's stdio communication pipe. Instead, start Xvfb separately and set DISPLAY. The MCP server then launches headed Chrome which uses the virtual display.

**Playwright MCP config for Docker** (`.claude/mcp.json`):
```json
{
  "mcpServers": {
    "playwright": {
      "command": "npx",
      "args": ["@playwright/mcp@latest",
               "--launch-options", "{\"args\":[\"--disable-blink-features=AutomationControlled\",\"--no-sandbox\",\"--disable-setuid-sandbox\",\"--window-size=1920,1080\"]}"]
    }
  }
}
```

### 2. Anti-Detection Browser Flags

Essential Chromium flags:
```
--disable-blink-features=AutomationControlled  # Prevents navigator.webdriver=true
--disable-infobars                              # Removes automation banner
--disable-dev-shm-usage                         # Docker stability
--no-first-run --no-default-browser-check
--window-size=1920,1080
```

### 3. Realistic Browser Context

```
Viewport: 1920x1080 or 1366x768 (common resolutions)
Locale: en-US (match your IP geolocation)
Timezone: America/New_York (match your IP)
User-Agent: Must match actual Chrome version — never fabricate
Device scale factor: 1 (standard) or 2 (Retina)
```

### 4. Human-Like Behavior

- **Mouse**: Move to elements before clicking (Bezier curves, not teleport)
- **Typing**: Variable delays 50-200ms between keystrokes
- **Scrolling**: Incremental, variable speed, pause between scrolls
- **Timing**: Random delays 200ms-2s between actions (never uniform)
- **Idle movement**: Occasional mouse movements while "reading"

### 5. Session Persistence

After solving a Cloudflare challenge once, preserve cookies:
- `cf_clearance` — challenge pass token (15-30 min expiry)
- `__cf_bm` — bot management cookie
- Use `launchPersistentContext()` to reuse across sessions
- Re-authenticate only when cookies expire (403/challenge page returns)

### 6. Fallback: Direct API Access

Many Cloudflare-protected sites have APIs that bypass the web UI:
- **Platform APIs**: many Cloudflare-protected services expose a JSON API on a sibling subdomain (e.g. `api.<TARGET>` or `labs.<TARGET>`) reachable with a Bearer token from the user-settings/profile page
- **API tokens**: Check user settings/profile for App Tokens
- API calls with valid auth headers often skip Cloudflare challenges entirely

## Turnstile Challenge Handling

Cloudflare Turnstile replaces legacy CAPTCHAs. Three modes:

| Mode | Behavior | Bypass |
|------|----------|--------|
| Managed | Auto-solves if browser signals pass | Headed + stealth flags |
| Non-interactive | Visible widget, auto-completes | Wait for completion (~5s) |
| Interactive | Requires user action | AskUserQuestion for manual solve |

**Auto-solve approach** (works ~90% with headed + stealth):
1. Wait for Turnstile iframe to appear
2. Wait up to 15s for auto-completion
3. If still pending — `AskUserQuestion` for manual intervention

## IP Reputation

| IP Type | Risk Level | Recommendation |
|---------|-----------|----------------|
| Datacenter (AWS/GCP/Azure) | Blocked often | Avoid for web UI |
| VPN (commercial) | Medium risk | Acceptable for most engagements |
| Residential proxy | Low risk | Best for stealth |
| Home ISP | Lowest risk | Ideal |

## Quick Reference: CTF-Style Platform Pattern

```
Protected: Platform web UI (login, dashboard, flag submission)
Not protected: Lab machines via VPN (direct IP access)
Best approach: Headed browser with stealth flags for web UI
Fallback: Platform API + App Token (no browser needed)
Critical: Never headless against Cloudflare-protected UIs — instant block
```
