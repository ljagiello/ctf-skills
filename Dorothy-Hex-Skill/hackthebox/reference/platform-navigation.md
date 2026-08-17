# Platform Navigation — Playwright Automation

## CRITICAL: Headed Browser Required

The platform uses Cloudflare Turnstile. **Headless browsers are blocked.** ALWAYS use headed mode.
See `skills/reconnaissance/reference/anti-bot-bypass.md` for setup (Xvfb for Docker, anti-detection flags).

## Login Flow

```
1. Ensure headed browser mode (Cloudflare will block headless)
2. Navigate to login page
3. Fill username/email field
4. Fill password field
5. Click login button
6. Wait for Turnstile challenge to auto-solve (up to 15s)
7. Handle 2FA if prompted (ask user for code)
8. Verify dashboard loaded
```

### Playwright Steps

```python
# Login (MUST be headed browser — headless will be blocked by Cloudflare)
await page.goto("https://app.hackthebox.com/login")
await page.fill('input[name="email"]', email)
await page.fill('input[name="password"]', password)
await page.click('button[type="submit"]')

# Wait for Turnstile if it appears (auto-solves in headed mode)
await page.wait_for_timeout(5000)

# Wait for dashboard
await page.wait_for_url("**/dashboard**", timeout=30000)
```

## Dashboard Navigation

| Section | Purpose |
|---------|---------|
| Machines | Full OS-level targets (easy→insane) |
| Challenges | Category-specific puzzles (web, crypto, pwn, etc.) |
| Starting Point | Guided beginner machines |
| Seasonal | Time-limited competitive machines |
| Labs | Multi-machine enterprise environments |

## Machine Interaction

```
1. Navigate to machine page
2. Read description, difficulty, tags
3. Click "Join Machine" / "Spawn Machine"
4. Wait for target IP assignment
5. Copy target IP for pentest agent
```

## Challenge Interaction

```
1. Navigate to challenge page
2. Read description and category
3. Download challenge files if any
4. Click "Start Instance"
5. Note connection details (IP:port or URL)
6. Submit flag via platform UI or API
```

## VPN Config Download

```
1. Navigate to Access / Connection Pack section
2. Select appropriate VPN server (nearest region)
3. Download .ovpn file
4. Save to {OUTPUT_DIR}/artifacts/vpn/
```

## Flag Submission

```python
# Via Playwright
await page.fill('input[placeholder*="flag"]', flag)
await page.click('button:has-text("Submit")')

# Verify acceptance
success = await page.locator('.success-message').is_visible()
```

## Tab Management

**Tab 0 = Control Tab** (challenge/machine page). NEVER close it.

```
Tab layout:
  Tab 0: Platform challenge/machine page (control plane)
  Tab 1: Target web app (primary attack surface)
  Tab 2+: Additional endpoints, admin panels, etc.
```

### Machine State Operations (Tab 0) — Autonomous Control

**Always use Playwright MCP tools directly. Do NOT ask the user to click buttons.**

To perform ANY machine state change:
1. `browser_tabs` → identify Tab 0 (the challenge/machine page)
2. If not already on Tab 0: `browser_navigate` to Tab 0's URL (or click its tab)
3. `browser_snapshot` → read the accessibility tree to find the current state and action buttons
4. `browser_click` on the appropriate button by `ref` from the snapshot

#### Specific Operations

**Check state:**
```
browser_tabs                    # Find Tab 0
browser_snapshot                # Look for: "Running", "Stopped", "Expired", timer text
```

**Start / Spawn machine:**
```
browser_snapshot                # Find "Spawn Machine" or "Start Instance" button ref
browser_click ref="<ref>"       # Click it
browser_wait_for text="Running" # Wait for state change
browser_snapshot                # Confirm Running + capture IP address
```

**Stop machine:**
```
browser_snapshot                # Find "Stop" button ref
browser_click ref="<ref>"       # Click it
browser_wait_for text="Stopped" # Confirm stopped
```

**Reset machine (clean state):**
```
browser_snapshot                # Find "Reset Machine" button ref
browser_click ref="<ref>"       # Click it — may trigger confirmation dialog
browser_handle_dialog accept=true  # Accept "Are you sure?" if prompted
browser_wait_for text="Running" timeout=60000  # Wait for reset to complete
browser_snapshot                # Confirm Running + same IP
```

**Extend timer:**
```
browser_snapshot                # Find "Extend" button ref (usually near timer)
browser_click ref="<ref>"       # Click it
browser_snapshot                # Confirm timer reset
```

**Submit flag:**
```
browser_snapshot                # Find flag input field ref
browser_fill_form ref="<ref>" value="<FLAG>"  # Fill the flag
browser_snapshot                # Find "Submit" / "Submit Flag" button ref
browser_click ref="<ref>"       # Submit
browser_snapshot                # Verify success message
```

### When to Manage Machine State Autonomously

- **Before attacking**: Verify machine is Running. If Stopped/Expired → Start it.
- **Target unreachable**: Switch to Tab 0, check state. If Stopped → Restart. If Expired → Re-spawn.
- **Timer low** (< 5 min): Extend before continuing.
- **Corrupted state** (app broken after failed exploit): Reset machine, wait for clean state.
- **After flag capture**: Submit flag directly from Tab 0.
- **Done with challenge**: Stop machine to free resources.

### Workflow

1. After login → navigate to challenge page → **this is now Tab 0**
2. Spawn/start machine from Tab 0 (autonomous — click the button)
3. Open **new tab** for target interaction (Tab 1+)
4. Before each attack phase → switch to Tab 0, `browser_snapshot`, confirm Running
5. If target unreachable → switch to Tab 0, check state, restart/reset autonomously
6. After flag capture → switch to Tab 0, submit flag via UI
7. Work tabs are disposable — close/reopen as needed

### Tab Navigation Commands

```
# List all tabs — find Tab 0
browser_tabs

# Open new tab for target (keeps Tab 0 intact)
browser_navigate url="http://TARGET" new_tab=true

# Switch back to Tab 0 (use its URL from browser_tabs output)
browser_navigate url="https://app.hackthebox.com/machines/<MachineName>"
# OR click the tab from browser_tabs list

# Always snapshot after switching to read the page state
browser_snapshot
```

## Tips

- Take screenshots at each step: `await page.screenshot(path="evidence/screenshots/step-N.png")`
- The platform uses dynamic loading — use `wait_for_selector` not just `goto`
- Session tokens expire — re-login if 401/403 encountered
- Rate limiting exists — add small delays between rapid navigation
- **Always check Tab 0** before concluding "target is down" — it may just need respawning
