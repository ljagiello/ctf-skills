# Social Media OSINT

## Table of Contents
- [Twitter/X Account Tracking](#twitterx-account-tracking)
- [Tumblr Investigation](#tumblr-investigation)
- [BlueSky Advanced Search](#bluesky-advanced-search)
- [Username OSINT](#username-osint)
- [Platform False Positives](#platform-false-positives)
- [Social Media General Tips](#social-media-general-tips)
- [Multi-Platform OSINT Chain](#multi-platform-osint-chain)
- [MetaCTF OSINT Challenge Patterns](#metactf-osint-challenge-patterns)
- [Discord API Enumeration](#discord-api-enumeration)

---

## Twitter/X Account Tracking

**Persistent numeric User ID (key technique):**
- Every Twitter/X account has a permanent numeric ID that never changes
- Access any account by ID: `https://x.com/i/user/<numeric_id>` -- works even after username changes
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
- `curl -sI "https://USERNAME.tumblr.com"` -> look for `x-tumblr-user` header (confirms blog exists even if API returns 401)
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

## BlueSky Advanced Search

**Pattern (Ms Blue Sky):** Find target's posts on BlueSky social media.

**Search filters:**
```
from:username        # Posts from specific user
since:2025-01-01     # Date range
has:images           # Posts with images
```

**Reference:** https://bsky.social/about/blog/05-31-2024-search

## Username OSINT

- [namechk.com](https://namechk.com) - Check username across platforms
- [whatsmyname.app](https://whatsmyname.app) - Username enumeration (741+ sites)
- Search `"username"` in quotes on major platforms

**Username chain tracing (account renames):**
1. Start with known username -> find Wayback archives
2. Look for t.co links or cross-references to other usernames in archived pages
3. Discovered new username -> enumerate across ALL platforms again
4. Repeat until you find the platform with the flag

**Priority platforms for CTF username enumeration:**
- Twitter/X, Tumblr, GitHub, Reddit, Bluesky, Mastodon
- Spotify, SoundCloud, Steam, Keybase
- Pastebin, LinkedIn, YouTube, TikTok
- bio-link services (linktr.ee, bio.link, about.me)

## Platform False Positives

Platforms that return 200 but no real profile:
- Telegram (`t.me/USER`): Always returns 200 with "Contact @USER" page; check for "View" vs "Contact" in title
- TikTok: Returns 200 with "Couldn't find this account" in body
- Smule: Returns 200 with "Not Found" in page content
- linkin.bio: Redirects to Later.com product page for unclaimed names
- Instagram: Returns 200 but shows login wall (may or may not exist)

## Social Media General Tips

- Check Wayback Machine for deleted posts on Bluesky, Twitter, etc.
- Unlisted YouTube videos may be linked in deleted posts
- Bio links lead to itch.io, personal sites with more info
- Search `"username"` with quotes on platform-specific searches
- Challenge titles are often hints (e.g., "Linked Traces" -> LinkedIn / linked accounts)
- **Twitter strips EXIF** on upload - don't waste time on stego for Twitter-served images
- **Tumblr preserves more metadata** in avatars than in post images

## Multi-Platform OSINT Chain

**Pattern (Massive-Equipment393):** Reddit username -> Spotify social link -> Base58-encoded string -> Spotify playlist descriptions (base64) -> first-letter acrostic from song titles.

**Key techniques:**
- Base58 decoding for non-standard encodings
- Spotify playlists encode data in descriptions and song title initials
- Platform chaining: each platform links to the next

## MetaCTF OSINT Challenge Patterns

**Common flow:**
1. Start image with hidden EXIF/metadata -> extract username
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
- Song lyric identification -> artist/song as flag component

## Discord API Enumeration

**Pattern (Insanity 1 & 2, 0xFun 2026):** Flags hidden in Discord server metadata not visible in normal UI.

**Hiding spots:**
- Role names
- Animated GIF emoji (flag in 2nd frame with tiny duration)
- Message embeds
- Server description, stickers, events

```bash
# Enumerate with user token
TOKEN="your_token"
# List roles
curl -H "Authorization: $TOKEN" "https://discord.com/api/v10/guilds/GUILD_ID/roles"
# List emojis
curl -H "Authorization: $TOKEN" "https://discord.com/api/v10/guilds/GUILD_ID/emojis"
# Search messages
curl -H "Authorization: $TOKEN" "https://discord.com/api/v10/guilds/GUILD_ID/messages/search?content=flag"
```

**Animated emoji:** Download GIF, extract frames -- hidden data in brief frames invisible at normal speed.
