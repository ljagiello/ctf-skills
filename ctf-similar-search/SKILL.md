---
name: ctf-similar-search
description: Searches for similar CTF challenge writeups using Tavily API for search and content extraction. Use when the user requests finding related challenges, when solve-challenge has failed multiple times and needs reference solutions, or when first identifying a challenge type and seeking examples.
license: MIT
compatibility: Requires filesystem-based agent (Claude Code or similar) with bash and Python 3 with requests and tavily packages.
allowed-tools: Bash Read Write Glob Grep Skill
metadata:
  user-invocable: "true"
  argument-hint: "<challenge-name-or-clues>"
---

# CTF Similar Challenge Search

Search for similar CTF challenge writeups using Tavily API.

## Prerequisites

```bash
pip install requests tavily
```

Set your Tavily API key (from https://tavily.com) before running:

```bash
export TAVILY_API_KEY='tvly-...'
```

## API Overview

This skill provides two interfaces:

| Interface | Purpose | Command |
|-----------|---------|---------|
| **Tavily Search** | Search for writeups and articles | `./search.sh search <keyword>` |
| **Tavily Extract** | Extract content from URLs | `./search.sh extract <url1> [url2] ...` |

## Search Workflow

### Step 1: Search with Keywords

Choose keywords based on available information:

#### Scenario 1: Known Competition + Challenge Name
```bash
# Format: [Competition Name] [Challenge Name] — max 3 words
./search.sh search "DASCTF URL Storage"
./search.sh search "HGAME baby web"
./search.sh search "BUUCTF pwn1"
```

#### Scenario 2: Challenge Name Only (no competition info)
```bash
# Use challenge name directly — max 3 words
./search.sh search "URL Storage"
./search.sh search "baby overflow"
./search.sh search "crypto-rsa"
```

#### Scenario 3: Unique Identifiers (code snippets, strings)
```bash
# Use unique, non-trivial strings from the challenge — NO word limit
./search.sh search "def encrypt_flag(key): return base64"
./search.sh search "CUSTOM_MAGIC_BYTES"
./search.sh search "ERROR: invalid padding in AES block"
```

### ⚠️ Critical: 3-Word Limit for Non-Code Queries

**All keyword searches that are NOT code snippets or unique identifier strings MUST NOT exceed 3 words.** This constraint ensures precise, focused queries that return relevant CTF writeup results instead of broad, diluted searches.

| Search Type | Word Limit | Examples |
|-------------|-----------|----------|
| Competition + Challenge name | ≤ 3 words | `"DASCTF URL Storage"`, `"HGAME baby web"` |
| Challenge name only | ≤ 3 words | `"URL Storage"`, `"baby overflow"` |
| Code snippets / strings | **No limit** | `"def encrypt_flag(key): return base64"` |
| Error messages / identifiers | **No limit** | `"CUSTOM_MAGIC_BYTES"`, `"ERROR: invalid padding in AES block"` |

**For competition + challenge name searches**, drop filler words (year numbers, "CTF", "competition", "writeup", "solution") and keep only the 3 most distinctive words:

- ❌ `"HGAME 2024 baby web challenge"` (5 words)
- ✅ `"HGAME baby web"` (3 words)
- ❌ `"DASCTF 2023 URL Storage writeup"` (5 words)
- ✅ `"DASCTF URL Storage"` (3 words)
- ❌ `"PlaidCTF 2025 zero day exploit solution"` (6 words)
- ✅ `"PlaidCTF zero day"` (3 words)

**For code/string searches**, use the entire unique snippet — these are exempt from the word limit:

- ✅ `"def xor_encrypt(data, key):"` (code — exempt)
- ✅ `"ERROR: invalid padding in AES block"` (error string — exempt)
- ✅ `"CUSTOM_MAGIC_BYTES"` (identifier — exempt)

### Keyword Rules

| ✅ Good Keywords | ❌ Bad Keywords |
|------------------|-----------------|
| Competition + Challenge name (≤3 words) | Single vulnerability type (SSRF, XSS) |
| Challenge name (≤3 words) | Generic terms (web, pwn, crypto) |
| Unique code snippets (no word limit) | Full sentences |
| Specific error messages (no word limit) | Articles (a, the, in) |
| Library/framework names | Generic strings (flag{}, etc.) |
| Custom function names | Tool names alone |

**Why avoid these?**
- "SSRF" → returns generic vulnerability explanations, not CTF writeups
- "flag{" → returns millions of unrelated results
- "URL Storage DASCTF" → returns specific CTF challenges

**Why the 3-word limit?**
- Forces precision: only the most distinctive keywords survive
- Filters noise: filler words like "challenge", "writeup", "solution" dilute results
- Improves API efficiency: shorter, focused queries consume fewer credits

**Key principle:** Use keywords that uniquely identify THIS challenge, not the general technique or common patterns. Keep non-code queries to 3 words or fewer.

### Step 2: Review Search Results

The search returns:
- **Answer**: AI-generated summary if available
- **Results**: List of URLs with titles and content previews
- **Credits**: API usage information

### Step 3: Extract Content (Optional)

If a search result looks promising, extract its full content:

```bash
# Single URL
./search.sh extract "https://example.com/writeup"

# Multiple URLs
./search.sh extract "https://url1.com" "https://url2.com"
```

### Step 4: Analyze and Pivot

Based on extracted content:
- Identify common techniques used in similar challenges
- Determine if the approach is applicable
- Pivot to category-specific skill if needed

## When to Pivot

- If the challenge is already well-categorized, use the specific `ctf-*` skill
- If you need OSINT techniques, use `ctf-osint`
- If you need to generate a writeup after solving, use `ctf-writeup`

## Quick Start

```bash
# Scenario 1: Competition + Challenge name (≤3 words)
./search.sh search "DASCTF URL Storage"

# Scenario 2: Challenge name only (≤3 words)
./search.sh search "URL Storage"

# Scenario 3: Unique identifier from challenge (no word limit)
./search.sh search "def xor_encrypt(data, key):"
./search.sh search "ERROR: invalid padding"

# Extract content from promising results
./search.sh extract "https://ctftime.org/writeup/12345"
```

## Tips

1. **Be specific**: Use competition name + challenge name when available
2. **Use unique strings**: Code snippets, error messages, unique identifiers
3. **Avoid generic terms**: Don't search "SSRF CTF writeup" - too broad
4. **Review first**: Check search results before extracting
5. **Extract selectively**: Only extract URLs that look relevant
6. **Respect the 3-word limit**: For non-code queries, strip filler words and keep only the 3 most distinctive keywords

$ARGUMENTS
