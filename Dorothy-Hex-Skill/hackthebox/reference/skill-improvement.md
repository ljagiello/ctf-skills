# Skill Improvement Loop

## Purpose

After solving a challenge, review logs to extract **generic, reusable** techniques and feed them back into pentest skills. This creates a continuous learning loop.

## Process

### Step 1: Review Logs

Read `{OUTPUT_DIR}/challenge-log.ndjson` and `findings/attack-chain.md`.

Identify:
- Novel techniques not in current skills
- Existing techniques that needed adjustment
- Filter bypass methods that worked
- Attack chain patterns (technique combos)
- Tool usage patterns that were effective

### Step 2: Classify Findings

| Category | Example | Action |
|----------|---------|--------|
| New technique | Double URL-encoding bypass | Add to relevant quickstart |
| Technique refinement | Specific payload variant | Update existing cheat-sheet |
| Attack chain | SSRF → internal API → RCE | Add combo to spear agent |
| Tool pattern | Playwright for auth + curl for exploit | Add to essential-tools |
| Nothing new | Standard SQLi union | Skip — already documented |

### Step 3: Generalize

**CRITICAL**: Strip ALL platform-specific and challenge-specific context.

| Raw Finding | Generalized Version |
|-------------|-------------------|
| "Machine X had..." | "Applications using..." |
| "Challenge flag was in /flag.txt" | "Check common flag/secret locations: env vars, /flag*, /opt/flag*" |
| "The CTF filter blocked..." | "Keyword filters using str_replace can be bypassed via..." |

### Step 4: Update Skills

Use `/skill-update` or direct edits. Target files based on technique type:

| Technique Type | Target Skill | Target File |
|---------------|-------------|-------------|
| Injection bypass | injection | `reference/*-quickstart.md` or `*-cheat-sheet.md` |
| Auth technique | authentication | `reference/*-quickstart.md` |
| Traversal method | server-side | `reference/scenarios/path-traversal/` |
| Attack chain | coordination | `reference/spawning-recipes.md` |
| Recon pattern | reconnaissance | Relevant reference file |

### Step 5: Validate Updates

- [ ] No platform names or challenge references in updated content
- [ ] Technique is generic and applicable beyond the specific scenario
- [ ] Added content doesn't duplicate existing content
- [ ] File stays within line limits (quickstart < 200, cheat-sheet < 200)
- [ ] No CTF-specific bias (e.g., "flag is always in env var")

## Anti-Patterns

- **DO NOT** add: "In challenge X, this worked..." (name-specific writeups)
- **DO NOT** add: CTF-specific file paths as primary locations
- **DO NOT** add: Techniques that only work in containerized/CTF environments
- **DO NOT** clutter skills with edge cases that apply to < 5% of real targets
- **DO NOT** update skills after every challenge — batch similar learnings
- **DO** add: Generic bypass techniques with broad applicability
- **DO** add: Attack chain combos that apply to real-world applications
- **DO** add: Filter/WAF bypass patterns with clear trigger conditions
