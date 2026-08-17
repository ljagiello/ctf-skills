# PATT Integration Standard
> Governs all `payloads/` files and future PATT curation sessions.

## File Format

Every `payloads/` file MUST use this frontmatter:

```markdown
---
source: PayloadsAllTheThings
patt-path: <path in PATT repo, e.g. "SQL Injection/README.md">
patt-url: https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/<encoded-path>
last-curated: YYYY-MM-DD
priority: critical|high|medium|low
---

# <Attack Type> — <Variant> Payloads

## Quick Hits
<!-- Top 10 most reliable payloads — ~20 lines max -->

## Extended List
<!-- Broader payload set — ~40 lines max -->

## Bypass Variants
<!-- WAF/filter evasion — ~30 lines max -->

## Notes
<!-- When to use which, target-specific tips — 5-10 lines -->

---
*Full list: `patt-fetcher` agent → "<PATT category name>"*
```

## P1/P2 Stub Format

```markdown
---
source: PayloadsAllTheThings
patt-path: <TBD — fill in next session>
patt-url: <TBD>
last-curated: TBD
priority: high|medium|low
---

<!-- TODO: run patt-fetcher agent → "<category name>" and curate into this file -->
```

## Hard Rules

- Every file **< 200 lines** — split into basic.md / bypass.md / etc. if needed
- `priority: critical` = curated this session; `high/medium/low` = future sessions
- `last-curated` date makes staleness visible at a glance
- Curated files always end with `*Full list: patt-fetcher*` pointer
- Inline additions to existing files tagged `<!-- PATT enrichment 2026-03-13 -->`
- If a file hits 200 lines: split overflow into a new file immediately

## Adding a New Category (Future Sessions)

1. Find the PATT category in the URL map in `skills/patt-fetcher/SKILL.md`
2. Create `attacks/<group>/<category>/payloads/<variant>.md` following the format above
3. Run `patt-fetcher` agent → curate top 10 quick hits + bypass variants
4. Validate: `wc -l <file>.md` must show < 200
5. Set `priority: critical` and `last-curated: YYYY-MM-DD`
6. Commit: `feat: add <category> PATT payloads`
