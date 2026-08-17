# Bookkeeping

Single source for the internal records the coordinator and executors maintain. These are mechanics, not principles — keep them out of SKILL.md so they don't displace creative thinking.

## attack-chain.md

`{OUTPUT_DIR}/attack-chain.md`. Living document, updated every batch. Sections in order:

```markdown
## Services
- <port> <service> <version>

## Surface
- <endpoint or interface> — <observation>

## Theory (this batch)
1. <hypothesis A> — <reasoning>
2. <hypothesis B> — <reasoning>
3. [wildcard] <hypothesis C> — <reasoning>
Chosen: <which one and why>

## Tested (cumulative, terse)
- <experiment id> <technique> → <result one-liner>

## Next
- <single concrete next step>
```

Cap 50 lines. Prune resolved tested items to one-liners. Three hypotheses every batch — record the two you didn't pick; they form the backlog.

## experiments.md

`{OUTPUT_DIR}/experiments.md`. Append-only ledger. Never rewrite, never prune.

```markdown
| ID | Batch | Goal | Technique | Target | Hypothesis | Result | Goal_attempts | Notes |
|----|-------|------|-----------|--------|------------|--------|---------------|-------|
```

- **ID** — `E-NNN`, monotonically incrementing.
- **Batch** — sequential batch number (P2/P3 pair = one batch).
- **Goal** — the conceptual goal this experiment serves. *Not* the technique. Examples of goals: `auth as winrm_svc`, `read root.txt`, `read source of /admin endpoint`, `escape /uploads sandbox`.
- **Technique** — the specific technique tried. Examples: `Shadow Cred via certipy v4`, `Shadow Cred via pywhisker`, `MIT kinit with self-signed cert`. Three different techniques can share one goal.
- **Target** — the endpoint, host, share, or service.
- **Hypothesis** — one-line.
- **Result** — `success` / `partial` / `fail` / `pending`.
- **Goal_attempts** — count of fail rows for this *goal* so far (running total). Increments at row write.
- **Notes** — short observation, link to evidence file.

The `Goal_attempts` column is the conceptual-goal counter that drives Rule 6 (P4b reset). It catches the case where an agent slices one conceptual approach into many "different techniques" and never trips the stuck rule.

### Conceptual-goal counting — example

| ID | Goal | Technique | Result | Goal_attempts |
|----|------|-----------|--------|---------------|
| E-014 | auth as winrm_svc | Shadow Cred + certipy v4 PKINIT | fail | 1 |
| E-015 | auth as winrm_svc | Shadow Cred + pywhisker PKINIT | fail | 2 |
| E-016 | auth as winrm_svc | Shadow Cred + custom-SID-extension cert | fail | 3 → P4b |

Three different techniques, one conceptual goal, three strikes. The narrow per-technique-string counter would record three "1-strike" entries and never reset. The Goal column makes the conceptual repetition visible.

### Dedup rule

Skip a row only if (Goal, Technique, Target, parameters-meaningful-to-the-test) all match a prior row. Different parameters = new row. Different technique = new row even if same goal — that's how you accumulate goal_attempts toward Rule 6.

## tools/

`{OUTPUT_DIR}/tools/{NNN}_{tool}.md`. Executors log significant tool runs (scans, exploit attempts, HTTP requests). Skip trivial commands (`cd`, `ls`, `cat`).

```markdown
# Tool NNN — <tool>

## Cmd
<exact invocation>

## Out
<stdout/stderr, truncated to first 500 lines if long>

## Linked
- experiment: E-NNN
- finding: F-NNN (if applicable)
```

## EXPERIMENT_ID injection

Coordinator passes `EXPERIMENT_ID: E-NNN` in every executor prompt. Executor:
1. Updates that row's Result + Notes on completion.
2. Increments Goal_attempts on fail rows.
3. Tags `tools/{NNN}_*.md` files with `linked: experiment E-NNN`.

## Token budget

Bookkeeping (chain + experiments + tools logs) ≤ 10% of mission tokens. If logs grow faster than findings, batch them or compress old rows.
