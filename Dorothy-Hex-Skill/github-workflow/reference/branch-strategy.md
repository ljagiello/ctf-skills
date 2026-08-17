# Branch Strategy

## Naming Convention

```
<type>/<short-description>
```

| Type | Purpose | Example |
|------|---------|---------|
| `feature/` | New functionality | `feature/add-ssti-agent` |
| `bugfix/` | Bug fixes | `bugfix/fix-port-detection` |
| `docs/` | Documentation | `docs/update-readme` |
| `refactor/` | Code restructuring | `refactor/split-executor-agents` |
| `test/` | Test additions | `test/add-jwt-tests` |
| `chore/` | Maintenance | `chore/update-dependencies` |
| `hotfix/` | Urgent production fix | `hotfix/fix-auth-bypass` |

## Rules

- Use lowercase, hyphens for spaces: `feature/add-jwt-testing` (not `Feature/Add_JWT`)
- Keep names short but descriptive: `bugfix/sqli-quote-escaping` (not `bugfix/fix`)
- Branch from `main` unless explicitly told otherwise
- One branch per feature/fix — don't combine unrelated changes

## Workflow

```bash
# 1. Start from up-to-date main
git checkout main
git pull origin main

# 2. Create branch
git checkout -b feature/my-feature

# 3. Work, commit, push
git add <files>
git commit -m "feat(scope): description"
git push -u origin feature/my-feature

# 4. Create PR
gh pr create --title "feat(scope): description" --body "..."

# 5. After merge, clean up
git checkout main
git pull origin main
git branch -d feature/my-feature
```

## Branch Lifecycle

```
main ─────────────────────────────────── main (updated)
  \                                      /
   └── feature/add-jwt-testing ────────┘
        commit 1 → commit 2 → PR → merge
```

## Protected Branch Rules

- `main` / `master`: never force-push, never commit directly
- All changes via PR with at least one review (when configured)
- CI must pass before merge (when configured)

## Stale Branches

```bash
# List merged branches (safe to delete)
git branch --merged main

# Delete local merged branches
git branch --merged main | grep -v main | xargs git branch -d

# Delete remote merged branch
git push origin --delete feature/old-branch
```
