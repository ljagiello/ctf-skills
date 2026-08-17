# Pull Request Workflow

## Before Creating a PR

1. **Ensure branch is up to date**:
   ```bash
   git fetch origin main
   git rebase origin/main  # or merge
   ```
2. **Review your changes**:
   ```bash
   git diff origin/main...HEAD   # All changes vs main
   git log origin/main..HEAD     # All commits
   ```
3. **Verify no secrets staged**: check for `.env`, keys, tokens
4. **Run tests** if applicable

## Creating a PR

```bash
gh pr create \
  --title "feat(scope): short description" \
  --body "$(cat <<'EOF'
## Summary
- Brief description of changes and motivation

## Changes
- List of specific changes made

## Test plan
- [ ] Step-by-step verification instructions

Fixes #<issue-number>
EOF
)"
```

### Title Guidelines
- < 70 characters
- Use conventional commit format: `type(scope): description`
- Imperative mood: "add", "fix", "update" (not "added", "fixed")

### Body Guidelines
- **Summary**: 1-3 bullets explaining what and why
- **Test plan**: how to verify the changes work
- **Issue link**: `Fixes #N` or `Closes #N` (auto-closes issue on merge)

## Reviewing a PR

```bash
# View PR details
gh pr view <number>

# View diff
gh pr diff <number>

# Check CI status
gh pr checks <number>

# Leave review
gh pr review <number> --approve
gh pr review <number> --request-changes --body "feedback"
gh pr review <number> --comment --body "looks good, minor nit on L42"

# View comments
gh api repos/{owner}/{repo}/pulls/<number>/comments
```

## Merging

```bash
# Merge (creates merge commit)
gh pr merge <number> --merge

# Squash merge (single commit)
gh pr merge <number> --squash

# Rebase merge (linear history)
gh pr merge <number> --rebase

# Delete branch after merge
gh pr merge <number> --squash --delete-branch
```

### When to Use Each Strategy
- **Squash**: most PRs — clean single commit on main
- **Merge**: large PRs where individual commits matter
- **Rebase**: small PRs, maintain linear history

## Updating a PR

```bash
# Push new commits to the PR branch
git push

# If rebased, force push (with care)
git push --force-with-lease  # safer than --force
```

## Draft PRs

```bash
# Create as draft (not ready for review)
gh pr create --draft --title "wip: exploring approach"

# Mark ready when done
gh pr ready <number>
```

## Handling Conflicts

```bash
git fetch origin main
git rebase origin/main
# Resolve conflicts in editor
git add <resolved-files>
git rebase --continue
git push --force-with-lease
```
