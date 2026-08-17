---
name: github-workflow
description: GitHub workflow automation — branching, committing, pushing, pull requests, issues, and code review. Use when asked to commit, push, create PRs/branches/issues, or manage git workflow.
---

# GitHub Workflow

Automate the full GitHub development lifecycle: branches, commits, pushes, PRs, issues, and code review.

## Quick Start

1. User requests a git action (commit, PR, branch, push, issue)
2. Check repo state: `git status`, `git branch`, `git log --oneline -5`
3. Execute the appropriate workflow below
4. Confirm result to user

## Workflows

### 1. Branching

```bash
# Create feature branch from main
git checkout main && git pull origin main
git checkout -b <type>/<name>
# Types: feature/, bugfix/, docs/, refactor/, test/, chore/
```

- Always branch from up-to-date `main`
- Use conventional naming: `feature/add-jwt-testing`, `bugfix/fix-port-detection`

### 2. Committing

```bash
# Stage specific files (never git add -A blindly)
git add <file1> <file2>
# Commit with conventional format
git commit -m "type(scope): description"
```

- **Types**: `feat`, `fix`, `docs`, `refactor`, `test`, `chore`
- Message focuses on **why**, not what
- Never commit `.env`, credentials, or secrets
- See [reference/commit-conventions.md](reference/commit-conventions.md)

### 3. Pushing

```bash
# First push (set upstream)
git push -u origin <branch-name>
# Subsequent pushes
git push
```

- Never force-push to `main`/`master` without explicit user approval
- If push is rejected, `git pull --rebase` first

### 4. Pull Requests

```bash
# Create PR linking to issue
gh pr create --title "Short title < 70 chars" --body "$(cat <<'EOF'
## Summary
- What changed and why

## Test plan
- [ ] How to verify

Fixes #<issue-number>
EOF
)"
```

- Title < 70 chars, details in body
- Always link to issue: `Fixes #N` or `Closes #N`
- See [reference/pr-workflow.md](reference/pr-workflow.md)

### 5. Issues

```bash
gh issue create --title "type: description" --body "$(cat <<'EOF'
## Problem
What needs to change

## Proposed solution
How to fix it

## Acceptance criteria
- [ ] Criteria 1
EOF
)"
```

### 6. Code Review

```bash
# Review a PR
gh pr view <number>
gh pr diff <number>
gh pr checks <number>
# Comment or approve
gh pr review <number> --approve
gh pr review <number> --comment --body "feedback"
```

## Reference

- [commit-conventions.md](reference/commit-conventions.md) — Commit message format and examples
- [pr-workflow.md](reference/pr-workflow.md) — PR creation, review, and merge workflow
- [branch-strategy.md](reference/branch-strategy.md) — Branching model and naming conventions

## Critical Rules

- **NEVER** force-push to main/master without explicit user approval
- **NEVER** commit secrets, `.env` files, or credentials
- **NEVER** use `git add -A` without reviewing what's staged
- **NEVER** skip pre-commit hooks (`--no-verify`) unless user explicitly asks
- **NEVER** amend published commits — create new commits instead
- **ALWAYS** use conventional commit format: `type(scope): description`
- **ALWAYS** link PRs to issues
- **ALWAYS** check `git status` before committing
- **ALWAYS** pull before pushing to avoid conflicts
- **ALWAYS** create branches from up-to-date main
