# Git Conventions

IMPORTANT: Always follow these git workflows.

## Branches
- Create from main: `feature/skill-name`, `bugfix/description`, `docs/update`
- NEVER commit directly to main

## Commits
- Format: `type: description`
- Types: feat, fix, docs, refactor, test, chore
- Example: `feat: add JWT testing agent`

## Pull Requests
- MUST link to issue: "Fixes #123" or "Closes #123"
- Create issue BEFORE starting work
- Use PR template in `.github/pull_request_template.md`
