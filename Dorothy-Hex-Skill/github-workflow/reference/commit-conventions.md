# Commit Conventions

## Format

```
type(scope): description

[optional body]

[optional footer]
```

## Types

| Type | When to use | Example |
|------|-------------|---------|
| `feat` | New feature | `feat(auth): add JWT refresh token endpoint` |
| `fix` | Bug fix | `fix(sqli): correct union payload for MySQL 8` |
| `docs` | Documentation only | `docs(readme): update installation steps` |
| `refactor` | Code restructuring, no behavior change | `refactor(agents): extract common HTTP helper` |
| `test` | Adding/updating tests | `test(xss): add DOM-based XSS test cases` |
| `chore` | Maintenance, dependencies, CI | `chore(deps): bump playwright to 1.40` |
| `perf` | Performance improvement | `perf(recon): parallelize port scanning` |
| `style` | Formatting, whitespace | `style(skills): fix YAML indentation` |

## Scope

Optional, describes the area affected:
- Skill name: `(pentest)`, `(hackerone)`, `(auth)`
- Component: `(agents)`, `(skills)`, `(commands)`
- Feature: `(jwt)`, `(sqli)`, `(recon)`

## Rules

- **Subject line**: imperative mood ("add" not "added"), lowercase, no period, < 72 chars
- **Body**: wrap at 72 chars, explain **why** not **what**
- **Footer**: `Fixes #123`, `Closes #456`, `BREAKING CHANGE: description`
- **Co-authorship**: add `Co-Authored-By:` when AI-assisted

## Multi-line Commit (HEREDOC)

```bash
git commit -m "$(cat <<'EOF'
feat(pentest): add PHP filter chain RCE technique

Adds detection and exploitation guidance for PHP filter chain attacks
via controlled include paths. Covers Apache header size constraints
and short-tag payload optimization.

Fixes #42

Co-Authored-By: Claude <noreply@anthropic.com>
EOF
)"
```

## What NOT to Commit

- `.env` files, API keys, passwords, tokens
- Large binaries, build artifacts
- IDE config (`.idea/`, `.vscode/` unless shared)
- OS files (`.DS_Store`, `Thumbs.db`)
- Node modules, virtualenvs, compiled output
