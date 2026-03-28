# Contributing to ctf-skills

Thanks for helping expand the CTF skills collection. This guide covers how to set up your environment, add techniques, create new skill categories, and get your PR merged.

## Development Setup

### Prerequisites

- Python 3.12+
- Node.js (for markdownlint)
- [pre-commit](https://pre-commit.com/)

### Install pre-commit hooks

```bash
pip install pre-commit
pre-commit install
```

This installs hooks that run automatically on every commit:

- **trailing-whitespace** and **end-of-file-fixer** — basic formatting
- **check-yaml** — validates YAML files
- **check-added-large-files** — prevents accidental binary commits
- **ruff** — Python linter and formatter (for files in `scripts/`)
- **shellcheck** — static analysis for shell scripts
- **markdownlint-cli2** — Markdown linter (all `.md` files)

### Install test dependencies

```bash
pip install pytest
```

## Adding Techniques to an Existing Skill

This is the most common contribution. Each skill category (e.g., `ctf-web`, `ctf-crypto`) has a `SKILL.md` and one or more supporting technique files.

### 1. Choose the right file

Look at the existing technique files in the skill directory. For example, `ctf-web/` has files like `sql-injection.md`, `server-side.md`, `client-side.md`, etc. Add your technique to the file that best matches its topic. If no file fits, you can create a new one.

### 2. Follow the technique format

Technique files use this structure:

````markdown
## Technique Name (Optional CTF/Year Attribution)

Brief description of when and why to use this technique.

```language
# Working payload or code example
# Use realistic but safe placeholder targets (example.com, attacker.com)
```

**Key insight:** One or two sentences explaining the core idea.
````

Conventions:

- Start each technique with an h2 (`##`) heading
- Include working code examples in fenced code blocks with a language tag
- Use placeholder hostnames (`example.com`, `attacker.com`) — never real infrastructure
- Attribute the source CTF/competition in the heading when known
- Keep explanations concise — this is a quick reference, not a tutorial

### 3. Update the SKILL.md

After adding a technique, update the parent `SKILL.md`:

- Add the technique to the **Additional Resources** list if you modified an existing file
- If you created a new technique file, add a new entry to the list with a relative link

### 4. Update the README table

Update the skill's row in `README.md`: increment the **Files** count if you added a new file, and add the technique name to the **Description** column.

## Creating a New Skill Category

A new skill category is a directory at the repo root containing at minimum a `SKILL.md` file.

The `SKILL.md` must have YAML frontmatter with these required fields:

```yaml
---
name: ctf-newcategory
description: >-
  Provides [category] techniques for CTF challenges. Use when [trigger conditions].
license: MIT
compatibility: Requires filesystem-based agent (Claude Code or similar) with bash, Python 3, and internet access for tool installation.
allowed-tools: Bash Read Write Edit Glob Grep Task WebFetch WebSearch
metadata:
  user-invocable: "false"
---
```

Frontmatter rules enforced by tests:

| Field | Requirement |
|-------|-------------|
| `name` | Must exactly match the directory name |
| `description` | Must be longer than 20 characters; must start with a third-person verb (e.g., "Provides...", "Solves...") |
| `license` | Must be `MIT` |
| `compatibility` | Required, free-form string |
| `allowed-tools` | Space-separated list; valid values: `Bash`, `Read`, `Write`, `Edit`, `Glob`, `Grep`, `Task`, `WebFetch`, `WebSearch`, `Skill` |
| `metadata.user-invocable` | Must be `"true"` or `"false"` |
| `metadata.argument-hint` | Required if `user-invocable` is `"true"` |

## Running Tests Locally

```bash
# Run all tests
python -m pytest tests/ -v

# Run just the frontmatter validation
python -m pytest tests/test_skill_frontmatter.py -v

# Run the security auditor on a specific skill
python3 scripts/skill_security_auditor.py ctf-web --strict --json
```

### Running pre-commit checks manually

```bash
pre-commit run --all-files
```

## Code Quality Standards

- **Markdown** — Linted by markdownlint-cli2 (relaxed rules in `.markdownlint-cli2.yaml` for CTF content)
- **Python/Shell** — `scripts/` checked by ruff and shellcheck
- **Security** — Every PR triggers the Skill Security Audit workflow. Critical findings fail the build. Use `<!-- audit-ok -->` to suppress intentional attack documentation.
- **Links** — The Link Checker (lychee) validates all URLs on every PR and weekly

## Pull Request Process

### Before submitting

1. Run `pre-commit run --all-files` and fix any issues
2. Run `python -m pytest tests/ -v` and ensure all tests pass
3. If you added a new skill, verify `name` in frontmatter matches the directory name

### What reviewers look for

- Working code examples with placeholder hostnames (no real credentials or live infrastructure)
- Correct categorization in the right skill and file
- Frontmatter validity and security audit passing
- SKILL.md and README updated to reflect changes
- Source CTF/competition attributed in technique headings when known

### CI checks that must pass

| Workflow | What it does |
|----------|--------------|
| **Tests** | Runs `pytest` on `tests/` |
| **Markdown Lint** | Runs markdownlint-cli2 on all `.md` files |
| **Skill Security Audit** | Scans changed skills for dangerous patterns |
| **Link Checker** | Validates all URLs in `.md` files |
| **Lint Scripts** | Runs ruff and shellcheck on `scripts/` |

## Responsible Use

This repository documents offensive security techniques for **authorized CTF competitions, security research, and education only**. All contributors must adhere to the responsible use policy in [SECURITY.md](SECURITY.md). Never include real credentials, PII, or links to live malicious infrastructure.
