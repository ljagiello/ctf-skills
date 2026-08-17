# Promptfoo / DeepTeam — Command & Config Reference

## Install

| Tool | Command |
|------|---------|
| Promptfoo (global) | `npm install -g promptfoo` |
| Promptfoo (no install) | `npx promptfoo@latest redteam run` |
| DeepTeam | `pip install -U deepteam` |

## Promptfoo Red-Team CLI

| Command | Purpose |
|---------|---------|
| `promptfoo redteam init` | Scaffold an interactive red-team config |
| `promptfoo redteam generate` | Generate adversarial test cases only |
| `promptfoo redteam run` | Generate + evaluate (combined) |
| `promptfoo redteam eval` | Evaluate existing generated tests |
| `promptfoo redteam report` | Open/export the results report |
| `promptfoo redteam plugins` | List available plugins |
| `promptfoo redteam strategies` | List available strategies |

Useful flags: `--no-progress-bar` (CI), `--output results.json`, `--filter-failing <file>`, `-c <config>`.

## Promptfoo Config Keys (`redteam:` block)

| Key | Purpose |
|-----|---------|
| `purpose` | Application description; grounds attack generation |
| `numTests` | Tests generated per plugin |
| `plugins` | Adversarial generators (e.g. `owasp:llm`, `owasp:agentic`, `pii:direct`, `prompt-extraction`, `harmful`) |
| `strategies` | Delivery techniques (`jailbreak`, `jailbreak:composite`, `crescendo`, `prompt-injection`) |
| `targets` | Endpoints/models under test |

## DeepTeam Python API

| Import | Purpose |
|--------|---------|
| `from deepteam import red_team` | Run a red-team assessment |
| `from deepteam.vulnerabilities import Bias, PIILeakage` | Vulnerability definitions (50+) |
| `from deepteam.attacks.single_turn import PromptInjection` | Single-turn attack methods |
| `red_team(model_callback=..., vulnerabilities=[...], attacks=[...])` | Execute the suite |

## DeepTeam CLI

| Command | Purpose |
|---------|---------|
| `deepteam run config.yaml` | Run red teaming from a YAML config |

## External References

- Promptfoo command line: https://www.promptfoo.dev/docs/usage/command-line/
- DeepTeam attacks: https://www.trydeepteam.com/docs/red-teaming-adversarial-attacks
- DeepTeam vulnerabilities: https://www.trydeepteam.com/docs/red-teaming-vulnerabilities
