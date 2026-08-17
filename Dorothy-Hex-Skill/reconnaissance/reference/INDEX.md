# Reconnaissance Reference Index

Reference material for `skills/reconnaissance/`. Start with `reconnaissance-principles.md` for the decision tree, then jump to the relevant scenario.

## Principles

- [reconnaissance-principles.md](reconnaissance-principles.md) - decision tree, archetype-driven triage, output layout.

## Scenarios

| Scenario | Use when |
|----------|----------|
| [scenarios/subdomain-enumeration.md](scenarios/subdomain-enumeration.md) | Given a root domain, need to enumerate subdomains via passive + active sources. |
| [scenarios/port-scanning.md](scenarios/port-scanning.md) | Given an IP or host, need open-port and service inventory. |
| [scenarios/vhost-enumeration.md](scenarios/vhost-enumeration.md) | Suspected name-based virtual hosts behind a single IP. |
| [scenarios/api-endpoint-discovery.md](scenarios/api-endpoint-discovery.md) | Web app exposes a backend API; need to map routes, parameters, swagger. |
| [scenarios/obfuscated-js-deobfuscation.md](scenarios/obfuscated-js-deobfuscation.md) | Client-side bundle is JSFuck/packer/Function-wrapper obfuscated; need to recover hidden routes by intercepting the executor. |

## Focused Technique Files

- [anti-bot-bypass.md](anti-bot-bypass.md) - Cloudflare/Turnstile bypass during authorised testing.

## Related Skills

- `skills/osint/` - run alongside subdomain enumeration for repository and employee footprinting.
- `skills/techstack-identification/` - stack fingerprints to guide wordlist and endpoint selection.
- `skills/infrastructure/` - port scanning escalation into protocol-level testing.
