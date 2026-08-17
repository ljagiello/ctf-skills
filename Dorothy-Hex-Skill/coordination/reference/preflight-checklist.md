# Pre-flight Checklist

Run before spawning any executor batch. Write the checklist to `attack-chain.md`. Any unchecked item → fix before spawning. **Never spawn an executor "to learn" — spawn only to test a clear hypothesis.**

## Phase 1 (recon) gate

- [ ] Full TCP port scan complete (not just top-1k). UDP top-100 if relevant.
- [ ] Every accessible source code path read (web app source, scripts, configs, share contents).
- [ ] Every readable share spidered with **both** anonymous (`-u '' -p ''`) and guest (`-u guest -p ''`) where applicable. Different share lists can return.
- [ ] Every binary downloaded from the target decompiled or strings-dumped.
- [ ] Every form/admin panel surveyed — each input field is a potential injection point.
- [ ] Platform/lab metadata read (whatever the host platform exposes — starter creds, machine info, tags).
- [ ] DNS / vhost enumeration done if HTTP services present.
- [ ] All discovered hostnames added to `/etc/hosts`.

## Surface-expansion gate (mandatory when an apex domain is in scope)

- [ ] CT-log / passive-DNS sweep of EVERY in-scope apex (`crt.sh`, `certspotter`, `subfinder`) → `recon/inventory/subdomains.json`.
- [ ] CDN/WAF-fronted hosts get an explicit origin-discovery pass (direct cloud endpoints, archive.org CDX, historical A records).
- [ ] All discovered hosts added to the inventory AND to `/etc/hosts`.
- [ ] Run even in grey-box where hostnames were provided: provided != complete; scope = discovered surface.

## Web/API attack-class surface gate (mandatory for any HTTP/API target)

These classes emit NO fingerprint until actively probed — they will never appear as a symptom-driven hypothesis. Probe each explicitly, on the API AND each discovered web origin:

- [ ] CORS (reflected origin / `null` origin / credentialed).
- [ ] Security headers (HSTS / CSP / X-Frame-Options / X-Content-Type-Options) on the API AND every origin.
- [ ] Redirect scheme-downgrade (https → http `Location`).
- [ ] Unauth webhook / ingress probe.
- [ ] Unauth existence oracles.
- [ ] Verbose-error probe.
- [ ] Public docs / `swagger` / `openapi.json` / `redoc`.
- [ ] TLS posture via `sslscan`.

Reference `skills/coordination/reference/coverage-matrix.md` as the authoritative class list.

## Phase 2 (think) gate

- [ ] Three hypotheses written to `attack-chain.md` for the next batch.
- [ ] At least one tagged `[wildcard]` — an angle no mounted skill explicitly prescribes.
- [ ] Chosen hypothesis: 1-2, with the rejected ones recorded for backlog.
- [ ] Each hypothesis names: goal (what it would unlock), technique (what to run), target (where to run), expected signal (how you'll know it worked).

## Phase 3 (spawn) gate

- [ ] EXPERIMENT_ID assigned per executor.
- [ ] Goal column populated in experiments.md before spawn (result=pending).
- [ ] Skill files mounted: 1-2 relevant — never the full set.
- [ ] PATT_URL chosen (specific, not the full map).
- [ ] CHAIN_CONTEXT extract is current.

## Stuck gate (fires before declaring P4b)

Before writing "stuck" to attack-chain.md, confirm thoroughness:

- [ ] Every share spidered (null + guest + auth where creds exist).
- [ ] Every readable file inspected for credentials, tokens, keys, paths.
- [ ] Every alternate username casing tried (lowercase, capitalized, ALL-CAPS).
- [ ] Every readable LDAP attribute scanned (description, info, scriptPath, comment).
- [ ] Every config / env / SYSVOL / installer-log searched for cleartext secrets.
- [ ] PSReadLine history (Windows), .bash_history, .python_history (Linux) read where reachable.
- [ ] Every accessible service tried with both null and authenticated probes.

If any unchecked: that's where to spend the next experiment, not P4b.

## Easy-target gate

On Easy-rated targets, "user flag captured but root failed" is a temporary `status=FAILED_partial`, never a final state. Restart from recon with fresh hypotheses if no progress in 5 batches after user-foothold.
