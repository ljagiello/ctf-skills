---
name: protection-and-modes
description: Assessor playbook for sourcing evidence for PCI SSS v2.0 Security Objective 4 (sensitive modes of operation) and Security Objective 5 (protection mechanisms against anomalous behaviour and disclosure).
---

# Sensitive Modes of Operation & Protection Mechanisms (SO4, SO5)

SO4 requires that any sensitive mode of operation (admin/privileged/maintenance/key-management state) be gated by strong authentication, locked out after failed attempts, silent on failure, time-bounded, and audited. SO5 requires the software to lean on evaluated platform mechanisms, pre-emptively mitigate anomalous behaviour from inputs/errors/remote elements, detect-and-record anomalies, securely implement authorized access, and mitigate inadvertent disclosure. This playbook tells you where in source and docs the evidence lives, and which sub-skills to reuse to find it.

## Where to find evidence

- **Sensitive-mode gating** — search for the privileged-mode entry point: globs `**/admin/**`, `**/{maintenance,setup,recovery,keymgmt}*`, route decorators `@requires_admin`, `@role(...)`, `if user.is_admin`, feature flags toggling "maintenance"/"debug"/"sensitive" mode. The doc set must *enumerate* every sensitive mode (vendor documentation, per 4-1.a) — find that list first; code with no doc counterpart (or vice-versa) is a gap.
- **Auth + MFA enforcement (4-1.1)** — auth middleware, `verify_mfa`, `totp`, `webauthn`, OIDC/SAML enforcement on the gate above; confirm it fires *before* the mode is entered, not after.
- **Lockout counters (4-1.2/4-1.3)** — config keys `max_failed_attempts`, `lockout_threshold`, `lockout_duration`, `attempt_window`; counter writes (`failed_count++`, Redis/DB `INCR`), and the branch that enforces the lockout window. Confirm the *period* and *lockout duration* are both defined.
- **Non-disclosure on failure (4-1.4)** — failure responses on the auth path: identical message/status/timing for "bad user" vs "bad password" vs "locked"; grep error strings near the auth handler for `user not found`, `account locked`, stack traces.
- **Timeouts (4-1.5/4-1.6)** — `session_timeout`, `idle_timeout`, `inactivity`, `max_session_duration`, `absolute_timeout`; the code that *exits* the mode and re-authenticates. Distinguish inactivity (4-1.5) from absolute max-duration (4-1.6) — both required.
- **Access records (4-1.7.x)** — audit/log-record writers: `audit_log`, `logger.audit`, `record_access`. Each event must uniquely identify the attempt (4-1.7.1), the successful entity + traceability (4-1.7.2), and the net change (4-1.7.3); records protected by strong crypto (4-1.7.4), behind strong auth (4-1.7.5), retained a defined period (4-1.7.6), and protected per 6-2 in transit (4-1.7.7).
- **Platform mechanisms (5-1)** — docs naming the evaluated OS/runtime/HSM/TEE/keystore controls relied upon; code calls into them (`Keychain`, `KeyStore`, `DPAPI`, `SELinux`, sandbox/seccomp). Evidence is the *evaluation reference*, not just the import.
- **Pre-emptive mitigation (5-2.x)** — input-validation and error-handling middleware (5-2.1 input, 5-2.2 errors), and remote-fetch/update code paths (5-2.3): `requests.get`, `fetch(`, `urlopen`, update/CDN/third-party-element loaders with integrity/SRI/cert pinning/timeout/size limits.
- **Detection + records of anomalies (5-3.x)** — anomaly detectors, alerting (`alert(`, `raise SecurityEvent`), the immediate-indication path (5-3.2) and its tamper-protection (5-3.2.1), plus the same record fields/crypto/auth/retention/transit ladder as 4-1.7 (5-3.3.1–5-3.3.5).
- **Authorized access (5-4.x)** — authorization decision points enforcing access to sensitive data (5-4.1), resources (5-4.2), functionality (5-4.3) and modes (5-4.3.1).
- **Inadvertent disclosure (5-5.x)** — serializers, log/exception emitters, debug/verbose flags, cache/temp/backup writes that could leak sensitive data (5-5.1), resources (5-5.2), functionality (5-5.3), or modes (5-5.3.1).

## Reused sub-skills

- [skills/authentication/SKILL.md](../../../authentication/SKILL.md) — locating strong-auth/MFA enforcement, lockout counters, and session/timeout logic for 4-1.1/4-1.2/4-1.3/4-1.5/4-1.6 and the strong-auth gates on records (4-1.7.5, 5-3.3.3).
- [skills/source-code-scanning/SKILL.md](../../../source-code-scanning/SKILL.md) — input-validation, error-handling and remote-fetch code-path discovery (5-2.x), audit-writer and disclosure-sink scanning (4-1.7.x, 5-3.3.x, 5-5.x), and access-control decision points (5-4.x).
- [skills/web-app-logic/SKILL.md](../../../web-app-logic/SKILL.md) — authorization-flaw and timeout-logic analysis: bypassable mode gates, missing inactivity/duration exits, broken lockout windows (4-1.2/4-1.3/4-1.5/4-1.6, 5-4.x).
- [skills/cryptography/SKILL.md](../../../cryptography/SKILL.md) — verifying the "strong cryptography" record-protection claims for 4-1.7.4 and 5-3.3.2 (algorithm, mode, key handling) rather than trusting a library import.

## Assessing each requirement

Map every verdict to `Evidence{source_file, source_lineno, quoted_text}` per [../core/schema.md](../core/schema.md). Quote verbatim; never reword a snippet to fit. Static/documentation requirements can reach MET on a read; **dynamic / Perform / Test rows must run the negative test or be `REQUIRES_MANUAL_REVIEW`** — never MET from a read alone.

- **4-1 (doc enumeration)** — MET: docs list each sensitive mode. NOT_MET: a code-discovered mode absent from the list. Cite the doc section and the code path.
- **4-1.1 strong auth** — MET: gate calls MFA/strong-auth before entry. NOT_MET: password-only or post-entry check. Negative move: attempt to reach the mode without/with weak auth and observe.
- **4-1.2/4-1.3 lockout** — MET: defined threshold *and* window *and* lockout duration, enforced. NOT_MET: counter that never blocks, or threshold/duration undefined. Negative move: drive N+1 failures, confirm lockout actually engages for the configured period.
- **4-1.4 non-disclosure** — MET: uniform failure response across causes. NOT_MET: distinct messages/status/timing or leaked stack trace. Negative move: enumerate failure causes, diff the responses.
- **4-1.5/4-1.6 timeouts** — MET: inactivity *and* absolute-duration exits that re-require auth. NOT_MET: only one (or neither). Negative move: idle past the window / exceed max duration, confirm the mode actually exits.
- **4-1.7 + 4-1.7.1–.7** — MET: a record written on every failed/successful access carrying unique-id (.1), entity traceability (.2), net change (.3), crypto-protected (.4), strong-auth-gated (.5), retained a defined period (.6), transit-protected per 6-2 (.7). NOT_MET: missing event, missing field, plaintext store, undefined retention. Treat .4 crypto strength as a cryptography-skill check, not an import sighting.
- **5-1 platform mechanisms** — MET: docs cite the evaluated mechanism *and* code uses it. NOT_MET: claimed reliance with no evaluation reference. (documentation/research row → manual review if unverifiable.)
- **5-2 / 5-2.1–.3** — MET: input validation (.1), error handling (.2), and remote-element handling (.3 integrity/timeout/size) present on the relevant paths. NOT_MET: unvalidated sink, swallowed/over-disclosing error, unauthenticated/un-pinned remote fetch. Negative move (dynamic rows): send malformed input / force an error / point a fetch at a hostile element and observe containment.
- **5-3 / 5-3.1–.3.5** — MET: detection (5-3), impact-mitigation (5-3.1), immediate tamper-proof indication (5-3.2/5-3.2.1), and the full record ladder (5-3.3.1–.5). NOT_MET: silent on anomalies, spoofable indicator, or a record gap mirroring 4-1.7.
- **5-4 / 5-4.1–.3.1** — MET: an authorization decision guards sensitive data (.1), resources (.2), functionality (.3), modes (.3.1). NOT_MET: missing/bypassable check. Negative move: attempt access as an unauthorized principal.
- **5-5 / 5-5.1–.3.1** — MET: disclosure sinks scrub sensitive data (.1), resources (.2), functionality (.3), modes (.3.1). NOT_MET: sensitive value in logs/errors/caches/backups. Negative move: trigger the sink and inspect the output.

## Remediation themes

- Lockout that counts but never enforces, or an undefined window/duration → define threshold + period + lockout duration and enforce server-side.
- One timeout only → add the missing inactivity *or* absolute-duration exit; both are required.
- Distinguishing failure messages or leaked traces → collapse to one generic failure response.
- Audit records present but plaintext, unauthenticated, or with no defined retention → add strong crypto (4-1.7.4/5-3.3.2), strong-auth gating, and a retention policy.
- Remote/third-party elements fetched without integrity, pinning, timeout, or size cap → add them (5-2.3).
- Sensitive values in logs/errors/caches → centralise scrubbing at the disclosure sink (5-5.x).

## Anti-Patterns

- Asserting a **dynamic** requirement (lockout enforcement, timeout exit, non-disclosure, anomaly mitigation) **MET from a static read of docs or code** — these need the negative test run, or the verdict is `REQUIRES_MANUAL_REVIEW`.
- Treating an **MFA/crypto library import** as proof the control is wired into the sensitive-mode gate or actually protects the records — verify the call site and the algorithm/key handling.
- Counting a **lockout counter that increments but never blocks**, or a timeout *config key* with no enforcing branch, as the control.
- Collapsing the **4-1.7 / 5-3.3 record sub-requirements into one verdict** — each field (.1 unique-id, .2 traceability, .3 net change) and each protection (.4 crypto, .5 auth, .6 retention, .7 transit) is assessed separately.
- Inferring a **sensitive mode is documented** because code exists, or **exists** because docs mention it — confirm both halves and cite each.

## See also

- [../core/schema.md](../core/schema.md) — the Evidence / RequirementVerdict contract every verdict here must satisfy.
- [../catalog/INDEX.md](../catalog/INDEX.md) — the catalog file with the verbatim SO4/SO5 requirement IDs and texts.
