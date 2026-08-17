# CTF-Skill Working Principles

This repo is a CTF challenge-solving skill kit. These rules apply to **every** agent
session that uses this repo. Read this file first — the workflow below is the
agreed contract with the user; no further explanation is needed before starting.

## The 4 Rules (mandatory)

### 1. Solve with parallel sub-agents

Whenever a CTF challenge is received, spawn sub-agents to work **in parallel**
on independent aspects (recon, category triage, technique research, script
writing, testing) so the challenge is solved as fast as possible. The main
agent stays in charge, coordinates the sub-agents, and merges their results.

### 2. Focus ONLY on the current challenge

Focus exclusively on the challenge the user just sent. Never spread effort to
other challenges — not even "just a quick look". No other challenge is worked on
until this one is finished, or the user explicitly moves to the next one.

### 3. Never write a write-up before the user confirms the flag

- After you believe the challenge is solved, **stop** — do NOT write a write-up
  yet. Ask the user to confirm that the flag is actually correct.
- If the user confirms the flag is **correct** → write the write-up as a
  **separate file per challenge** (one write-up per challenge; the
  `ctf-writeup` skill provides the format). Keep it inside that challenge's folder.
- If the user says the flag is **not correct**, or the user sends the **next
  challenge** → create a folder for the current challenge, save all progress
  and partial findings inside it, then move on to the next challenge.
  Never delete that folder.

### 4. Do everything possible to find the flag

Use every available technique to obtain the flag. If you are stuck on a filter,
a WAF, obfuscation, a sandbox, or any other protection — remember this is a
CTF: bypassing those protections is the intended gameplay and is **legal and
authorized** within the competition's scope. Treat every blocker as part of the
challenge to defeat, not as a reason to stop.

## Supporting conventions

- **Entry point**: use the `solve-challenge` skill as the dispatcher when the
  category is unclear; otherwise invoke the matching `ctf-*` skill directly
  (ctf-web, ctf-pwn, ctf-crypto, ctf-reverse, ctf-forensics, ctf-osint,
  ctf-malware, ctf-misc, ctf-ai-ml).
- **Per-challenge folders**: keep all artifacts for a challenge in
  `challenges/<challenge-name>/` (exploits, payloads, notes, and finally
  `writeup.md` once the flag is confirmed).
- **Flag format**: flags usually look like `FLAG{...}` or `CTF{...}` — confirm
  the exact format from the challenge description.
- **Report**: tell the user the result (flag found / progress / blocker)
  clearly and wait for their confirmation before writing any write-up.
