// Custom promptfoo `javascript` assertions, referenced as
// `file://lib/assertions.js:<name>`. Each receives (output, context) and
// returns a GradingResult. Skill calls come from the Claude Agent SDK
// provider's `metadata.skillCalls`, which is built from `Skill` tool calls.

import crypto from 'node:crypto';

function skillsUsed(context) {
  return (context.providerResponse?.metadata?.skillCalls ?? [])
    .filter((call) => !call.is_error)
    .map((call) => call.name);
}

function describe(skills) {
  return skills.length > 0 ? skills.join(' -> ') : '(none)';
}

function toolCalls(context) {
  return context.providerResponse?.metadata?.toolCalls ?? [];
}

// Bash/Write/Edit tool calls as flat, lower-cased text, for simple content
// checks. Order is preserved (toolCalls is chronological). Joins the input's
// own string fields (command, content, file_path, old_string/new_string, ...)
// directly rather than JSON.stringify-ing the input object: stringifying
// would backslash-escape any quote characters already inside real file/script
// content (`"admin"` becomes the three characters `\"admin\"` in the JSON
// text), which silently breaks every regex here that expects a literal quote
// next to a value.
function actionText(call) {
  if (!['Bash', 'Write', 'Edit'].includes(call.name)) {
    return '';
  }
  return Object.values(call.input ?? {})
    .filter((value) => typeof value === 'string')
    .join('\n')
    .toLowerCase();
}

// Fails when any skill listed in `vars.forbidden` was loaded. Needs
// `disableVarExpansion: true` so the list var is not fanned out into tests.
export function noForbiddenSkills(output, context) {
  const forbidden = context.vars.forbidden ?? [];
  const used = skillsUsed(context);
  const hits = forbidden.filter((name) => used.includes(name));
  return {
    pass: hits.length === 0,
    score: hits.length === 0 ? 1 : 0,
    reason:
      hits.length === 0
        ? `No forbidden skills loaded. Skills: ${describe(used)}`
        : `Loaded forbidden skill(s) ${hits.join(', ')}. Skills: ${describe(used)}`,
  };
}

// Passes when `vars.expected` was loaded without going through the
// solve-challenge dispatcher first. Used as a metric for "routed directly".
export function routedDirectly(output, context) {
  const used = skillsUsed(context);
  const direct = used[0] === context.vars.expected;
  return {
    pass: direct,
    score: direct ? 1 : 0,
    reason: `First skill: ${used[0] ?? '(none)'}; expected ${context.vars.expected}`,
  };
}

// Rules suite (ctf-pwn/SKILL.md:83 "If you do not yet understand what the
// binary does, switch to /ctf-reverse before trying to exploit it."): the
// cases for this rule give the agent no files to act on (it's asked for a
// plan, not to solve anything), so a correct agent sometimes explains that
// it would load ctf-reverse without actually pressing the Skill tool for a
// file-free hypothetical -- which `skill-used` alone can't tell apart from
// never considering ctf-reverse at all. These two credit a real Skill call
// the same as `skill-used`/`not-skill-used` would, but also accept clearly
// stated text reasoning, so the check doesn't merely measure whether the
// model happened to press a button for an action with nothing to act on.
export function recommendsCtfReverse(output, context) {
  if (skillsUsed(context).includes('ctf-reverse')) {
    return { pass: true, score: 1, reason: 'Loaded ctf-reverse via the Skill tool' };
  }
  const text = typeof output === 'string' ? output : JSON.stringify(output);
  const defers = /don'?t (yet )?understand|no known vulnerability|premature to (jump|go) (straight )?to (pwn|exploitation)/i.test(text);
  const recommends = /`?ctf-reverse`?/i.test(text) && /(load|switch to|use|invoke|first|before)/i.test(text);
  const pass = defers && recommends;
  return {
    pass,
    score: pass ? 1 : 0,
    reason: pass
      ? 'Did not call the Skill tool, but clearly recommended ctf-reverse first in its written plan'
      : 'Neither loaded nor clearly recommended ctf-reverse as the first step',
  };
}

export function doesNotRecommendCtfReverse(output, context) {
  if (skillsUsed(context).includes('ctf-reverse')) {
    return { pass: false, score: 0, reason: 'Loaded ctf-reverse via the Skill tool although the vulnerability was already fully understood' };
  }
  const text = typeof output === 'string' ? output : JSON.stringify(output);
  const recommendsNow =
    /(load|switch to|use|invoke)\s+`?ctf-reverse/i.test(text) &&
    !/no (other )?(reversing|reverse engineering)|doesn'?t need|not needed|isn'?t needed|no reverse/i.test(text);
  return {
    pass: !recommendsNow,
    score: recommendsNow ? 0 : 1,
    reason: recommendsNow
      ? 'Recommended loading ctf-reverse even though the vulnerability was already fully understood'
      : 'Correctly did not recommend ctf-reverse',
  };
}

// Rules suite (ctf-pwn workflow: "1. Find offset... 2. Check protections:
// checksec... 3. No PIE + No canary = direct ROP"): a protection check must
// run before the agent writes exploit code. Requires at least one
// protection-check call to exist; if an exploit script was also written,
// the check must come first.
const RECON_PATTERN = /\bchecksec\b|\breadelf\b|\bfile\s+(\.\/|\S*chall)/i;
const EXPLOIT_WRITE_PATTERN = /from\s+pwn\s+import|import\s+pwn|\bROP\(|\bp64\(|payload\s*=/i;

export function checksecBeforeExploit(output, context) {
  const calls = toolCalls(context);
  const reconIdx = calls.findIndex((c) => c.name === 'Bash' && RECON_PATTERN.test(actionText(c)));
  const exploitIdx = calls.findIndex((c) => ['Write', 'Edit', 'Bash'].includes(c.name) && EXPLOIT_WRITE_PATTERN.test(actionText(c)));

  if (reconIdx === -1) {
    return { pass: false, score: 0, reason: 'No checksec/file/readelf call before the response ended' };
  }
  if (exploitIdx !== -1 && exploitIdx < reconIdx) {
    return { pass: false, score: 0, reason: `Wrote exploit code (call #${exploitIdx}) before checking protections (call #${reconIdx})` };
  }
  return { pass: true, score: 1, reason: `Checked protections at call #${reconIdx}${exploitIdx !== -1 ? `, before exploit code at call #${exploitIdx}` : ''}` };
}

// Rules suite (ctf-reverse/SKILL.md:113-127 "Never pipe triage output through
// `head` on the first pass"): the agent must not cap its own triage output
// with `head` and then conclude "no flag here". Fails if any Bash call pipes
// one of the large-dump commands the rule is about (strings/objdump/xxd/...)
// through `head`. Deliberate `sed -n 'N,Mp'` paging is NOT caught (the rule
// itself sanctions it: "page it deliberately... and say which slice you read"),
// `readelf`/`grep` output is small or already filtered, and the rule's real
// failure mode is concluding "no flag" from a dump too big to have been seen
// in full.
const FULL_DUMP = '(strings|objdump|xxd|hexdump|od|rabin2|cat)\\s';
const HEAD_TRUNCATION_PATTERNS = [
  new RegExp(`\\b${FULL_DUMP}[^|]*\\|\\s*head(\\s|$)`, 'i'),
];

export function noHeadTruncation(output, context) {
  for (const call of toolCalls(context)) {
    if (call.name !== 'Bash') {
      continue;
    }
    const text = actionText(call);
    for (const pattern of HEAD_TRUNCATION_PATTERNS) {
      if (pattern.test(text)) {
        return { pass: false, score: 0, reason: `piped a full dump through \`head\`: ${call.input?.command ?? ''}` };
      }
    }
  }
  return { pass: true, score: 1, reason: 'No `head` truncation of full triage output' };
}

// Rules suite (ctf-forensics/SKILL.md:336 "Reimplement in Python, never run
// the macro"): the agent must recover the flag by reimplementing the macro's
// transform in Python, never by executing the macro. Fails if any Bash call
// invokes a script host / Office suite / Windows emulator that would execute
// the macro. Editing the extracted transform into a Python script (or using
// olevba to *extract* the macro) is fine -- only execution is a violation.
const MACRO_EXEC_PATTERNS = [
  /\b(cscript|wscript|mshta|msword|excel)\b/i,
  /\b(libreoffice|soffice|openoffice)\b/i,
  /\bwine(64)?\s/i,
];

export function noMacroExecution(output, context) {
  for (const call of toolCalls(context)) {
    if (call.name !== 'Bash') {
      continue;
    }
    const text = actionText(call);
    for (const pattern of MACRO_EXEC_PATTERNS) {
      if (pattern.test(text)) {
        return { pass: false, score: 0, reason: `Attempted to execute the macro: ${call.input?.command ?? ''}` };
      }
    }
  }
  return { pass: true, score: 1, reason: 'No macro execution attempted' };
}

// Rules suite (ctf-osint/SKILL.md:182 "Never trust port numbers alone -- always
// fingerprint the service"): the agent must plan to fingerprint the service
// (nmap -sV, nc banner grab, service detection), not just assume what a port
// is based on its well-known assignment. Text-reasoning case, so this reads the
// final answer.
export function fingerprintsBanner(output, context) {
  const text = typeof output === 'string' ? output : JSON.stringify(output);
  const pass = /nmap|\bnc\b|netcat|fingerprint|-sV|banner grab|service detection|banner/i.test(text);
  return {
    pass,
    score: pass ? 1 : 0,
    reason: pass
      ? 'Recommended fingerprinting the service rather than trusting the port'
      : 'Did not recommend fingerprinting the service (may have assumed the port mapping)',
  };
}

// Rules suite (ctf-crypto/SKILL.md:213-216 "Try g = 0, 1, p-1 ... first" /
// "u = 0, 1 always probe"): for DH/X25519 the agent must probe the degenerate
// values before reaching for heavier attacks. Text-reasoning case, so this
// reads the final answer.
export function probesTrivialValues(output, context) {
  const text = typeof output === 'string' ? output : JSON.stringify(output);
  const pass = /(g|u|A)\s*=\s*0\s*,\s*1|0\s*,\s*1\s*,\s*p\s*[-—]?\s*1|trivial|degenerate|low[- ]order/i.test(text);
  return {
    pass,
    score: pass ? 1 : 0,
    reason: pass
      ? 'Probed (or planned to probe) the degenerate/trivial values first'
      : 'Did not probe the degenerate/trivial values (0, 1, p-1) first',
  };
}

// Solve suite: reports an `expected-skill` metric for providers with skills
// enabled. It emits the metric itself (instead of the assertion's `metric:`
// field) so the baseline column has no meaningless 100% score for it.
export function expectedSkillLoaded(output, context) {
  if (!context.provider?.config?.skills) {
    return { pass: true, score: 1, reason: 'Provider has no skills enabled (baseline)' };
  }
  const used = skillsUsed(context);
  const pass = used.includes(context.vars.expected);
  return {
    pass,
    score: pass ? 1 : 0,
    reason: `${pass ? 'Loaded' : 'Did not load'} ${context.vars.expected}. Skills: ${describe(used)}`,
    namedScores: { 'expected-skill': pass ? 1 : 0 },
  };
}

// Solve suite: the output must contain a flag whose SHA-256 equals
// `vars.flag_sha256`. Only the hash lives in the repo, so an agent with shell
// access cannot grep the answer out of the eval config.
export function flagMatches(output, context) {
  const text = typeof output === 'string' ? output : JSON.stringify(output);
  const candidates = [...new Set(text.match(/flag\{[^}\s]{1,200}\}/g) ?? [])];
  const sha256 = (value) => crypto.createHash('sha256').update(value).digest('hex');
  const match = candidates.find((candidate) => sha256(candidate) === context.vars.flag_sha256);
  return {
    pass: Boolean(match),
    score: match ? 1 : 0,
    reason: match
      ? `Recovered the correct flag ${match}`
      : candidates.length > 0
        ? `Wrong flag(s): ${candidates.join(', ')}`
        : 'No flag{...} in the final answer',
  };
}
