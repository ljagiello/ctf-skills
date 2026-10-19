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
