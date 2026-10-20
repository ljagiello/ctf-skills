// promptfoo extension hooks that stage fresh agent workspaces under
// evals/.work/ from the current working tree, so every eval exercises the
// skills exactly as they are on disk right now (including uncommitted edits).
//
// Layout produced (all gitignored):
//   .work/routing/.claude/skills/<skill>/...          every skill (copy), no challenge files
//   .work/skills/<fixture>/{challenge files, .claude/skills/<skill>/...}   (copy)
//   .work/baseline/<fixture>/{challenge files}         same files, no skills
//   .work/rules/text/.claude/skills/<skill> -> ../../../../../../<skill>   (SYMLINK, no copy)
//   .work/rules/<fixture>/{challenge files, .claude/skills/<skill> -> ...} (SYMLINK, no copy)
//
// Skills live under .claude/skills/ because that is where `npx skills add`
// installs them and what the Claude Agent SDK discovers with
// `setting_sources: ['project']`, so skill names stay unnamespaced (ctf-pwn,
// not plugin:ctf-pwn).
//
// The routing and solve suites COPY the skills into .work/ (their configs use
// copy_working_dir: copy, which rejects symlinks that leave the workspace).
// The rules suite instead SYMLINKS them straight to the live source folders and
// runs with copy_working_dir: false, so a rules case always tests the skill
// files as they are on disk right now -- never a stale snapshot.
//
// Each suite has its own stager and only replaces its own directories, so the
// routing and solve suites can run at the same time. They are not named after
// a hook, so promptfoo calls them for every hook as (hookName, context).

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const EVALS_DIR = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const REPO_ROOT = path.resolve(EVALS_DIR, '..');
const WORK_DIR = path.join(EVALS_DIR, '.work');
const FIXTURES_DIR = path.join(EVALS_DIR, 'fixtures');
const RULE_FIXTURES_DIR = path.join(FIXTURES_DIR, 'rules');

// Top-level directories that hold a SKILL.md are skills (same rule as tests/).
function discoverSkills() {
  return fs
    .readdirSync(REPO_ROOT, { withFileTypes: true })
    .filter((entry) => entry.isDirectory() && !entry.name.startsWith('.'))
    .filter((entry) => fs.existsSync(path.join(REPO_ROOT, entry.name, 'SKILL.md')))
    .map((entry) => entry.name)
    .sort();
}

// Skip symlinks (e.g. the optional ctf-web/payloads PayloadsAllTheThings link):
// they point outside the repo, bloat the copy, and copy_working_dir rejects them.
function copyTree(src, dest) {
  fs.cpSync(src, dest, {
    recursive: true,
    filter: (source) =>
      !fs.lstatSync(source).isSymbolicLink() && path.basename(source) !== '__pycache__',
  });
}

function installSkills(workspace, skills) {
  for (const skill of skills) {
    copyTree(path.join(REPO_ROOT, skill), path.join(workspace, '.claude', 'skills', skill));
  }
}

// Rules suite loads skills straight from the live source folders (NO COPY):
// symlink each repo skill into <workspace>/.claude/skills/<name> so the
// Skill tool reads the actual SKILL.md and technique files on disk, never a
// stale snapshot. The rules provider must set copy_working_dir: false, since
// promptfoo's copy_working_dir rejects symlinks that point outside the
// workspace.
function linkSkills(workspace, skills) {
  const skillsDir = path.join(workspace, '.claude', 'skills');
  fs.mkdirSync(skillsDir, { recursive: true });
  for (const skill of skills) {
    const target = path.relative(skillsDir, path.join(REPO_ROOT, skill));
    fs.symlinkSync(target, path.join(skillsDir, skill));
  }
}

function resetDir(dir) {
  fs.rmSync(dir, { recursive: true, force: true });
  fs.mkdirSync(dir, { recursive: true });
}

function log(message) {
  console.error(`[ctf-skills evals] ${message}`);
}

export function stageRouting(hookName) {
  if (hookName !== 'beforeAll') {
    return;
  }
  const skills = discoverSkills();
  const workspace = path.join(WORK_DIR, 'routing');
  resetDir(workspace);
  installSkills(workspace, skills);
  log(`staged ${skills.length} skills in ${workspace}`);
}

export function stageSolve(hookName) {
  if (hookName !== 'beforeAll') {
    return;
  }
  const skills = discoverSkills();
  const fixtures = fs
    .readdirSync(FIXTURES_DIR, { withFileTypes: true })
    .filter((entry) => entry.isDirectory())
    .map((entry) => entry.name);
  resetDir(path.join(WORK_DIR, 'baseline'));
  resetDir(path.join(WORK_DIR, 'skills'));
  for (const fixture of fixtures) {
    const source = path.join(FIXTURES_DIR, fixture);
    copyTree(source, path.join(WORK_DIR, 'baseline', fixture));
    copyTree(source, path.join(WORK_DIR, 'skills', fixture));
    installSkills(path.join(WORK_DIR, 'skills', fixture), skills);
  }
  log(`staged ${fixtures.length} fixtures with and without ${skills.length} skills in ${WORK_DIR}`);
}

// Rules suite: every fixture gets the skills symlinked (there is no
// with/without-skills comparison here — these cases test whether a loaded
// skill's documented rules are actually followed). `text` is a skills-only
// workspace for cases that need no challenge files, just Bash/Write access
// to see what the agent would run. Unlike routing/solve, the skills are
// linked straight to the live source folders (NO COPY) so the eval always
// exercises the skill files as they are on disk right now.
//
// promptfoo only renders {{vars}} in `working_dir` on the `copy_working_dir`
// path; with copy_working_dir false (required for symlinks) the raw
// `{{workspace}}` reaches the provider. So we capture the shared provider
// config at beforeAll and rewrite its `working_dir` per test at beforeEach.
export function stageRules(hookName, context) {
  if (hookName === 'beforeAll') {
    stages.rulesProviderConfig = context?.suite?.providers?.[0]?.config ?? null;
    const skills = discoverSkills();
    const rulesWork = path.join(WORK_DIR, 'rules');
    resetDir(rulesWork);
    linkSkills(path.join(rulesWork, 'text'), skills);

    const fixtures = fs.existsSync(RULE_FIXTURES_DIR)
      ? fs
          .readdirSync(RULE_FIXTURES_DIR, { withFileTypes: true })
          .filter((entry) => entry.isDirectory())
          .map((entry) => entry.name)
      : [];
    for (const fixture of fixtures) {
      const workspace = path.join(rulesWork, fixture);
      copyTree(path.join(RULE_FIXTURES_DIR, fixture), workspace);
      linkSkills(workspace, skills);
    }
    log(`staged a text-only workspace and ${fixtures.length} rule fixtures in ${rulesWork} (skills symlinked, no copy)`);
    return;
  }

  if (hookName === 'beforeEach' && stages.rulesProviderConfig) {
    const workspace = context?.test?.vars?.workspace;
    if (typeof workspace === 'string' && workspace && !String(workspace).includes('{{')) {
      stages.rulesProviderConfig.working_dir = path.join('.work', 'rules', workspace);
      // The `text` workspace is shared by several text-only cases; without
      // copy_working_dir its files live across cases, so clear any prior
      // case's writes (leaving the .claude/skills symlinks alone).
      if (workspace === 'text') {
        cleanWorkspaceFiles(path.join(WORK_DIR, 'rules', 'text'));
      }
    }
  }
  return context;
}

// Remove every entry in a workspace except the .claude/ skills symlinks.
function cleanWorkspaceFiles(workspace) {
  if (!fs.existsSync(workspace)) {
    return;
  }
  for (const entry of fs.readdirSync(workspace, { withFileTypes: true })) {
    if (entry.name === '.claude') {
      continue;
    }
    fs.rmSync(path.join(workspace, entry.name), { recursive: true, force: true });
  }
}

// Module state shared between the beforeAll and beforeEach hook invocations.
const stages = { rulesProviderConfig: null };
