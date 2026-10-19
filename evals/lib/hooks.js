// promptfoo extension hooks that stage fresh agent workspaces under
// evals/.work/ from the current working tree, so every eval exercises the
// skills exactly as they are on disk right now (including uncommitted edits).
//
// Layout produced (all gitignored):
//   .work/routing/.claude/skills/<skill>/...          every skill, no challenge files
//   .work/skills/<fixture>/{challenge files, .claude/skills/<skill>/...}
//   .work/baseline/<fixture>/{challenge files}         same files, no skills
//
// Skills live under .claude/skills/ because that is where `npx skills add`
// installs them and what the Claude Agent SDK discovers with
// `setting_sources: ['project']`, so skill names stay unnamespaced (ctf-pwn,
// not plugin:ctf-pwn).
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
