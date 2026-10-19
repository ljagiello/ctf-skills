"""Keep the promptfoo evals in evals/ in sync with the skills.

The evals themselves call a model and cost money, so they run on demand.
These checks are free: every skill must have at least one routing case, and
every solve case must point at a real fixture that does not leak its flag.
"""

import re
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
EVALS_DIR = REPO_ROOT / "evals"
ROUTING_CASES = EVALS_DIR / "cases" / "routing.yaml"
SOLVE_CASES = EVALS_DIR / "cases" / "solve.yaml"
RULES_CASES = EVALS_DIR / "cases" / "rules.yaml"
FIXTURES_DIR = EVALS_DIR / "fixtures"
RULE_FIXTURES_DIR = FIXTURES_DIR / "rules"
# "text" isn't a fixture directory -- it's the skills-only workspace staged
# by lib/hooks.js:stageRules for cases with no challenge files.
TEXT_ONLY_WORKSPACE = "text"


def _skills() -> set[str]:
    return {path.parent.name for path in REPO_ROOT.glob("*/SKILL.md")}


def _var_values(path: Path, var: str) -> list[str]:
    """Collect scalar `var: value` entries from a flat promptfoo cases file."""
    pattern = re.compile(rf"^\s+{re.escape(var)}:\s*([^\s#\[{{]+)\s*$", re.MULTILINE)
    return pattern.findall(path.read_text(encoding="utf-8"))


class TestEvalCoverage(unittest.TestCase):
    def test_every_skill_has_a_routing_case(self):
        expected = set(_var_values(ROUTING_CASES, "expected"))
        missing = _skills() - expected
        self.assertFalse(
            missing,
            f"Add a case to {ROUTING_CASES.relative_to(REPO_ROOT)} for: {sorted(missing)}",
        )

    def test_routing_cases_name_real_skills(self):
        unknown = set(_var_values(ROUTING_CASES, "expected")) - _skills()
        self.assertFalse(unknown, f"Routing cases expect unknown skills: {sorted(unknown)}")

    def test_solve_cases_reference_fixtures(self):
        fixtures = _var_values(SOLVE_CASES, "fixture")
        self.assertTrue(fixtures, "No solve cases found")
        for fixture in fixtures:
            with self.subTest(fixture=fixture):
                self.assertTrue((FIXTURES_DIR / fixture).is_dir())

    def test_solve_cases_use_sha256_flags(self):
        hashes = _var_values(SOLVE_CASES, "flag_sha256")
        self.assertEqual(len(hashes), len(_var_values(SOLVE_CASES, "fixture")))
        for value in hashes:
            with self.subTest(value=value):
                self.assertRegex(value, r"^[0-9a-f]{64}$")

    def test_fixtures_do_not_contain_flags(self):
        # The rules suite's decoy-flag fixture deliberately embeds a
        # flag-shaped *decoy* string -- that's the point of the case, not a
        # leaked answer, so it's exempt from this check.
        exempt = {RULE_FIXTURES_DIR / "decoy-flag" / "build.log"}
        for path in FIXTURES_DIR.rglob("*"):
            if path.is_file() and path not in exempt:
                with self.subTest(path=str(path.relative_to(REPO_ROOT))):
                    self.assertNotIn(b"flag{", path.read_bytes())

    def test_rules_cases_reference_real_workspaces(self):
        workspaces = _var_values(RULES_CASES, "workspace")
        self.assertTrue(workspaces, "No rule cases found")
        known = {TEXT_ONLY_WORKSPACE} | {p.name for p in RULE_FIXTURES_DIR.iterdir() if p.is_dir()}
        for workspace in workspaces:
            with self.subTest(workspace=workspace):
                self.assertIn(workspace, known)

    def test_rules_cases_with_flags_use_sha256(self):
        hashes = _var_values(RULES_CASES, "flag_sha256")
        self.assertTrue(hashes, "Expected at least one flag-checking rule case")
        for value in hashes:
            with self.subTest(value=value):
                self.assertRegex(value, r"^[0-9a-f]{64}$")

    def test_rules_cases_come_in_positive_and_negative_pairs(self):
        """Every rule tag should have at least one positive and one negative/
        trap polarity, per the pairing convention documented in
        cases/rules.yaml's header."""
        text = RULES_CASES.read_text(encoding="utf-8")
        pairs = re.findall(r"rule:\s*(\S+),\s*polarity:\s*(positive|negative)\s*}", text)
        by_rule: dict[str, set[str]] = {}
        for rule, polarity in pairs:
            by_rule.setdefault(rule, set()).add(polarity)
        self.assertTrue(by_rule, "No (rule, polarity) metadata found in cases/rules.yaml")
        for rule, polarities in by_rule.items():
            with self.subTest(rule=rule):
                self.assertEqual(polarities, {"positive", "negative"})


if __name__ == "__main__":
    unittest.main()
