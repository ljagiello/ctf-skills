"""Validate SKILL.md frontmatter across all skills in the repository."""

import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

VALID_TOOLS = {
    "Bash",
    "Read",
    "Write",
    "Edit",
    "Glob",
    "Grep",
    "Task",
    "WebFetch",
    "WebSearch",
    "Skill",
}

REQUIRED_FIELDS = {"name", "description", "license", "compatibility", "allowed-tools"}


def _parse_frontmatter(text: str) -> dict[str, str] | None:
    """Parse YAML frontmatter between --- markers into a flat dict.

    Handles the simple key: value format used by SKILL.md files, plus the
    nested metadata block.
    """
    lines = text.splitlines()
    if not lines or lines[0].strip() != "---":
        return None

    end = None
    for i, line in enumerate(lines[1:], start=1):
        if line.strip() == "---":
            end = i
            break
    if end is None:
        return None

    result: dict[str, str] = {}
    current_block: str | None = None

    for line in lines[1:end]:
        stripped = line.strip()
        if not stripped:
            continue

        # Detect nested block (e.g. "metadata:")
        if stripped.endswith(":") and ":" not in stripped[:-1]:
            current_block = stripped[:-1]
            continue

        if ":" not in stripped:
            continue

        key, _, value = stripped.partition(":")
        key = key.strip()
        value = value.strip().strip('"')

        if current_block:
            result[f"{current_block}.{key}"] = value
        else:
            result[key] = value

    return result


def _discover_skills() -> list[Path]:
    """Find all directories containing a SKILL.md file."""
    return sorted(p.parent for p in REPO_ROOT.glob("*/SKILL.md"))


class TestSkillFrontmatter(unittest.TestCase):
    """Validate frontmatter for every SKILL.md in the repository."""

    def setUp(self):
        self.skills = _discover_skills()
        self.assertGreater(len(self.skills), 0, "No SKILL.md files found")

    def test_all_skills_have_valid_frontmatter(self):
        for skill_dir in self.skills:
            text = (skill_dir / "SKILL.md").read_text(encoding="utf-8")
            fm = _parse_frontmatter(text)
            with self.subTest(skill=skill_dir.name):
                self.assertIsNotNone(fm, f"{skill_dir.name}/SKILL.md has no frontmatter")

    def test_required_fields_present(self):
        for skill_dir in self.skills:
            text = (skill_dir / "SKILL.md").read_text(encoding="utf-8")
            fm = _parse_frontmatter(text)
            if fm is None:
                continue
            with self.subTest(skill=skill_dir.name):
                missing = REQUIRED_FIELDS - fm.keys()
                self.assertEqual(
                    missing,
                    set(),
                    f"{skill_dir.name}/SKILL.md missing fields: {missing}",
                )

    def test_name_matches_directory(self):
        for skill_dir in self.skills:
            text = (skill_dir / "SKILL.md").read_text(encoding="utf-8")
            fm = _parse_frontmatter(text)
            if fm is None:
                continue
            with self.subTest(skill=skill_dir.name):
                self.assertEqual(
                    fm.get("name"),
                    skill_dir.name,
                    f"name '{fm.get('name')}' doesn't match directory '{skill_dir.name}'",
                )

    def test_allowed_tools_are_valid(self):
        for skill_dir in self.skills:
            text = (skill_dir / "SKILL.md").read_text(encoding="utf-8")
            fm = _parse_frontmatter(text)
            if fm is None:
                continue
            with self.subTest(skill=skill_dir.name):
                tools_str = fm.get("allowed-tools", "")
                tools = set(tools_str.split())
                unknown = tools - VALID_TOOLS
                self.assertEqual(
                    unknown,
                    set(),
                    f"{skill_dir.name} has unknown tools: {unknown}",
                )

    def test_license_is_mit(self):
        for skill_dir in self.skills:
            text = (skill_dir / "SKILL.md").read_text(encoding="utf-8")
            fm = _parse_frontmatter(text)
            if fm is None:
                continue
            with self.subTest(skill=skill_dir.name):
                self.assertEqual(
                    fm.get("license"),
                    "MIT",
                    f"{skill_dir.name} license is '{fm.get('license')}', expected 'MIT'",
                )

    def test_user_invocable_is_boolean_string(self):
        for skill_dir in self.skills:
            text = (skill_dir / "SKILL.md").read_text(encoding="utf-8")
            fm = _parse_frontmatter(text)
            if fm is None:
                continue
            with self.subTest(skill=skill_dir.name):
                value = fm.get("metadata.user-invocable")
                self.assertIsNotNone(
                    value,
                    f"{skill_dir.name} missing metadata.user-invocable",
                )
                self.assertIn(
                    value,
                    ("true", "false"),
                    f"{skill_dir.name} metadata.user-invocable is '{value}'",
                )

    def test_invocable_skills_have_argument_hint(self):
        for skill_dir in self.skills:
            text = (skill_dir / "SKILL.md").read_text(encoding="utf-8")
            fm = _parse_frontmatter(text)
            if fm is None:
                continue
            with self.subTest(skill=skill_dir.name):
                if fm.get("metadata.user-invocable") == "true":
                    hint = fm.get("metadata.argument-hint")
                    self.assertIsNotNone(
                        hint,
                        f"{skill_dir.name} is user-invocable but missing argument-hint",
                    )
                    self.assertGreater(
                        len(hint),
                        0,
                        f"{skill_dir.name} has empty argument-hint",
                    )

    def test_description_is_meaningful(self):
        for skill_dir in self.skills:
            text = (skill_dir / "SKILL.md").read_text(encoding="utf-8")
            fm = _parse_frontmatter(text)
            if fm is None:
                continue
            with self.subTest(skill=skill_dir.name):
                desc = fm.get("description", "")
                self.assertGreater(
                    len(desc),
                    20,
                    f"{skill_dir.name} description too short ({len(desc)} chars)",
                )
