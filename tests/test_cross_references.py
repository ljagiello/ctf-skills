"""Validate cross-references between CTF skills.

Tests:
1. Every technique .md file in a category is referenced in its SKILL.md
2. All /ctf-* cross-references in SKILL.md files point to valid targets
3. Internal markdown links ([text](file.md)) resolve to existing files
4. Anchor links within files resolve to actual headings
"""

import re
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

# Directories that contain skills
SKILL_DIRS = sorted(p.parent for p in REPO_ROOT.glob("*/SKILL.md"))


def _slugify_heading(heading: str) -> str:
    """Convert a markdown heading to a GitHub-style anchor slug.

    This is an approximation of GitHub's algorithm. It handles the common
    cases in this repo but may diverge for emoji, non-Latin scripts, or
    unusual consecutive special characters.
    """
    slug = heading.lower().strip()
    # Remove markdown formatting (but keep underscores — GitHub preserves
    # them in heading anchors, and they are common in identifiers like
    # `__dict__` or `stub_execveat` inside heading inline code).
    slug = re.sub(r"[*`~]", "", slug)
    # Remove HTML tags
    slug = re.sub(r"<[^>]+>", "", slug)
    # GitHub strips non-alphanumeric chars (except space, hyphen, underscore)
    # without collapsing adjacent whitespace — so `A + B` becomes `a--b`
    # because the `+` is removed and both surrounding spaces become hyphens.
    slug = re.sub(r"[^\w\s-]", "", slug)
    slug = slug.replace(" ", "-")
    return slug


def _strip_fenced_code(text: str) -> str:
    """Remove ```...``` fenced code blocks (keeps inline backtick content
    intact so headings like `## `stub_execveat` Syscall` still produce a
    slug containing `stub_execveat`).
    """
    out_lines = []
    in_fence = False
    for line in text.split("\n"):
        if line.strip().startswith("```"):
            in_fence = not in_fence
            out_lines.append("")
            continue
        out_lines.append("" if in_fence else line)
    return "\n".join(out_lines)


def _strip_all_code(text: str) -> str:
    """Strip fenced code blocks AND inline backtick code. Used before
    extracting markdown links so that `obj['k']('a')` in a code sample
    does not register as `[k](a)`.
    """
    text = _strip_fenced_code(text)
    return re.sub(r"`[^`]*`", "", text)


def _extract_headings(text: str) -> set[str]:
    """Extract all markdown headings as GitHub-style anchor slugs."""
    headings = set()
    for m in re.finditer(r"^#{1,6}\s+(.+)$", _strip_fenced_code(text), re.MULTILINE):
        headings.add(_slugify_heading(m.group(1)))
    return headings


def _extract_skill_references(text: str) -> list[str]:
    """Extract /ctf-* skill references from text."""
    return re.findall(r"/ctf-[\w-]+", text)


def _extract_local_md_links(text: str, source_dir: Path) -> list[tuple[str, str | None]]:
    """Extract local markdown links as (file, anchor_or_None) tuples.

    Only returns links to .md files within the same directory (not URLs).
    Code blocks and inline code are stripped first so JavaScript, Python,
    and LaTeX samples that contain `[key](val)`-shaped syntax do not
    register as markdown links.
    """
    text = _strip_all_code(text)
    links = []
    for m in re.finditer(r"\[([^\]]*)\]\(([^)]+)\)", text):
        target = m.group(2)
        # Skip URLs
        if target.startswith(("http://", "https://", "mailto:")):
            continue
        # Skip absolute paths outside the repo
        if target.startswith("/") and not target.startswith("/ctf-"):
            continue
        # Parse file#anchor
        if "#" in target:
            file_part, anchor = target.split("#", 1)
        else:
            file_part, anchor = target, None
        # Only check .md files
        if file_part and file_part.endswith(".md"):
            links.append((file_part, anchor))
    return links


class TestTechniqueFilesReferenced(unittest.TestCase):
    """Every .md file in a skill directory should be referenced in SKILL.md."""

    def test_all_technique_files_referenced_in_skill_md(self):
        for skill_dir in SKILL_DIRS:
            skill_text = (skill_dir / "SKILL.md").read_text(encoding="utf-8")
            technique_files = sorted(
                f.name for f in skill_dir.glob("*.md") if f.name != "SKILL.md"
            )
            for technique in technique_files:
                with self.subTest(skill=skill_dir.name, technique=technique):
                    self.assertIn(
                        technique,
                        skill_text,
                        f"{skill_dir.name}/SKILL.md does not reference {technique}",
                    )


class TestCrossSkillReferences(unittest.TestCase):
    """All /ctf-* references should point to valid skill directories."""

    def test_skill_references_are_valid(self):
        valid_dirs = {d.name for d in SKILL_DIRS}
        for skill_dir in SKILL_DIRS:
            skill_text = (skill_dir / "SKILL.md").read_text(encoding="utf-8")
            refs = _extract_skill_references(skill_text)
            for ref in refs:
                # /ctf-web -> ctf-web
                target = ref.lstrip("/")
                with self.subTest(skill=skill_dir.name, ref=ref):
                    self.assertIn(
                        target,
                        valid_dirs,
                        f"{skill_dir.name}/SKILL.md references {ref} "
                        f"but no {target}/ directory exists",
                    )


class TestLocalMarkdownLinks(unittest.TestCase):
    """Markdown links to local .md files should resolve to existing files."""

    def test_local_links_resolve(self):
        for skill_dir in SKILL_DIRS:
            for md_file in skill_dir.glob("*.md"):
                text = md_file.read_text(encoding="utf-8")
                links = _extract_local_md_links(text, skill_dir)
                for file_part, _anchor in links:
                    target_path = skill_dir / file_part
                    with self.subTest(
                        source=f"{skill_dir.name}/{md_file.name}",
                        link=file_part,
                    ):
                        self.assertTrue(
                            target_path.exists(),
                            f"{skill_dir.name}/{md_file.name} links to "
                            f"{file_part} which does not exist",
                        )


class TestAnchorLinks(unittest.TestCase):
    """Anchor links within files should resolve to actual headings."""

    def test_same_file_anchors_resolve(self):
        for skill_dir in SKILL_DIRS:
            for md_file in skill_dir.glob("*.md"):
                text = md_file.read_text(encoding="utf-8")
                headings = _extract_headings(text)
                links = _extract_local_md_links(text, skill_dir)
                for file_part, anchor in links:
                    if anchor is None:
                        continue
                    # For links to other files, check that file's headings
                    if file_part:
                        target_path = skill_dir / file_part
                        if not target_path.exists():
                            continue  # Covered by TestLocalMarkdownLinks
                        target_text = target_path.read_text(encoding="utf-8")
                        target_headings = _extract_headings(target_text)
                    else:
                        target_headings = headings

                    with self.subTest(
                        source=f"{skill_dir.name}/{md_file.name}",
                        anchor=anchor,
                    ):
                        self.assertIn(
                            anchor,
                            target_headings,
                            f"{skill_dir.name}/{md_file.name} links to "
                            f"#{anchor} but that heading was not found "
                            f"in {file_part or md_file.name}",
                        )


class TestBidirectionalPivotReferences(unittest.TestCase):
    """If skill A mentions /ctf-B in When to Pivot, B should mention /ctf-A."""

    def _extract_pivot_targets(self, text: str) -> set[str]:
        """Extract /ctf-* targets from the 'When to Pivot' section."""
        lines = text.splitlines()
        in_pivot = False
        targets = set()
        for line in lines:
            if re.match(r"^##\s+When to Pivot", line):
                in_pivot = True
                continue
            if in_pivot and re.match(r"^##\s+", line):
                break
            if in_pivot:
                for ref in _extract_skill_references(line):
                    targets.add(ref.lstrip("/"))
        return targets

    def test_pivot_references_are_bidirectional(self):
        pivot_map: dict[str, set[str]] = {}
        for skill_dir in SKILL_DIRS:
            text = (skill_dir / "SKILL.md").read_text(encoding="utf-8")
            targets = self._extract_pivot_targets(text)
            if targets:
                pivot_map[skill_dir.name] = targets

        for source, targets in pivot_map.items():
            for target in targets:
                with self.subTest(source=source, target=target):
                    if target not in pivot_map:
                        # Target skill has no pivot section — not a failure,
                        # but worth noting
                        continue
                    self.assertIn(
                        source,
                        pivot_map.get(target, set()),
                        f"{target}/SKILL.md 'When to Pivot' does not "
                        f"reference back to /{source} "
                        f"(but {source} references /{target}). "
                        f"Fix: add a '- If ..., switch to `/{source}`.' "
                        f"bullet in {target}/SKILL.md's 'When to Pivot' section.",
                    )
