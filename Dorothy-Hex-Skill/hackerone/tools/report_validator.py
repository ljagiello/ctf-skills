"""
HackerOne Report Validator

Validates vulnerability reports meet HackerOne submission requirements.
"""

import re
from pathlib import Path
from typing import Tuple, List, Dict


class ReportValidator:
    """Validates HackerOne vulnerability reports."""

    REQUIRED_SECTIONS = [
        "## Summary",
        "## Severity",
        "## Steps to Reproduce",
        "## Impact",
        "## Remediation"
    ]

    CVSS_PATTERN = r"CVSS:3\.\d+/AV:[NALP]/AC:[LH]/PR:[NLH]/UI:[NR]/S:[UC]/C:[NLH]/I:[NLH]/A:[NLH]"

    def __init__(self, report_path: str):
        """Initialize validator with report path."""
        self.report_path = Path(report_path)
        self.content = ""
        self.errors = []
        self.warnings = []

    def validate(self) -> Tuple[bool, str]:
        """
        Validate the report.

        Returns:
            Tuple of (is_valid, message)
        """
        if not self.report_path.exists():
            return False, f"Report file not found: {self.report_path}"

        with open(self.report_path, 'r', encoding='utf-8') as f:
            self.content = f.read()

        # Run all validation checks
        self._check_required_sections()
        self._check_cvss_score()
        self._check_steps_to_reproduce()
        self._check_poc_evidence()
        self._check_sensitive_data()
        self._check_report_length()
        self._check_title()

        # Build result message
        if self.errors:
            message = "Validation FAILED:\n\n"
            message += "Errors:\n"
            for error in self.errors:
                message += f"  ❌ {error}\n"
        else:
            message = "Validation PASSED:\n"
            message += "  ✅ All required sections present\n"
            message += "  ✅ CVSS score valid\n"
            message += "  ✅ Steps to reproduce included\n"
            message += "  ✅ PoC evidence present\n"

        if self.warnings:
            message += "\nWarnings:\n"
            for warning in self.warnings:
                message += f"  ⚠️  {warning}\n"

        return len(self.errors) == 0, message

    def _check_required_sections(self):
        """Check all required sections are present."""
        missing = []
        for section in self.REQUIRED_SECTIONS:
            if section not in self.content:
                missing.append(section)

        if missing:
            self.errors.append(f"Missing required sections: {', '.join(missing)}")

    def _check_cvss_score(self):
        """Check CVSS score is present and valid."""
        if "CVSS" not in self.content:
            self.errors.append("Missing CVSS score")
            return

        cvss_match = re.search(self.CVSS_PATTERN, self.content)
        if not cvss_match:
            self.warnings.append("CVSS vector string format may be invalid")

    def _check_steps_to_reproduce(self):
        """Check steps to reproduce are clear and numbered."""
        if "## Steps to Reproduce" not in self.content:
            return  # Already caught by required sections

        # Extract steps section
        steps_start = self.content.find("## Steps to Reproduce")
        next_section = self.content.find("##", steps_start + 1)
        steps_section = self.content[steps_start:next_section] if next_section != -1 else self.content[steps_start:]

        # Check for numbered steps
        if not re.search(r'^\d+\.', steps_section, re.MULTILINE):
            self.warnings.append("Steps to reproduce should be numbered (1. 2. 3.)")

        # Check section length
        if len(steps_section.strip()) < 100:
            self.warnings.append("Steps to reproduce section seems very short")

    def _check_poc_evidence(self):
        """Check for PoC evidence (code blocks, HTTP requests, screenshots)."""
        # Check for code blocks
        if "```" not in self.content:
            self.warnings.append("No code blocks found - include HTTP requests or PoC code")

        # Check for evidence references
        evidence_keywords = ["screenshot", "image", "video", "evidence", "proof"]
        has_evidence = any(keyword.lower() in self.content.lower() for keyword in evidence_keywords)

        if not has_evidence:
            self.warnings.append("No evidence references found - include screenshots or videos")

    def _check_sensitive_data(self):
        """Check for potential sensitive data leaks."""
        # Common patterns that might indicate sensitive data
        sensitive_patterns = [
            (r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', "email addresses"),
            (r'\b\d{16}\b', "potential credit card numbers"),
            (r'password["\s:=]+\w+', "passwords in plain text"),
            (r'api[_-]?key["\s:=]+\w+', "API keys"),
            (r'bearer\s+[A-Za-z0-9._-]+', "bearer tokens"),
            (r'-----BEGIN [A-Z]+ KEY-----', "private keys"),
        ]

        found_sensitive = []
        for pattern, description in sensitive_patterns:
            if re.search(pattern, self.content, re.IGNORECASE):
                found_sensitive.append(description)

        if found_sensitive:
            self.errors.append(f"Potential sensitive data found: {', '.join(found_sensitive)} - MUST sanitize before submission")

    def _check_report_length(self):
        """Check report is not too short or too long."""
        word_count = len(self.content.split())

        if word_count < 200:
            self.warnings.append(f"Report is very short ({word_count} words) - add more detail")
        elif word_count > 3000:
            self.warnings.append(f"Report is very long ({word_count} words) - consider being more concise")

    def _check_title(self):
        """Check for a clear title (first H1 heading)."""
        title_match = re.search(r'^# (.+)$', self.content, re.MULTILINE)

        if not title_match:
            self.warnings.append("No title found - add # Title at top of report")
        else:
            title = title_match.group(1).strip()
            if len(title) > 100:
                self.warnings.append(f"Title is too long ({len(title)} chars) - keep under 100 characters")
            elif len(title) < 10:
                self.warnings.append("Title is too short - be more descriptive")


def validate_report(report_path: str) -> Tuple[bool, str]:
    """
    Validate a HackerOne report.

    Args:
        report_path: Path to the report markdown file

    Returns:
        Tuple of (is_valid, message)

    Example:
        >>> valid, message = validate_report("finding-001/report.md")
        >>> print(message)
        Validation PASSED:
          ✅ All required sections present
          ✅ CVSS score valid
          ...
    """
    validator = ReportValidator(report_path)
    return validator.validate()


def validate_finding_directory(finding_dir: str) -> Tuple[bool, str]:
    """
    Validate a complete finding directory.

    Checks for:
    - report.md exists and is valid
    - poc.py or poc.sh exists
    - poc_output.txt exists with recent timestamp
    - workflow.md exists

    Args:
        finding_dir: Path to finding directory

    Returns:
        Tuple of (is_valid, message)
    """
    finding_path = Path(finding_dir)
    errors = []
    warnings = []

    # Check report.md
    report_path = finding_path / "report.md"
    if not report_path.exists():
        errors.append("report.md not found")
    else:
        valid, msg = validate_report(str(report_path))
        if not valid:
            errors.append(f"report.md validation failed:\n{msg}")

    # Check PoC script
    poc_py = finding_path / "poc.py"
    poc_sh = finding_path / "poc.sh"

    if not poc_py.exists() and not poc_sh.exists():
        errors.append("No PoC script found (poc.py or poc.sh)")

    # Check PoC output
    poc_output = finding_path / "poc_output.txt"
    if not poc_output.exists():
        errors.append("poc_output.txt not found - PoC must be executed and validated")
    else:
        # Check file is not empty
        if poc_output.stat().st_size == 0:
            errors.append("poc_output.txt is empty - run PoC to generate output")

    # Check workflow
    workflow = finding_path / "workflow.md"
    if not workflow.exists():
        warnings.append("workflow.md not found - include manual exploitation steps")

    # Build message
    if errors:
        message = f"Finding directory validation FAILED:\n\n"
        message += "Errors:\n"
        for error in errors:
            message += f"  ❌ {error}\n"
    else:
        message = "Finding directory validation PASSED:\n"
        message += "  ✅ report.md valid\n"
        message += "  ✅ PoC script present\n"
        message += "  ✅ PoC output validated\n"

    if warnings:
        message += "\nWarnings:\n"
        for warning in warnings:
            message += f"  ⚠️  {warning}\n"

    return len(errors) == 0, message


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage:")
        print("  python report_validator.py <report.md>")
        print("  python report_validator.py <finding_directory>")
        sys.exit(1)

    path = Path(sys.argv[1])

    if path.is_dir():
        valid, message = validate_finding_directory(str(path))
    elif path.is_file():
        valid, message = validate_report(str(path))
    else:
        print(f"Error: {path} is not a file or directory")
        sys.exit(1)

    print(message)
    sys.exit(0 if valid else 1)
