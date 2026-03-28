#!/usr/bin/env python3
"""Skill Security Auditor — scans skill directories for security risks."""

import argparse
import json
import re
import sys
from pathlib import Path

# --- Pattern definitions ---

CRITICAL_PATTERNS = [
    (r'rm\s+-rf\s+/', "Destructive command: rm -rf /"),
    (r'curl\s+[^\|]*\|\s*(ba)?sh', "Pipe-to-shell: curl | sh"),
    (r'wget\s+[^\|]*\|\s*(ba)?sh', "Pipe-to-shell: wget | sh"),
    (r'mkfs\.\w+\s+/dev/', "Destructive command: mkfs on device"),
    (r'dd\s+.*of=/dev/(sd|hd|vd|nvme)', "Destructive command: dd to disk device"),
    (r':\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:', "Fork bomb"),
]

SECRET_PATTERNS = [
    (r'\b(AKIA[0-9A-Z]{16})\b', "Hardcoded AWS access key"),
    (r'-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----', "Embedded private key"),
    (r'\b(ghp_[A-Za-z0-9_]{36,})\b', "Hardcoded GitHub personal access token"),
    (r'\b(sk-[A-Za-z0-9]{20,})\b', "Hardcoded API secret key (sk-...)"),
]

HIGH_PATTERNS = [
    (r'(?<![\w.])eval\s*\(\s*["\']', "Direct eval() with string literal"),
    (r'(?<![\w.])exec\s*\(\s*["\']', "Direct exec() with string literal"),
    (r'os\.system\s*\(\s*f["\']', "os.system() with f-string (injection risk)"),
    (r'<script[^>]*>.*document\.(cookie|location)', "XSS payload accessing sensitive DOM"),
    (r'chmod\s+[47]77\s+/', "World-writable permission on system path"),
    (r'--no-check-certificate', "SSL verification disabled"),
    (r'verify\s*=\s*False', "SSL verification disabled in Python"),
]

INFO_PATTERNS = [
    (r'\b(TODO|FIXME|HACK)\s*:', "Code annotation found"),
]

PLACEHOLDER_HOST_MARKERS = (
    'exfil.com',
    'attacker.com',
    'example.com',
    'example.org',
    'example.invalid',
)

# Inline suppression: lines containing this marker are skipped for HIGH patterns
AUDIT_SUPPRESS_MARKER = '<!-- audit-ok'

# CTF documentation patterns that are expected in attack technique references.
# These appear in code blocks as copy-paste payloads, not as instructions to
# run dangerous commands against real systems.

# AngularJS $eval() is a template sandbox escape payload, not Python/JS eval()
CTF_EVAL_ALLOWLIST = re.compile(
    r'\$eval\s*\('        # AngularJS $eval('...')
    r'|'
    r'eval\s*\(\s*["\']x='  # AngularJS sandbox: eval('x=alert(1)')
)

# Common RCE verification commands used in CTF exploit demonstrations
CTF_EXEC_ALLOWLIST = re.compile(
    r"""exec\s*\(\s*['"](?:id|ls|cat |whoami|uname|pwd|echo )"""
)

# /tmp/ is world-writable by design — chmod 777 /tmp/* is standard in
# kernel exploitation (modprobe_path, core_pattern) and not a system risk
CTF_CHMOD_ALLOWLIST = re.compile(
    r'chmod\s+[47]77\s+/tmp/'
)

FRONTMATTER_CHECKS = {
    'license': 'Missing license field in frontmatter',
    'allowed-tools': 'Missing allowed-tools field in frontmatter',
    'name': 'Missing name field in frontmatter',
    'description': 'Missing description field in frontmatter',
}

THIRD_PERSON_STARTERS = (
    'provides', 'generates', 'solves', 'analyzes', 'extracts', 'scans',
    'detects', 'identifies', 'builds', 'creates', 'parses', 'runs',
    'executes', 'processes', 'transforms', 'validates', 'checks',
    'orchestrates', 'delegates', 'implements',
)


def parse_frontmatter(content: str) -> dict:
    """Extract YAML frontmatter fields (simple key: value parsing)."""
    fm = {}
    if not content.startswith('---'):
        return fm

    match = re.match(r"^---\s*\n(.*?)\n---\s*(?:\n|$)", content, re.DOTALL)
    if not match:
        return fm

    block = match.group(1)
    for line in block.strip().splitlines():
        if ':' in line:
            key, _, val = line.partition(':')
            fm[key.strip()] = val.strip()
    return fm


def has_shell_true_subprocess_call(line: str) -> bool:
    """Detect subprocess.call() with a string argument and shell=True on the same line."""
    if 'subprocess.call' not in line or 'shell=True' not in line:
        return False

    match = re.search(r'subprocess\.call\s*\(\s*([\'"])', line)
    return match is not None


def read_markdown_file(filepath: Path) -> tuple[str | None, dict | None]:
    """Read a markdown file with strict UTF-8 handling."""
    try:
        return filepath.read_text(encoding='utf-8'), None
    except UnicodeDecodeError as e:
        return None, {
            'severity': 'HIGH',
            'file': str(filepath),
            'line': 0,
            'rule': 'unreadable_file',
            'message': f'Could not decode file as UTF-8: {e}',
        }
    except OSError as e:
        return None, {
            'severity': 'HIGH',
            'file': str(filepath),
            'line': 0,
            'rule': 'unreadable_file',
            'message': f'Could not read file: {e}',
        }


def is_placeholder_xss_example(line: str) -> bool:
    """Ignore educational XSS exfil examples that only use placeholder hosts."""
    lowered = line.lower()
    touches_sensitive_dom = 'document.cookie' in lowered or 'document.location' in lowered
    uses_placeholder_host = any(marker in lowered for marker in PLACEHOLDER_HOST_MARKERS)
    return touches_sensitive_dom and uses_placeholder_host


def scan_file(filepath: Path) -> list:
    """Scan a single file and return findings."""
    findings = []
    content, read_error = read_markdown_file(filepath)
    if read_error is not None:
        findings.append(read_error)
        return findings

    lines = content.splitlines()

    # Check code blocks only (between ``` markers) for dangerous patterns
    in_code_block = False
    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        is_indented_code = line.startswith('    ') or line.startswith('\t')

        if stripped.startswith('```'):
            in_code_block = not in_code_block
            continue

        in_executable_example = in_code_block or is_indented_code

        # Destructive commands should appear in runnable examples before we flag them.
        if in_executable_example:
            for pattern, message in CRITICAL_PATTERNS:
                if re.search(pattern, line):
                    findings.append({
                        'severity': 'CRITICAL',
                        'file': str(filepath),
                        'line': i,
                        'rule': pattern[:40],
                        'message': message,
                        'context': line.strip()[:120],
                    })

        # Real secret material should be flagged wherever it appears.
        for pattern, message in SECRET_PATTERNS:
            if re.search(pattern, line):
                findings.append({
                    'severity': 'CRITICAL',
                    'file': str(filepath),
                    'line': i,
                    'rule': pattern[:40],
                    'message': message,
                    'context': line.strip()[:120],
                })

        # High patterns — only in runnable code examples
        if in_executable_example:
            # Inline suppression: <!-- audit-ok --> on the current or previous line
            suppress_marker_here = AUDIT_SUPPRESS_MARKER in line
            suppress_marker_prev = (i >= 2 and AUDIT_SUPPRESS_MARKER in lines[i - 2])
            suppress = suppress_marker_here or suppress_marker_prev

            if not suppress and has_shell_true_subprocess_call(line):
                findings.append({
                    'severity': 'HIGH',
                    'file': str(filepath),
                    'line': i,
                    'rule': 'subprocess.call+shell=True',
                    'message': 'subprocess with shell=True and string',
                    'context': line.strip()[:120],
                })

            if not suppress:
                for pattern, message in HIGH_PATTERNS:
                    if re.search(pattern, line):
                        if message == "XSS payload accessing sensitive DOM" and is_placeholder_xss_example(line):
                            continue
                        # CTF-specific allowlists for documented attack payloads
                        if "eval()" in message and CTF_EVAL_ALLOWLIST.search(line):
                            continue
                        if "exec()" in message and CTF_EXEC_ALLOWLIST.search(line):
                            continue
                        if "World-writable" in message and CTF_CHMOD_ALLOWLIST.search(line):
                            continue
                        findings.append({
                            'severity': 'HIGH',
                            'file': str(filepath),
                            'line': i,
                            'rule': pattern[:40],
                            'message': message,
                            'context': line.strip()[:120],
                        })

        for pattern, message in INFO_PATTERNS:
            if re.search(pattern, line):
                findings.append({
                    'severity': 'INFO',
                    'file': str(filepath),
                    'line': i,
                    'rule': pattern[:40],
                    'message': message,
                    'context': line.strip()[:120],
                })

    return findings


def scan_skill(skill_dir: Path) -> dict:
    """Scan an entire skill directory."""
    findings = []

    skill_md = skill_dir / 'SKILL.md'
    if not skill_md.exists():
        findings.append({
            'severity': 'HIGH',
            'file': str(skill_md),
            'line': 0,
            'rule': 'missing_skill_md',
            'message': 'SKILL.md not found in skill directory',
        })
    else:
        try:
            content = skill_md.read_text(encoding='utf-8')
        except UnicodeDecodeError as e:
            findings.append({
                'severity': 'HIGH',
                'file': str(skill_md),
                'line': 0,
                'rule': 'unreadable_skill_md',
                'message': f'Could not decode SKILL.md as UTF-8: {e}',
            })
            content = None
        except OSError as e:
            findings.append({
                'severity': 'HIGH',
                'file': str(skill_md),
                'line': 0,
                'rule': 'unreadable_skill_md',
                'message': f'Could not read SKILL.md: {e}',
            })
            content = None

        if content is not None:
            fm = parse_frontmatter(content)
            for key, message in FRONTMATTER_CHECKS.items():
                if key not in fm:
                    findings.append({
                        'severity': 'INFO',
                        'file': str(skill_md),
                        'line': 0,
                        'rule': f'missing_{key}',
                        'message': message,
                    })

            # Validate name matches directory
            if 'name' in fm:
                expected_name = skill_dir.name
                actual_name = fm['name'].strip('"').strip("'")
                if actual_name != expected_name:
                    findings.append({
                        'severity': 'HIGH',
                        'file': str(skill_md),
                        'line': 0,
                        'rule': 'name_mismatch',
                        'message': f'Frontmatter name "{actual_name}" does not match directory "{expected_name}"',
                    })

            # Validate description is third-person
            if 'description' in fm:
                desc = fm['description'].strip('"').strip("'").strip()
                first_word = desc.split()[0].lower() if desc else ''
                if first_word and not first_word.endswith('s'):
                    findings.append({
                        'severity': 'INFO',
                        'file': str(skill_md),
                        'line': 0,
                        'rule': 'description_not_third_person',
                        'message': f'Description should start with a third-person verb (e.g., "Provides..."), got "{first_word.capitalize()}..."',
                    })

    # Scan all markdown files
    md_files = sorted(skill_dir.rglob('*.md'))
    for md_file in md_files:
        findings.extend(scan_file(md_file))

    # Determine verdict
    crit = sum(1 for f in findings if f['severity'] == 'CRITICAL')
    high = sum(1 for f in findings if f['severity'] == 'HIGH')
    info = sum(1 for f in findings if f['severity'] == 'INFO')

    if crit > 0:
        verdict = 'FAIL'
    elif high > 0:
        verdict = 'WARN'
    else:
        verdict = 'PASS'

    return {
        'skill': str(skill_dir),
        'verdict': verdict,
        'summary': {
            'critical': crit,
            'high': high,
            'info': info,
            'total': crit + high + info,
        },
        'findings': findings,
    }


def main():
    parser = argparse.ArgumentParser(description='Skill Security Auditor')
    parser.add_argument('skill_dir', help='Path to skill directory to audit')
    parser.add_argument('--strict', action='store_true',
                        help='Exit non-zero on CRITICAL findings')
    parser.add_argument('--json', action='store_true', dest='json_output',
                        help='Output results as JSON')
    args = parser.parse_args()

    skill_path = Path(args.skill_dir)
    if not skill_path.is_dir():
        print(f"Error: {args.skill_dir} is not a directory", file=sys.stderr)
        sys.exit(2)

    result = scan_skill(skill_path)

    if args.json_output:
        print(json.dumps(result, indent=2))
    else:
        v = result['verdict']
        s = result['summary']
        print(f"Skill: {result['skill']}")
        print(f"Verdict: {v}")
        print(f"Critical: {s['critical']}  High: {s['high']}  Info: {s['info']}")
        if result['findings']:
            print("\nFindings:")
            for f in result['findings']:
                print(f"  [{f['severity']}] {f['file']}:{f['line']} — {f['message']}")
                if 'context' in f:
                    print(f"    > {f['context']}")

    if args.strict and result['verdict'] == 'FAIL':
        sys.exit(1)


if __name__ == '__main__':
    main()
