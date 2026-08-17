"""
HackerOne Scope CSV Parser

Parses HackerOne scope CSV files and extracts eligible assets for testing.
"""

import csv
from pathlib import Path
from typing import List, Dict, Optional


def parse_scope_csv(csv_path: str) -> List[Dict[str, str]]:
    """
    Parse HackerOne scope CSV file and extract eligible assets.

    Args:
        csv_path: Path to the CSV scope file

    Returns:
        List of asset dictionaries with parsed fields

    Example:
        >>> assets = parse_scope_csv("scopes_for_program.csv")
        >>> print(assets[0])
        {
            'identifier': 'example.com',
            'asset_type': 'URL',
            'max_severity': 'critical',
            'instruction': '',
            'eligible_for_bounty': True,
            'eligible_for_submission': True
        }
    """
    assets = []
    csv_file = Path(csv_path)

    if not csv_file.exists():
        raise FileNotFoundError(f"CSV file not found: {csv_path}")

    with open(csv_file, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)

        # Validate required columns
        required_columns = ['identifier', 'asset_type', 'eligible_for_submission']
        if not all(col in reader.fieldnames for col in required_columns):
            raise ValueError(f"CSV missing required columns: {required_columns}")

        for row_num, row in enumerate(reader, start=2):  # Start at 2 (header is 1)
            # Only include assets eligible for submission
            if row.get('eligible_for_submission', '').lower() != 'true':
                continue

            asset = {
                'identifier': row['identifier'].strip(),
                'asset_type': row['asset_type'].strip(),
                'max_severity': row.get('max_severity', 'critical').strip(),
                'instruction': row.get('instruction', '').strip(),
                'eligible_for_bounty': row.get('eligible_for_bounty', 'true').lower() == 'true',
                'eligible_for_submission': True,
                'csv_row': row_num
            }

            # Validate identifier is not empty
            if not asset['identifier']:
                print(f"Warning: Skipping row {row_num} - empty identifier")
                continue

            assets.append(asset)

    return assets


def categorize_assets(assets: List[Dict[str, str]]) -> Dict[str, List[Dict[str, str]]]:
    """
    Categorize assets by type for organized testing.

    Args:
        assets: List of parsed assets

    Returns:
        Dictionary mapping asset types to asset lists

    Example:
        >>> categorized = categorize_assets(assets)
        >>> print(categorized.keys())
        dict_keys(['URL', 'WILDCARD', 'API', 'CIDR'])
    """
    categorized = {}

    for asset in assets:
        asset_type = asset['asset_type']
        if asset_type not in categorized:
            categorized[asset_type] = []
        categorized[asset_type].append(asset)

    return categorized


def filter_by_severity(assets: List[Dict[str, str]], min_severity: str = 'low') -> List[Dict[str, str]]:
    """
    Filter assets by minimum severity level.

    Args:
        assets: List of parsed assets
        min_severity: Minimum severity ('critical', 'high', 'medium', 'low')

    Returns:
        Filtered list of assets
    """
    severity_levels = {'low': 0, 'medium': 1, 'high': 2, 'critical': 3}
    min_level = severity_levels.get(min_severity.lower(), 0)

    filtered = []
    for asset in assets:
        asset_level = severity_levels.get(asset['max_severity'].lower(), 0)
        if asset_level >= min_level:
            filtered.append(asset)

    return filtered


def get_bounty_eligible_assets(assets: List[Dict[str, str]]) -> List[Dict[str, str]]:
    """
    Filter to only bounty-eligible assets.

    Args:
        assets: List of parsed assets

    Returns:
        List of bounty-eligible assets
    """
    return [asset for asset in assets if asset.get('eligible_for_bounty', False)]


def generate_summary(assets: List[Dict[str, str]]) -> str:
    """
    Generate a summary of parsed assets.

    Args:
        assets: List of parsed assets

    Returns:
        Formatted summary string
    """
    total = len(assets)
    bounty_eligible = len(get_bounty_eligible_assets(assets))
    categorized = categorize_assets(assets)

    summary = f"Total assets: {total}\n"
    summary += f"Bounty eligible: {bounty_eligible}\n\n"
    summary += "By type:\n"

    for asset_type, type_assets in sorted(categorized.items()):
        summary += f"  {asset_type}: {len(type_assets)}\n"

    summary += "\nBy severity:\n"
    severity_counts = {}
    for asset in assets:
        sev = asset['max_severity']
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    for sev in ['critical', 'high', 'medium', 'low']:
        if sev in severity_counts:
            summary += f"  {sev.capitalize()}: {severity_counts[sev]}\n"

    return summary


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python csv_parser.py <csv_file>")
        sys.exit(1)

    csv_path = sys.argv[1]

    try:
        assets = parse_scope_csv(csv_path)
        print(generate_summary(assets))
        print(f"\nParsed {len(assets)} eligible assets from {csv_path}")

    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)
