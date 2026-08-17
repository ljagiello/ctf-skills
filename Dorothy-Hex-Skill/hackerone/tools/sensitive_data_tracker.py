#!/usr/bin/env python3
"""
Sensitive Data Metadata Tracker for HackerOne Bug Bounty Testing

Tracks and documents all credentials, tokens, and sensitive data discovered
during penetration testing in a structured JSON format.
"""

import json
import os
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any
import hashlib


class SensitiveDataTracker:
    """Track sensitive data discovered during penetration testing"""

    CATEGORIES = [
        "credentials",
        "api_keys_and_tokens",
        "private_data",
        "configuration_data",
        "user_pii",
        "other_sensitive"
    ]

    SEVERITY_LEVELS = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

    def __init__(self, program_name: str, asset_identifier: str, output_dir: str):
        """
        Initialize sensitive data tracker

        Args:
            program_name: HackerOne program name
            asset_identifier: Asset being tested (URL, domain, etc.)
            output_dir: Directory to save metadata files
        """
        self.program_name = program_name
        self.asset_identifier = asset_identifier
        self.output_dir = output_dir

        # Ensure output directory exists
        os.makedirs(output_dir, exist_ok=True)

        # Initialize metadata structure
        self.metadata = {
            "program": program_name,
            "asset_identifier": asset_identifier,
            "testing_date_start": datetime.now(timezone.utc).isoformat(),
            "testing_date_end": None,
            "tester": "Pentester Agent",
            "sensitive_data_categories": {cat: [] for cat in self.CATEGORIES},
            "summary": {
                "total_items_discovered": 0,
                "by_category": {cat: 0 for cat in self.CATEGORIES},
                "by_severity": {level: 0 for level in self.SEVERITY_LEVELS},
                "highest_risk_finding": None
            },
            "remediation_status": "pending"
        }

        self._save_metadata()

    def add_sensitive_data(
        self,
        category: str,
        data_type: str,
        location: str,
        finding_id: str,
        data_preview: Dict[str, Any],
        severity: str,
        impact_assessment: Dict[str, Any],
        evidence: Optional[Dict[str, str]] = None,
        remediation: Optional[str] = None
    ) -> None:
        """
        Add discovered sensitive data to tracking

        Args:
            category: Data category (credentials, api_keys_and_tokens, etc.)
            data_type: Type within category (e.g., username_password, api_key)
            location: Where data was found
            finding_id: Associated finding ID
            data_preview: Preview of data (with redaction)
            severity: CRITICAL, HIGH, MEDIUM, LOW, INFO
            impact_assessment: Business impact analysis
            evidence: Files/screenshots proving discovery
            remediation: Recommended remediation action
        """

        if category not in self.CATEGORIES:
            raise ValueError(f"Invalid category: {category}")

        if severity not in self.SEVERITY_LEVELS:
            raise ValueError(f"Invalid severity: {severity}")

        item = {
            "type": data_type,
            "location": location,
            "finding_id": finding_id,
            "discovered_date": datetime.now(timezone.utc).isoformat(),
            "data": data_preview,
            "severity": severity,
            "impact_assessment": impact_assessment,
            "evidence": evidence or {},
            "remediation": remediation or "Review and rotate credentials",
            "status": "discovered"
        }

        # Add to metadata
        self.metadata["sensitive_data_categories"][category].append(item)

        # Update summary
        self.metadata["summary"]["total_items_discovered"] += 1
        self.metadata["summary"]["by_category"][category] += 1
        self.metadata["summary"]["by_severity"][severity] += 1

        # Update highest risk finding
        if severity == "CRITICAL":
            if not self.metadata["summary"]["highest_risk_finding"]:
                self.metadata["summary"]["highest_risk_finding"] = finding_id

        # Save immediately to avoid data loss
        self._save_metadata()

        print(f"[+] Logged {category}/{data_type} (severity: {severity})")

    def add_credentials(
        self,
        username: str,
        password_hash: str,
        account_type: str,
        location: str,
        finding_id: str,
        hash_algorithm: Optional[str] = None,
        evidence: Optional[Dict[str, str]] = None
    ) -> None:
        """Add discovered credentials"""

        data_preview = {
            "username": username if username else "[REDACTED]",
            "password_hash": password_hash if password_hash else "[REDACTED]",
            "account_type": account_type,
            "hash_algorithm": hash_algorithm
        }

        impact = {
            "severity": "CRITICAL",
            "risk": "Account takeover, privilege escalation",
            "potential_actions": ["account_takeover", "data_breach"]
        }

        self.add_sensitive_data(
            category="credentials",
            data_type="username_password",
            location=location,
            finding_id=finding_id,
            data_preview=data_preview,
            severity="CRITICAL",
            impact_assessment=impact,
            evidence=evidence,
            remediation="Rotate credentials immediately"
        )

    def add_api_key(
        self,
        key_id: str,
        key_preview: str,
        scope: List[str],
        location: str,
        finding_id: str,
        token_type: str = "API Key",
        evidence: Optional[Dict[str, str]] = None
    ) -> None:
        """Add discovered API key or token"""

        data_preview = {
            "key_id": key_id if key_id else "[REDACTED]",
            "key_preview": key_preview,
            "token_type": token_type,
            "scope": scope
        }

        impact = {
            "severity": "HIGH",
            "risk": "Unauthorized API access, data exfiltration",
            "endpoints_accessible": len(scope)
        }

        self.add_sensitive_data(
            category="api_keys_and_tokens",
            data_type=token_type.lower(),
            location=location,
            finding_id=finding_id,
            data_preview=data_preview,
            severity="HIGH",
            impact_assessment=impact,
            evidence=evidence,
            remediation="Revoke token immediately and rotate secrets"
        )

    def add_private_key(
        self,
        key_type: str,
        key_length: int,
        purpose: str,
        location: str,
        finding_id: str,
        systems_accessible: Optional[List[str]] = None,
        evidence: Optional[Dict[str, str]] = None
    ) -> None:
        """Add discovered private key"""

        data_preview = {
            "key_type": key_type,
            "key_length": key_length,
            "purpose": purpose,
            "systems_accessible": systems_accessible or []
        }

        impact = {
            "severity": "CRITICAL",
            "risk": "Server access, complete system compromise",
            "systems_affected": len(systems_accessible or [])
        }

        self.add_sensitive_data(
            category="private_data",
            data_type="private_key",
            location=location,
            finding_id=finding_id,
            data_preview=data_preview,
            severity="CRITICAL",
            impact_assessment=impact,
            evidence=evidence,
            remediation="Revoke key and rotate all dependent credentials"
        )

    def add_database_credentials(
        self,
        database_type: str,
        host: str,
        port: int,
        database_name: str,
        location: str,
        finding_id: str,
        records_affected: Optional[int] = None,
        evidence: Optional[Dict[str, str]] = None
    ) -> None:
        """Add discovered database credentials"""

        data_preview = {
            "database_type": database_type,
            "host": host if host else "[REDACTED]",
            "port": port,
            "database_name": database_name,
            "records_accessible": records_affected
        }

        impact = {
            "severity": "CRITICAL",
            "risk": "Complete database access, data exfiltration",
            "records_affected": records_affected or 0
        }

        self.add_sensitive_data(
            category="configuration_data",
            data_type="database_credentials",
            location=location,
            finding_id=finding_id,
            data_preview=data_preview,
            severity="CRITICAL",
            impact_assessment=impact,
            evidence=evidence,
            remediation="Rotate database credentials immediately"
        )

    def add_user_pii(
        self,
        pii_types: List[str],
        records_affected: int,
        location: str,
        finding_id: str,
        affected_jurisdictions: Optional[List[str]] = None,
        evidence: Optional[Dict[str, str]] = None
    ) -> None:
        """Add discovered user PII"""

        data_preview = {
            "pii_types": pii_types,
            "records_affected": records_affected,
            "affected_jurisdictions": affected_jurisdictions or []
        }

        impact = {
            "severity": "CRITICAL",
            "risk": "Privacy violation, regulatory fines, identity theft",
            "records_exposed": records_affected,
            "legal_implications": ["GDPR", "CCPA"] if affected_jurisdictions else []
        }

        self.add_sensitive_data(
            category="user_pii",
            data_type="personal_information",
            location=location,
            finding_id=finding_id,
            data_preview=data_preview,
            severity="CRITICAL",
            impact_assessment=impact,
            evidence=evidence,
            remediation="Notify affected users per GDPR requirements (72 hours)"
        )

    def add_configuration_data(
        self,
        config_type: str,
        data_exposed: str,
        location: str,
        finding_id: str,
        evidence: Optional[Dict[str, str]] = None
    ) -> None:
        """Add exposed configuration data"""

        data_preview = {
            "config_type": config_type,
            "description": data_exposed
        }

        impact = {
            "severity": "HIGH",
            "risk": "Information disclosure, enables further attacks",
            "potential_actions": ["reconnaissance", "targeted_attacks"]
        }

        self.add_sensitive_data(
            category="configuration_data",
            data_type=config_type,
            location=location,
            finding_id=finding_id,
            data_preview=data_preview,
            severity="HIGH",
            impact_assessment=impact,
            evidence=evidence,
            remediation="Remove sensitive data from error messages and logs"
        )

    def add_other_sensitive_data(
        self,
        data_type: str,
        items: List[str],
        location: str,
        finding_id: str,
        severity: str = "MEDIUM",
        evidence: Optional[Dict[str, str]] = None
    ) -> None:
        """Add other sensitive data"""

        data_preview = {
            "data_type": data_type,
            "items": items,
            "count": len(items)
        }

        impact = {
            "severity": severity,
            "risk": f"Exposed {data_type} enables further reconnaissance"
        }

        self.add_sensitive_data(
            category="other_sensitive",
            data_type=data_type,
            location=location,
            finding_id=finding_id,
            data_preview=data_preview,
            severity=severity,
            impact_assessment=impact,
            evidence=evidence
        )

    def finalize(self) -> None:
        """Finalize tracking upon testing completion"""
        self.metadata["testing_date_end"] = datetime.now(timezone.utc).isoformat()
        self._save_metadata()

    def generate_summary_report(self) -> str:
        """Generate markdown summary report"""

        report = f"""# Sensitive Data Discovery Report

**Program**: {self.program_name}
**Asset**: {self.asset_identifier}
**Testing Start**: {self.metadata['testing_date_start']}
**Testing End**: {self.metadata.get('testing_date_end', 'In Progress')}

## Summary

**Total Sensitive Items Discovered**: {self.metadata['summary']['total_items_discovered']}

### By Category
"""

        for cat, count in self.metadata['summary']['by_category'].items():
            if count > 0:
                report += f"- {cat.replace('_', ' ').title()}: **{count}** items\n"

        report += "\n### By Severity\n"

        for level, count in self.metadata['summary']['by_severity'].items():
            if count > 0:
                report += f"- **{level}**: {count} items\n"

        report += "\n## Highest Risk\n"

        if self.metadata['summary']['highest_risk_finding']:
            report += f"Most critical findings: {self.metadata['summary']['highest_risk_finding']}\n"

        report += "\n## Required Actions\n"
        report += "- [ ] Rotate all discovered credentials immediately\n"
        report += "- [ ] Revoke all API keys and tokens\n"
        report += "- [ ] Disable compromised accounts\n"
        report += "- [ ] Notify users if PII was exposed\n"
        report += "- [ ] Audit access logs\n"

        return report

    def _save_metadata(self) -> None:
        """Save metadata to JSON file"""
        filepath = os.path.join(self.output_dir, "sensitive_data_metadata.json")

        with open(filepath, 'w') as f:
            json.dump(self.metadata, f, indent=2)

    def export_summary(self, output_path: Optional[str] = None) -> str:
        """Export markdown summary report"""
        if not output_path:
            output_path = os.path.join(self.output_dir, "sensitive_data_report.md")

        report = self.generate_summary_report()

        with open(output_path, 'w') as f:
            f.write(report)

        return output_path


# Example usage
if __name__ == "__main__":
    # Initialize tracker
    tracker = SensitiveDataTracker(
        program_name="ACME Corp Bug Bounty",
        asset_identifier="https://example.com",
        output_dir="./findings"
    )

    # Log discovered credentials
    tracker.add_credentials(
        username="admin",
        password_hash="$2y$10$abc123...",
        account_type="admin",
        location="SQL injection in search parameter",
        finding_id="finding-001",
        evidence={
            "poc_script": "findings/finding-001/poc.py",
            "poc_output": "findings/finding-001/poc_output.txt"
        }
    )

    # Log discovered API key
    tracker.add_api_key(
        key_id="sk_live_abc123",
        key_preview="sk_live_****...1234",
        scope=["read:users", "write:data"],
        location="Hardcoded in JavaScript",
        finding_id="finding-003",
        token_type="API Key"
    )

    # Log discovered private key
    tracker.add_private_key(
        key_type="RSA",
        key_length=2048,
        purpose="SSH access to production",
        location=".git/config",
        finding_id="finding-005",
        systems_accessible=["prod-db-01", "prod-api-server"]
    )

    # Finalize
    tracker.finalize()

    # Export summary
    report_path = tracker.export_summary()
    print(f"\n[+] Report saved to: {report_path}")
    print(f"[+] Metadata saved to: {os.path.join(tracker.output_dir, 'sensitive_data_metadata.json')}")
