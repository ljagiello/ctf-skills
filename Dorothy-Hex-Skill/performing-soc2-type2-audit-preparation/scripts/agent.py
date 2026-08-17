#!/usr/bin/env python3
"""Agent for SOC 2 Type II audit preparation, evidence collection, and compliance monitoring."""

import os
import sys
import json
import argparse
from datetime import datetime, timedelta, timezone

import requests

try:
    import boto3
except ImportError:
    boto3 = None

try:
    import yaml
except ImportError:
    yaml = None


# AICPA Trust Services Criteria - Common Criteria (CC1-CC9)
TRUST_SERVICES_CRITERIA = {
    "CC1": {
        "name": "Control Environment",
        "description": "Organization demonstrates commitment to integrity, ethical values, oversight, structure, authority, responsibility, and competence.",
        "controls": {
            "CC1.1": "Demonstrates commitment to integrity and ethical values",
            "CC1.2": "Board exercises oversight responsibility",
            "CC1.3": "Management establishes structure, authority, and responsibility",
            "CC1.4": "Demonstrates commitment to competence",
            "CC1.5": "Enforces accountability",
        },
    },
    "CC2": {
        "name": "Communication and Information",
        "description": "Organization communicates internal and external information necessary to support the functioning of internal control.",
        "controls": {
            "CC2.1": "Obtains or generates relevant quality information",
            "CC2.2": "Internally communicates information including objectives and responsibilities",
            "CC2.3": "Communicates with external parties regarding matters affecting functioning of internal control",
        },
    },
    "CC3": {
        "name": "Risk Assessment",
        "description": "Organization identifies risks to the achievement of objectives and analyzes risks to determine how they should be managed.",
        "controls": {
            "CC3.1": "Specifies objectives with clarity to enable identification of risks",
            "CC3.2": "Identifies risks to achievement of objectives and analyzes them",
            "CC3.3": "Considers potential for fraud in assessing risks",
            "CC3.4": "Identifies and assesses changes that could impact internal control",
        },
    },
    "CC4": {
        "name": "Monitoring Activities",
        "description": "Organization selects, develops, and performs evaluations to ascertain whether controls are present and functioning.",
        "controls": {
            "CC4.1": "Selects, develops, and performs ongoing and separate evaluations",
            "CC4.2": "Evaluates and communicates internal control deficiencies in a timely manner",
        },
    },
    "CC5": {
        "name": "Control Activities",
        "description": "Organization deploys control activities through policies and procedures that put directives into actions.",
        "controls": {
            "CC5.1": "Selects and develops control activities that contribute to mitigation of risks",
            "CC5.2": "Selects and develops general controls over technology",
            "CC5.3": "Deploys control activities through policies and procedures",
        },
    },
    "CC6": {
        "name": "Logical and Physical Access Controls",
        "description": "Organization restricts logical and physical access to information assets.",
        "controls": {
            "CC6.1": "Implements logical access security software, infrastructure, and architectures",
            "CC6.2": "Prior to issuing system credentials, registers and authorizes new users",
            "CC6.3": "Removes access to protected information assets when appropriate",
            "CC6.4": "Restricts physical access to facilities and protected information assets",
            "CC6.5": "Implements controls to prevent and detect unauthorized access",
            "CC6.6": "Manages points of interaction with external systems",
            "CC6.7": "Restricts the transmission, movement, and removal of information",
            "CC6.8": "Implements controls to prevent or detect unauthorized or malicious software",
        },
    },
    "CC7": {
        "name": "System Operations",
        "description": "Organization detects and monitors system components and anomalies that represent events.",
        "controls": {
            "CC7.1": "Detects and monitors system configuration changes and new vulnerabilities",
            "CC7.2": "Monitors system components for anomalies indicative of malicious acts",
            "CC7.3": "Evaluates detected events and determines whether they constitute incidents",
            "CC7.4": "Responds to identified security incidents",
            "CC7.5": "Identifies, develops, and implements activities to recover from incidents",
        },
    },
    "CC8": {
        "name": "Change Management",
        "description": "Organization authorizes, designs, develops, configures, documents, tests, approves, and implements changes.",
        "controls": {
            "CC8.1": "Authorizes, designs, develops, configures, documents, tests, approves, and implements changes to infrastructure and software",
        },
    },
    "CC9": {
        "name": "Risk Mitigation",
        "description": "Organization identifies, selects, and develops risk mitigation activities for risks arising from business disruption and use of vendors.",
        "controls": {
            "CC9.1": "Identifies and assesses risk mitigation activities for risks from business disruptions",
            "CC9.2": "Assesses and manages risks associated with vendors and business partners",
        },
    },
}


def perform_gap_assessment(controls_status):
    """Perform a gap assessment against all Trust Services Criteria CC1-CC9."""
    results = {
        "assessment_date": datetime.now(timezone.utc).isoformat(),
        "summary": {
            "total_controls": 0, "implemented": 0, "partial": 0,
            "not_implemented": 0, "not_assessed": 0,
        },
        "gaps": [],
        "criteria_status": {},
    }

    for cc_id, cc_data in TRUST_SERVICES_CRITERIA.items():
        criteria_result = {"name": cc_data["name"], "controls": {}}
        for ctrl_id, ctrl_desc in cc_data["controls"].items():
            results["summary"]["total_controls"] += 1
            status_info = controls_status.get(ctrl_id, {})
            status = status_info.get("status", "not_assessed")

            criteria_result["controls"][ctrl_id] = {
                "description": ctrl_desc,
                "status": status,
                "evidence": status_info.get("evidence", ""),
                "gap": status_info.get("gap", ""),
                "owner": status_info.get("owner", ""),
                "due_date": status_info.get("due_date", ""),
            }

            if status == "implemented":
                results["summary"]["implemented"] += 1
            elif status == "partial":
                results["summary"]["partial"] += 1
                results["gaps"].append({
                    "control": ctrl_id, "criteria": cc_id,
                    "description": ctrl_desc,
                    "gap": status_info.get("gap", ""),
                    "severity": "medium",
                })
            elif status == "not_implemented":
                results["summary"]["not_implemented"] += 1
                results["gaps"].append({
                    "control": ctrl_id, "criteria": cc_id,
                    "description": ctrl_desc,
                    "gap": status_info.get("gap", ""),
                    "severity": "high",
                })
            else:
                results["summary"]["not_assessed"] += 1

        results["criteria_status"][cc_id] = criteria_result

    total = results["summary"]["total_controls"]
    implemented = results["summary"]["implemented"]
    results["summary"]["readiness_score"] = (
        round((implemented / total) * 100, 1) if total > 0 else 0
    )
    return results


def collect_aws_iam_evidence():
    """Collect AWS IAM evidence for CC6 (Access Controls)."""
    if boto3 is None:
        return {"status": "error", "error": "boto3 not installed"}

    iam = boto3.client("iam")
    evidence = {
        "collected_at": datetime.now(timezone.utc).isoformat(),
        "criteria": "CC6",
        "type": "aws_iam",
    }

    try:
        users = iam.list_users()["Users"]
        user_details = []
        users_without_mfa = []

        for user in users:
            mfa_devices = iam.list_mfa_devices(UserName=user["UserName"])
            has_mfa = len(mfa_devices["MFADevices"]) > 0
            user_info = {
                "username": user["UserName"],
                "created": user["CreateDate"].isoformat(),
                "mfa_enabled": has_mfa,
                "arn": user["Arn"],
            }
            if "PasswordLastUsed" in user:
                user_info["password_last_used"] = user["PasswordLastUsed"].isoformat()
            user_details.append(user_info)
            if not has_mfa:
                users_without_mfa.append(user["UserName"])

        evidence["users"] = {
            "total": len(users),
            "with_mfa": len(users) - len(users_without_mfa),
            "without_mfa": len(users_without_mfa),
            "mfa_compliance_rate": round(
                ((len(users) - len(users_without_mfa)) / max(len(users), 1)) * 100, 1
            ),
            "users_without_mfa": users_without_mfa,
            "details": user_details,
        }
    except Exception as e:
        evidence["users"] = {"error": str(e)}

    try:
        policy = iam.get_account_password_policy()["PasswordPolicy"]
        evidence["password_policy"] = {
            "minimum_length": policy.get("MinimumPasswordLength", 0),
            "require_symbols": policy.get("RequireSymbols", False),
            "require_numbers": policy.get("RequireNumbers", False),
            "require_uppercase": policy.get("RequireUppercaseCharacters", False),
            "require_lowercase": policy.get("RequireLowercaseCharacters", False),
            "max_age_days": policy.get("MaxPasswordAge", 0),
            "password_reuse_prevention": policy.get("PasswordReusePrevention", 0),
        }
    except Exception as e:
        evidence["password_policy"] = {"error": str(e)}

    return evidence


def collect_aws_cloudtrail_evidence():
    """Collect AWS CloudTrail evidence for CC7 (System Operations)."""
    if boto3 is None:
        return {"status": "error", "error": "boto3 not installed"}

    ct = boto3.client("cloudtrail")
    evidence = {
        "collected_at": datetime.now(timezone.utc).isoformat(),
        "criteria": "CC7",
        "type": "aws_cloudtrail",
    }

    try:
        trails = ct.describe_trails()["trailList"]
        trail_details = []
        for trail in trails:
            status = ct.get_trail_status(Name=trail["TrailARN"])
            trail_details.append({
                "name": trail["Name"],
                "arn": trail["TrailARN"],
                "is_logging": status["IsLogging"],
                "multi_region": trail.get("IsMultiRegionTrail", False),
                "log_validation": trail.get("LogFileValidationEnabled", False),
                "s3_bucket": trail.get("S3BucketName", ""),
                "kms_key": trail.get("KmsKeyId", "none"),
            })
        evidence["trails"] = trail_details
        evidence["all_logging"] = all(t["is_logging"] for t in trail_details)
        evidence["all_multi_region"] = all(t["multi_region"] for t in trail_details)
    except Exception as e:
        evidence["trails"] = {"error": str(e)}

    return evidence


def collect_aws_s3_public_access_evidence():
    """Collect AWS S3 public access evidence for CC6 (Access Controls)."""
    if boto3 is None:
        return {"status": "error", "error": "boto3 not installed"}

    s3 = boto3.client("s3")
    evidence = {
        "collected_at": datetime.now(timezone.utc).isoformat(),
        "criteria": "CC6",
        "type": "aws_s3_public_access",
    }

    try:
        buckets = s3.list_buckets()["Buckets"]
        bucket_details = []
        public_buckets = []

        for bucket in buckets:
            name = bucket["Name"]
            try:
                pab = s3.get_public_access_block(Bucket=name)
                cfg = pab["PublicAccessBlockConfiguration"]
                is_public_blocked = all([
                    cfg.get("BlockPublicAcls", False),
                    cfg.get("IgnorePublicAcls", False),
                    cfg.get("BlockPublicPolicy", False),
                    cfg.get("RestrictPublicBuckets", False),
                ])
            except Exception:
                is_public_blocked = False

            try:
                encryption = s3.get_bucket_encryption(Bucket=name)
                has_encryption = True
                enc_algorithm = (
                    encryption["ServerSideEncryptionConfiguration"]["Rules"][0]
                    ["ApplyServerSideEncryptionByDefault"]["SSEAlgorithm"]
                )
            except Exception:
                has_encryption = False
                enc_algorithm = "none"

            bucket_details.append({
                "name": name,
                "created": bucket["CreationDate"].isoformat(),
                "public_access_blocked": is_public_blocked,
                "encrypted": has_encryption,
                "encryption_algorithm": enc_algorithm,
            })
            if not is_public_blocked:
                public_buckets.append(name)

        evidence["buckets"] = {
            "total": len(buckets),
            "public_access_blocked": len(buckets) - len(public_buckets),
            "potentially_public": len(public_buckets),
            "public_bucket_names": public_buckets,
            "details": bucket_details,
        }
    except Exception as e:
        evidence["buckets"] = {"error": str(e)}

    return evidence


def collect_github_change_management_evidence(org, repo, token, since=None):
    """Collect GitHub PR evidence for CC8 (Change Management)."""
    if since is None:
        since = (datetime.now(timezone.utc) - timedelta(days=90)).isoformat()

    headers = {
        "Authorization": "token " + token,
        "Accept": "application/vnd.github.v3+json",
    }
    evidence = {
        "collected_at": datetime.now(timezone.utc).isoformat(),
        "criteria": "CC8",
        "type": "github_change_management",
        "repository": org + "/" + repo,
    }

    try:
        page = 1
        all_prs = []
        while page <= 10:
            resp = requests.get(
                "https://api.github.com/repos/" + org + "/" + repo + "/pulls",
                params={
                    "state": "closed", "base": "main",
                    "per_page": 100, "page": page,
                    "sort": "updated", "direction": "desc",
                },
                headers=headers, timeout=30,
            )
            resp.raise_for_status()
            prs = resp.json()
            if not prs:
                break
            for pr in prs:
                if pr.get("merged_at") and pr["merged_at"] >= since:
                    all_prs.append(pr)
            page += 1

        pr_details = []
        prs_without_approval = []
        for pr in all_prs:
            reviews_resp = requests.get(
                pr["url"] + "/reviews", headers=headers, timeout=15,
            )
            reviews = reviews_resp.json() if reviews_resp.ok else []
            approved = any(r["state"] == "APPROVED" for r in reviews)
            reviewers = list({r["user"]["login"] for r in reviews if "user" in r})

            pr_details.append({
                "number": pr["number"],
                "title": pr["title"],
                "author": pr["user"]["login"],
                "merged_at": pr["merged_at"],
                "approved": approved,
                "reviewers": reviewers,
                "additions": pr.get("additions", 0),
                "deletions": pr.get("deletions", 0),
            })
            if not approved:
                prs_without_approval.append(pr["number"])

        total = len(pr_details)
        approved_count = total - len(prs_without_approval)
        evidence["pull_requests"] = {
            "total_merged": total,
            "with_approval": approved_count,
            "without_approval": len(prs_without_approval),
            "approval_rate": round((approved_count / max(total, 1)) * 100, 1),
            "exceptions": prs_without_approval,
            "details": pr_details,
        }
    except Exception as e:
        evidence["pull_requests"] = {"error": str(e)}

    return evidence


def collect_branch_protection_evidence(org, repo, token):
    """Collect GitHub branch protection evidence for CC8."""
    headers = {
        "Authorization": "token " + token,
        "Accept": "application/vnd.github.v3+json",
    }
    evidence = {
        "collected_at": datetime.now(timezone.utc).isoformat(),
        "criteria": "CC8",
        "type": "github_branch_protection",
    }

    try:
        resp = requests.get(
            "https://api.github.com/repos/" + org + "/" + repo + "/branches/main/protection",
            headers=headers, timeout=15,
        )
        if resp.status_code == 200:
            protection = resp.json()
            pr_reviews = protection.get("required_pull_request_reviews", {})
            evidence["main_branch"] = {
                "protected": True,
                "required_reviews": pr_reviews.get("required_approving_review_count", 0),
                "dismiss_stale_reviews": pr_reviews.get("dismiss_stale_reviews", False),
                "require_code_owner_reviews": pr_reviews.get("require_code_owner_reviews", False),
                "status_checks_required": protection.get("required_status_checks", {}).get("strict", False),
                "enforce_admins": protection.get("enforce_admins", {}).get("enabled", False),
            }
        elif resp.status_code == 404:
            evidence["main_branch"] = {
                "protected": False,
                "gap": "No branch protection configured",
            }
        else:
            evidence["main_branch"] = {"error": "HTTP " + str(resp.status_code)}
    except Exception as e:
        evidence["main_branch"] = {"error": str(e)}

    return evidence


def run_continuous_compliance_checks(aws_enabled=True):
    """Run a suite of continuous compliance checks and return findings."""
    findings = {
        "check_time": datetime.now(timezone.utc).isoformat(),
        "checks": [], "passing": 0, "failing": 0, "errors": 0,
    }
    checks = []

    if aws_enabled and boto3 is not None:
        # CC6.1: MFA enforcement
        try:
            iam = boto3.client("iam")
            users = iam.list_users()["Users"]
            users_without_mfa = []
            for user in users:
                mfa_devices = iam.list_mfa_devices(UserName=user["UserName"])
                if not mfa_devices["MFADevices"]:
                    users_without_mfa.append(user["UserName"])
            checks.append({
                "control": "CC6.1",
                "check": "All IAM users have MFA enabled",
                "passing": len(users_without_mfa) == 0,
                "details": {"total_users": len(users), "without_mfa": users_without_mfa},
            })
        except Exception as e:
            checks.append({
                "control": "CC6.1",
                "check": "All IAM users have MFA enabled",
                "passing": None, "error": str(e),
            })

        # CC6.6: No public S3 buckets
        try:
            s3 = boto3.client("s3")
            buckets = s3.list_buckets()["Buckets"]
            public_buckets = []
            for bucket in buckets:
                try:
                    pab = s3.get_public_access_block(Bucket=bucket["Name"])
                    cfg = pab["PublicAccessBlockConfiguration"]
                    if not all([
                        cfg.get("BlockPublicAcls", False),
                        cfg.get("IgnorePublicAcls", False),
                        cfg.get("BlockPublicPolicy", False),
                        cfg.get("RestrictPublicBuckets", False),
                    ]):
                        public_buckets.append(bucket["Name"])
                except Exception:
                    public_buckets.append(bucket["Name"])
            checks.append({
                "control": "CC6.6",
                "check": "No public S3 buckets",
                "passing": len(public_buckets) == 0,
                "details": {"public_buckets": public_buckets},
            })
        except Exception as e:
            checks.append({
                "control": "CC6.6",
                "check": "No public S3 buckets",
                "passing": None, "error": str(e),
            })

        # CC7.1: CloudTrail logging enabled
        try:
            ct = boto3.client("cloudtrail")
            trails = ct.describe_trails()["trailList"]
            inactive_trails = []
            for trail in trails:
                status = ct.get_trail_status(Name=trail["TrailARN"])
                if not status["IsLogging"]:
                    inactive_trails.append(trail["Name"])
            checks.append({
                "control": "CC7.1",
                "check": "CloudTrail logging enabled on all trails",
                "passing": len(inactive_trails) == 0,
                "details": {"inactive_trails": inactive_trails},
            })
        except Exception as e:
            checks.append({
                "control": "CC7.1",
                "check": "CloudTrail logging enabled on all trails",
                "passing": None, "error": str(e),
            })

    findings["checks"] = checks
    for check in checks:
        if check.get("passing") is True:
            findings["passing"] += 1
        elif check.get("passing") is False:
            findings["failing"] += 1
        else:
            findings["errors"] += 1

    total = findings["passing"] + findings["failing"]
    findings["compliance_score"] = round(
        (findings["passing"] / max(total, 1)) * 100, 1
    )
    return findings


def generate_remediation_plan(gap_assessment):
    """Generate a prioritized remediation plan from gap assessment results."""
    plan = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total_gaps": len(gap_assessment.get("gaps", [])),
        "remediation_items": [],
    }

    severity_priority = {"high": 1, "medium": 2, "low": 3}
    sorted_gaps = sorted(
        gap_assessment.get("gaps", []),
        key=lambda g: severity_priority.get(g.get("severity", "low"), 3),
    )

    remediation_map = {
        "CC1": (["Draft information security policy", "Establish security committee charter", "Create security awareness training", "Document org structure"], "2-4 weeks"),
        "CC2": (["Publish security policy to all staff", "Document system boundaries", "Establish external communication procedures"], "2-4 weeks"),
        "CC3": (["Conduct formal risk assessment", "Create risk register with owners", "Document fraud risk analysis", "Assess change impacts"], "4-8 weeks"),
        "CC4": (["Implement continuous control monitoring", "Establish internal audit program", "Create deficiency tracking process"], "3-6 weeks"),
        "CC5": (["Map policies to procedures", "Deploy technology controls", "Create control activities documentation"], "3-6 weeks"),
        "CC6": (["Enforce MFA across all accounts", "Automate access provisioning/deprovisioning", "Establish quarterly access reviews", "Deploy encryption at rest and in transit"], "2-4 weeks"),
        "CC7": (["Enable CloudTrail/audit logging everywhere", "Deploy SIEM with anomaly alerting", "Implement weekly vulnerability scanning", "Document and test IR procedures"], "3-6 weeks"),
        "CC8": (["Enforce branch protection with required reviews", "Implement CI/CD with automated testing", "Create change advisory board process", "Document emergency change procedures"], "1-3 weeks"),
        "CC9": (["Implement vendor risk management program", "Create BCP and DR plans", "Conduct annual DR testing", "Collect vendor SOC 2 reports"], "4-8 weeks"),
    }

    for i, gap in enumerate(sorted_gaps, 1):
        actions, effort = remediation_map.get(
            gap["criteria"],
            (["Review and implement appropriate controls"], "2-4 weeks"),
        )
        plan["remediation_items"].append({
            "priority": i,
            "control": gap["control"],
            "criteria": gap["criteria"],
            "description": gap["description"],
            "severity": gap.get("severity", "medium"),
            "recommended_actions": actions,
            "estimated_effort": effort,
        })

    return plan


def generate_evidence_manifest(audit_start, audit_end):
    """Generate a manifest of required evidence packages organized by criteria."""
    manifest = {
        "audit_period": {"start": audit_start, "end": audit_end},
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "evidence_packages": {},
    }

    evidence_map = {
        "CC1": [
            {"name": "Code of Conduct Acknowledgments", "source": "HR system", "frequency": "annual"},
            {"name": "Board Meeting Minutes", "source": "Board secretary", "frequency": "quarterly"},
            {"name": "Organizational Chart", "source": "HR system", "frequency": "annual"},
            {"name": "Background Check Policy", "source": "HR system", "frequency": "annual"},
            {"name": "Security Training Completion Records", "source": "LMS", "frequency": "annual"},
        ],
        "CC2": [
            {"name": "Information Security Policy", "source": "Policy repo", "frequency": "annual"},
            {"name": "System Description Document", "source": "Engineering", "frequency": "annual"},
        ],
        "CC3": [
            {"name": "Risk Assessment Report", "source": "GRC platform", "frequency": "annual"},
            {"name": "Risk Register", "source": "GRC platform", "frequency": "quarterly"},
        ],
        "CC4": [
            {"name": "Control Monitoring Dashboard", "source": "Compliance platform", "frequency": "monthly"},
            {"name": "Internal Audit Reports", "source": "Internal audit", "frequency": "annual"},
        ],
        "CC5": [
            {"name": "IT General Controls Matrix", "source": "GRC platform", "frequency": "annual"},
        ],
        "CC6": [
            {"name": "IAM User MFA Status", "source": "AWS IAM / Okta", "frequency": "daily"},
            {"name": "Access Provisioning Tickets", "source": "Jira/ServiceNow", "frequency": "continuous"},
            {"name": "Quarterly Access Reviews", "source": "IAM system", "frequency": "quarterly"},
            {"name": "Terminated User Access Removal", "source": "HR + IAM", "frequency": "continuous"},
            {"name": "S3 Public Access Report", "source": "AWS S3", "frequency": "daily"},
            {"name": "Encryption Configuration", "source": "AWS KMS", "frequency": "daily"},
            {"name": "Password Policy Config", "source": "AWS IAM / Okta", "frequency": "monthly"},
        ],
        "CC7": [
            {"name": "CloudTrail Logging Status", "source": "AWS CloudTrail", "frequency": "daily"},
            {"name": "SIEM Alert Summaries", "source": "SIEM", "frequency": "monthly"},
            {"name": "Vulnerability Scan Reports", "source": "Scanner", "frequency": "weekly"},
            {"name": "Incident Response Reports", "source": "IR team", "frequency": "per-incident"},
            {"name": "GuardDuty Findings", "source": "AWS GuardDuty", "frequency": "daily"},
        ],
        "CC8": [
            {"name": "PR Approval Records", "source": "GitHub", "frequency": "continuous"},
            {"name": "Branch Protection Config", "source": "GitHub", "frequency": "monthly"},
            {"name": "CI/CD Pipeline Config", "source": "GitHub Actions", "frequency": "monthly"},
        ],
        "CC9": [
            {"name": "Vendor Risk Assessments", "source": "GRC platform", "frequency": "annual"},
            {"name": "Business Continuity Plan", "source": "BCP team", "frequency": "annual"},
            {"name": "DR Test Results", "source": "Engineering", "frequency": "annual"},
            {"name": "Vendor SOC 2 Reports", "source": "Vendors", "frequency": "annual"},
        ],
    }

    for cc_id, items in evidence_map.items():
        criteria_name = TRUST_SERVICES_CRITERIA.get(cc_id, {}).get("name", cc_id)
        manifest["evidence_packages"][cc_id] = {
            "criteria_name": criteria_name,
            "evidence_items": items,
            "item_count": len(items),
        }

    manifest["total_evidence_items"] = sum(
        pkg["item_count"] for pkg in manifest["evidence_packages"].values()
    )
    return manifest


def generate_readiness_report(gap_assessment=None, compliance_checks=None):
    """Generate a comprehensive audit readiness report."""
    report = {
        "report_type": "SOC 2 Type II Audit Readiness",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "overall_readiness": "unknown",
        "sections": {},
    }

    if gap_assessment:
        report["sections"]["gap_assessment"] = {
            "readiness_score": gap_assessment["summary"]["readiness_score"],
            "total_controls": gap_assessment["summary"]["total_controls"],
            "implemented": gap_assessment["summary"]["implemented"],
            "gaps_remaining": len(gap_assessment["gaps"]),
            "high_severity_gaps": len(
                [g for g in gap_assessment["gaps"] if g["severity"] == "high"]
            ),
        }

    if compliance_checks:
        report["sections"]["continuous_compliance"] = {
            "compliance_score": compliance_checks["compliance_score"],
            "checks_passing": compliance_checks["passing"],
            "checks_failing": compliance_checks["failing"],
            "checks_errored": compliance_checks["errors"],
        }

    scores = []
    if gap_assessment:
        scores.append(gap_assessment["summary"]["readiness_score"])
    if compliance_checks:
        scores.append(compliance_checks["compliance_score"])

    if scores:
        avg_score = sum(scores) / len(scores)
        if avg_score >= 90:
            report["overall_readiness"] = "ready"
        elif avg_score >= 70:
            report["overall_readiness"] = "conditionally_ready"
        elif avg_score >= 50:
            report["overall_readiness"] = "needs_work"
        else:
            report["overall_readiness"] = "not_ready"
        report["overall_score"] = round(avg_score, 1)

    return report


def main():
    parser = argparse.ArgumentParser(
        description="SOC 2 Type II Audit Preparation Agent"
    )
    parser.add_argument(
        "--action",
        choices=[
            "gap-assessment", "collect-aws-iam", "collect-aws-cloudtrail",
            "collect-aws-s3", "collect-github-changes", "collect-branch-protection",
            "compliance-checks", "remediation-plan", "evidence-manifest",
            "readiness-report", "list-criteria", "full-assessment",
        ],
        default="list-criteria",
    )
    parser.add_argument("--output", default="soc2_report.json")
    parser.add_argument("--github-org")
    parser.add_argument("--github-repo")
    parser.add_argument("--github-token", default=os.getenv("GITHUB_TOKEN"))
    parser.add_argument("--audit-start", default="2025-04-01")
    parser.add_argument("--audit-end", default="2026-03-31")
    parser.add_argument("--controls-file")
    parser.add_argument("--aws", action="store_true")
    args = parser.parse_args()

    report = {"generated_at": datetime.now(timezone.utc).isoformat(), "action": args.action}

    if args.action == "list-criteria":
        print("[*] AICPA Trust Services Criteria - Common Criteria (CC1-CC9):\n")
        for cc_id, cc_data in TRUST_SERVICES_CRITERIA.items():
            print("  " + cc_id + ": " + cc_data["name"])
            for ctrl_id, ctrl_desc in cc_data["controls"].items():
                print("       " + ctrl_id + ": " + ctrl_desc[:70])
            print()
        report["criteria"] = TRUST_SERVICES_CRITERIA

    elif args.action == "gap-assessment":
        controls_status = {}
        if args.controls_file and os.path.exists(args.controls_file):
            with open(args.controls_file) as f:
                controls_status = json.load(f)
        else:
            print("[!] No controls file provided. Run with --controls-file")
        result = perform_gap_assessment(controls_status)
        report["gap_assessment"] = result
        s = result["summary"]
        print("[+] Readiness Score: " + str(s["readiness_score"]) + "%")
        print("[+] Implemented: " + str(s["implemented"]) + "/" + str(s["total_controls"]))
        print("[+] Gaps: " + str(len(result["gaps"])))

    elif args.action == "collect-aws-iam":
        print("[+] Collecting AWS IAM evidence (CC6)...")
        result = collect_aws_iam_evidence()
        report["aws_iam_evidence"] = result

    elif args.action == "collect-aws-cloudtrail":
        print("[+] Collecting AWS CloudTrail evidence (CC7)...")
        result = collect_aws_cloudtrail_evidence()
        report["aws_cloudtrail_evidence"] = result

    elif args.action == "collect-aws-s3":
        print("[+] Collecting AWS S3 evidence (CC6)...")
        result = collect_aws_s3_public_access_evidence()
        report["aws_s3_evidence"] = result

    elif args.action == "collect-github-changes":
        if not all([args.github_org, args.github_repo, args.github_token]):
            print("[-] --github-org, --github-repo, and --github-token required")
            sys.exit(1)
        print("[+] Collecting GitHub change evidence...")
        result = collect_github_change_management_evidence(
            args.github_org, args.github_repo, args.github_token,
            since=args.audit_start,
        )
        report["github_change_evidence"] = result

    elif args.action == "collect-branch-protection":
        if not all([args.github_org, args.github_repo, args.github_token]):
            print("[-] --github-org, --github-repo, and --github-token required")
            sys.exit(1)
        result = collect_branch_protection_evidence(
            args.github_org, args.github_repo, args.github_token,
        )
        report["branch_protection_evidence"] = result

    elif args.action == "compliance-checks":
        print("[+] Running continuous compliance checks...")
        result = run_continuous_compliance_checks(aws_enabled=args.aws)
        report["compliance_checks"] = result
        print("[+] Compliance Score: " + str(result["compliance_score"]) + "%")
        for check in result["checks"]:
            p = check.get("passing")
            status = "PASS" if p is True else "FAIL" if p is False else "ERROR"
            print("    [" + status + "] " + check["control"] + ": " + check["check"])

    elif args.action == "remediation-plan":
        controls_status = {}
        if args.controls_file and os.path.exists(args.controls_file):
            with open(args.controls_file) as f:
                controls_status = json.load(f)
        gap = perform_gap_assessment(controls_status)
        plan = generate_remediation_plan(gap)
        report["remediation_plan"] = plan
        print("[+] Remediation plan: " + str(plan["total_gaps"]) + " items")
        for item in plan["remediation_items"]:
            print("    " + str(item["priority"]) + ". [" + item["severity"].upper() + "] " + item["control"])

    elif args.action == "evidence-manifest":
        manifest = generate_evidence_manifest(args.audit_start, args.audit_end)
        report["evidence_manifest"] = manifest
        print("[+] Evidence manifest: " + str(manifest["total_evidence_items"]) + " items")
        for cc_id, pkg in manifest["evidence_packages"].items():
            print("    " + cc_id + " (" + pkg["criteria_name"] + "): " + str(pkg["item_count"]) + " items")

    elif args.action == "readiness-report":
        controls_status = {}
        if args.controls_file and os.path.exists(args.controls_file):
            with open(args.controls_file) as f:
                controls_status = json.load(f)
        gap = perform_gap_assessment(controls_status)
        compliance = run_continuous_compliance_checks(aws_enabled=args.aws)
        readiness = generate_readiness_report(gap_assessment=gap, compliance_checks=compliance)
        report["readiness_report"] = readiness
        print("[+] Overall Readiness: " + readiness["overall_readiness"].upper())

    elif args.action == "full-assessment":
        print("[+] Running full SOC 2 Type II assessment...\n")
        controls_status = {}
        if args.controls_file and os.path.exists(args.controls_file):
            with open(args.controls_file) as f:
                controls_status = json.load(f)
        gap = perform_gap_assessment(controls_status)
        report["gap_assessment"] = gap
        print("[+] Gap Assessment - Readiness: " + str(gap["summary"]["readiness_score"]) + "%")

        manifest = generate_evidence_manifest(args.audit_start, args.audit_end)
        report["evidence_manifest"] = manifest
        print("[+] Evidence Manifest: " + str(manifest["total_evidence_items"]) + " items")

        compliance = run_continuous_compliance_checks(aws_enabled=args.aws)
        report["compliance_checks"] = compliance
        print("[+] Compliance Checks: " + str(compliance["compliance_score"]) + "%")

        plan = generate_remediation_plan(gap)
        report["remediation_plan"] = plan
        print("[+] Remediation Items: " + str(plan["total_gaps"]))

        readiness = generate_readiness_report(gap_assessment=gap, compliance_checks=compliance)
        report["readiness_report"] = readiness
        print("\n[+] OVERALL READINESS: " + readiness["overall_readiness"].upper())
        if "overall_score" in readiness:
            print("[+] OVERALL SCORE: " + str(readiness["overall_score"]) + "%")

    with open(args.output, "w") as f:
        json.dump(report, f, indent=2, default=str)
    print("\n[+] Report saved to " + args.output)


if __name__ == "__main__":
    main()
