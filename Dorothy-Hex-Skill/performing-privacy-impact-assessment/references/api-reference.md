# API Reference: Performing Privacy Impact Assessment

## PrivacyImpactAssessmentEngine

Core engine for automated PIA/DPIA workflows.

### Initialization

```python
from agent import PrivacyImpactAssessmentEngine

engine = PrivacyImpactAssessmentEngine(
    organization_name="Acme Corp",
    dpo_email="dpo@acme.com",
)
```

### register_processing_activity()

Register a processing activity for assessment.

```python
activity = engine.register_processing_activity(
    name="Customer Analytics",                    # Required
    description="Behavioral analytics pipeline",  # Required
    data_controller="Acme Corp",                  # Controller name
    data_processor="CloudAnalytics Inc",          # Processor name
    data_categories=["email", "ip_address"],      # List of data types
    data_subjects=["customers"],                  # Affected individuals
    legal_basis="consent",                        # consent|contract|legal_obligation|
                                                  # vital_interests|public_task|legitimate_interest
    retention_period_days=365,                    # Days before deletion
    cross_border_transfer=True,                   # International transfer
    transfer_destinations=["US", "IN"],           # ISO country codes
    automated_decision_making=False,              # Profiling/auto-decisions
)
# Returns: dict with activity_id, sensitivity_profile, etc.
```

**Supported data_categories:**

| Category | Sensitivity | Weight |
|----------|------------|--------|
| health_data, biometric_data, genetic_data | special_category | 5 |
| ssn, financial_account, credit_card, login_credentials | high | 4 |
| email, phone_number, ip_address, geolocation | medium | 3 |
| name, job_title, browsing_history, device_id | low | 2 |
| cookie_id, public_profile | low | 1 |

### map_data_flows()

Map data flows through the processing lifecycle.

```python
flow_map = engine.map_data_flows(
    activity_id="PA-XXXXXXXX",
    flows=[
        {
            "stage": "collection",       # collection|processing|storage|sharing|deletion
            "source": "Web form",
            "destination": "API server",
            "data_elements": ["email", "name"],
            "encryption_in_transit": True,
            "encryption_at_rest": False,
            "protocol": "TLS 1.3",
            "cross_border": False,
            "data_processing_agreement": False,
        },
    ],
)
```

### assess_privacy_risks()

Run risk assessment with scoring matrix.

```python
risk_report = engine.assess_privacy_risks(
    activity_id="PA-XXXXXXXX",
    assessment_type="full_dpia",  # full_dpia|screening|targeted
)
```

**Risk Scoring Matrix:**

| Score | Severity |
|-------|----------|
| 20-25 | CRITICAL |
| 15-19 | HIGH |
| 10-14 | MEDIUM |
| 5-9 | LOW |
| 1-4 | INFORMATIONAL |

Score = Likelihood (1-5) x Impact (1-5)

**Risk Categories Evaluated:**

| ID | Category | Description |
|----|----------|-------------|
| RISK-001 | Data Minimization | Excessive collection beyond purpose |
| RISK-002 | Purpose Limitation | Undefined or exceeded purposes |
| RISK-003 | Cross-Border Transfer | Transfer without safeguards |
| RISK-004 | Automated Decision Making | No human oversight |
| RISK-005 | Data Subject Rights | Missing DSR mechanisms |
| RISK-006 | Third-Party Risk | Processor compliance gaps |
| RISK-007 | Security Controls | Encryption/access gaps |
| RISK-008 | Retention | Over-retention or no policy |
| RISK-009 | Consent Management | Ambiguous consent |
| RISK-010 | Breach Notification | No 72-hour capability |
| RISK-011 | Special Category Data | Missing Art. 9 basis |
| RISK-012 | Transparency | Incomplete privacy notice |
| RISK-013 | Vulnerable Data Subjects | Missing extra safeguards |
| RISK-014 | Data Quality | No accuracy measures |

### run_screening_checklist()

ICO DPIA screening to determine if full DPIA is required.

```python
result = engine.run_screening_checklist(
    uses_special_category_data=False,
    large_scale_processing=True,
    systematic_monitoring=True,
    automated_decision_making=False,
    cross_border_transfer=True,
    vulnerable_data_subjects=False,
    innovative_technology=False,
    denial_of_service_or_rights=False,
    evaluation_or_scoring=False,
    matching_or_combining_datasets=False,
)
# Returns: {"dpia_required": True, "triggers": [...], ...}
```

### check_gdpr_compliance()

Article-level GDPR compliance checks.

```python
gdpr_report = engine.check_gdpr_compliance(activity_id="PA-XXXXXXXX")
# Returns: compliance_score (0-100), findings per article
```

**GDPR Articles Checked:**

| Article | Title |
|---------|-------|
| Art. 5 | Principles (lawfulness, minimization, retention, etc.) |
| Art. 6 | Lawfulness of processing |
| Art. 7 | Conditions for consent |
| Art. 13 | Information at collection |
| Art. 22 | Automated decision-making |
| Art. 25 | Data protection by design |
| Art. 28 | Processor obligations |
| Art. 30 | Records of processing |
| Art. 32 | Security of processing |
| Art. 33 | Breach notification |
| Art. 35 | DPIA requirements |
| Art. 44 | Transfer safeguards |

### check_ccpa_compliance()

CCPA/CPRA section-level compliance checks.

```python
ccpa_report = engine.check_ccpa_compliance(activity_id="PA-XXXXXXXX")
# Returns: compliance_score (0-100), findings per section
```

**CCPA Sections Checked:**

| Section | Title |
|---------|-------|
| 1798.100 | Right to know |
| 1798.105 | Right to delete |
| 1798.106 | Right to correct |
| 1798.110 | Right to specific PI |
| 1798.115 | Right to know about selling/sharing |
| 1798.120 | Right to opt-out |
| 1798.121 | Limit use of sensitive PI |
| 1798.125 | Non-discrimination |
| 1798.130 | Notice and request handling |
| 1798.135 | Do Not Sell link |
| 1798.185 | CPRA risk assessment |

### generate_nist_privacy_profile()

Map activity against NIST Privacy Framework functions.

```python
profile = engine.generate_nist_privacy_profile(
    activity_id="PA-XXXXXXXX",
    target_tier="tier_3",  # tier_1|tier_2|tier_3|tier_4
)
# Returns: coverage per function (ID-P, GV-P, CT-P, CM-P, PR-P)
```

### generate_remediation_plan()

Prioritized remediation action items.

```python
plan = engine.generate_remediation_plan(
    activity_id="PA-XXXXXXXX",
    risk_report=risk_report,
    gdpr_report=gdpr_report,
    ccpa_report=ccpa_report,
)
```

**Priority Levels:**

| Priority | Severity | Deadline |
|----------|----------|----------|
| P1 | CRITICAL | 14 days |
| P2 | HIGH | 30 days |
| P3 | MEDIUM | 60 days |
| P4 | LOW | 90 days |

### generate_dpia_report()

Generate formal DPIA report document.

```python
engine.generate_dpia_report(
    activity_id="PA-XXXXXXXX",
    output_path="dpia_report.json",
    format="json",
)
```

## CLI Usage

```bash
# Run demonstration workflow
python agent.py --action demo --org "Acme Corp" --output report.json

# Run screening checklist
python agent.py --action screening

# Specify DPO email
python agent.py --action demo --dpo-email dpo@acme.com --output dpia.json
```

## References

- ICO DPIA Guidance: https://ico.org.uk/for-organisations/uk-gdpr-guidance-and-resources/accountability-and-governance/data-protection-impact-assessments-dpias/
- NIST Privacy Framework: https://www.nist.gov/privacy-framework
- NIST PRAM: https://www.nist.gov/itl/applied-cybersecurity/privacy-engineering/collaboration-space/privacy-risk-assessment
- GDPR Full Text: https://gdpr-info.eu/
- CCPA Full Text: https://oag.ca.gov/privacy/ccpa
- IAPP PIA Template: https://iapp.org/resources/article/private-sector-privacy-impact-assessment-template/
