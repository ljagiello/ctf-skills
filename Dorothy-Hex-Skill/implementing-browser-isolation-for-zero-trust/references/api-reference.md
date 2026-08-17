# API Reference: Implementing Browser Isolation for Zero Trust

## BrowserIsolationPolicyEngine

Core engine for managing browser isolation policies, CDR processing, and Zero Trust integration.

### Initialization

```python
from agent import BrowserIsolationPolicyEngine

engine = BrowserIsolationPolicyEngine(
    organization="Acme Corp",
    default_isolation_mode="isolate_risky",  # isolate_risky | isolate_all | allow_all
)
```

### classify_url()

Classify a URL by category and risk level.

```python
result = engine.classify_url(
    url="https://docs.google.com/spreadsheets/d/abc",
    referrer=None,  # Optional referrer URL
)
# Returns: {url, domain, category, risk_level, risk_weight, action, reason}
```

**URL Categories:**

| Category | Risk Weight | Example Domains |
|----------|------------|-----------------|
| cloud_productivity | 1 | docs.google.com, office365.com, dropbox.com |
| business_saas | 1 | salesforce.com, slack.com, github.com |
| search_engines | 1 | google.com, bing.com, duckduckgo.com |
| developer_tools | 2 | stackoverflow.com, npmjs.com, pypi.org |
| news_media | 2 | cnn.com, bbc.com, reuters.com |
| social_media | 3 | facebook.com, twitter.com, linkedin.com |
| webmail | 3 | mail.google.com, outlook.live.com |
| ai_tools | 3 | chat.openai.com, claude.ai |
| file_sharing | 4 | wetransfer.com, mega.nz, mediafire.com |
| admin_console | 4 | console.aws.amazon.com, portal.azure.com |
| newly_registered | 5 | (domains < 30 days old) |
| uncategorized | 5 | (unknown domains) |
| phishing | 5 | (pattern-matched phishing URLs) |
| malware_hosting | 5 | (threat intel flagged domains) |

**Risk Levels:**

| Weight | Level | Default Action |
|--------|-------|----------------|
| 1 | low | allow_direct |
| 2 | low | allow_direct |
| 3 | medium | full_isolation |
| 4 | high | full_isolation |
| 5 | critical | block |

### add_isolation_policy()

Add an isolation policy with match criteria and controls.

```python
policy = engine.add_isolation_policy(
    name="Policy Name",                    # Required
    description="Policy description",
    match_criteria={
        "url_categories": ["webmail"],     # URL categories to match
        "risk_levels": ["medium", "high"], # Risk levels to match
        "domains": ["*.example.com"],      # Specific domains (supports wildcards)
        "referrer_categories": ["email"],  # Referrer URL categories
        "file_types": ["pdf", "docx"],     # File type triggers
        "user_groups": ["contractors"],    # User group membership
    },
    isolation_mode="full_isolation",       # See Isolation Modes below
    dlp_controls={                         # See DLP Controls below
        "disable_copy_paste": True,
        "disable_download": True,
    },
    cdr_config={                           # CDR config (for cdr_passthrough mode)
        "strip_macros": True,
        "strip_embedded_objects": True,
        "strip_javascript": True,
    },
    priority=1,                            # Lower = higher priority
)
```

**Isolation Modes:**

| Mode | Description | Code on Endpoint | Network Isolated |
|------|-------------|-----------------|-----------------|
| full_isolation | Pixel-streaming RBI | No | Yes |
| dom_reconstruction | Sanitized DOM mirror | No | Yes |
| read_only_isolation | Pixel stream, input restricted | No | Yes |
| cdr_passthrough | Direct browse, CDR for files | Yes | No |
| allow_direct | No isolation (trusted) | Yes | No |
| block | Access denied | No | Yes |

**DLP Controls:**

| Control | Type | Default | Description |
|---------|------|---------|-------------|
| disable_copy_paste | bool | false | Block clipboard operations |
| disable_download | bool | false | Block file downloads |
| disable_upload | bool | false | Block file uploads |
| disable_printing | bool | false | Block printing |
| disable_keyboard_input | bool | false | Block all keyboard input |
| watermark_session | bool | false | Apply visual watermark with user ID |
| record_session | bool | false | Record full session for audit |
| log_all_downloads | bool | true | Log download events to SIEM |
| log_clipboard_events | bool | true | Log clipboard operations |
| log_file_uploads | bool | true | Log upload events |
| max_download_size_mb | int | 100 | Maximum download size |
| blocked_upload_types | list | [exe,bat,...] | File types blocked from upload |

### process_file_cdr()

Process a file through Content Disarm and Reconstruction.

```python
result = engine.process_file_cdr(
    file_path="/path/to/file.docx",
    source_url="https://example.com/file.docx",  # Optional
    cdr_profile="strict",  # strict | standard | permissive
)
```

**CDR Profiles:**

| Profile | Strips | Use Case |
|---------|--------|----------|
| strict | All threat types (high, medium, low) | High-security environments |
| standard | High and critical severity threats | General business use |
| permissive | Critical severity only | Low-risk trusted sources |

**CDR Threat Types Detected:**

| Type | Severity | File Types |
|------|----------|------------|
| macro | high | docx, xlsx, pptx, doc, xls |
| embedded_ole | high | docx, xlsx, pptx, pdf, rtf |
| javascript_pdf | high | pdf |
| external_link | medium | docx, xlsx, pptx |
| embedded_executable | critical | pdf, docx, zip, rar |
| dde_exploit | high | docx, xlsx, csv |
| hidden_content | low | docx, xlsx, pptx, pdf |
| metadata_leak | low | docx, xlsx, pdf, jpg, png |

**CDR-Supported File Types:**

| Supported (reconstructed) | Blocked (quarantined) |
|--------------------------|----------------------|
| pdf, docx, xlsx, pptx | exe, msi, dll |
| doc, xls, ppt, rtf, csv | bat, ps1, sh |
| zip, rar, 7z | iso |
| png, jpg, gif, svg, html | |

### batch_cdr_process()

Process multiple files through CDR.

```python
result = engine.batch_cdr_process(
    files=["/path/file1.pdf", "/path/file2.docx"],
    cdr_profile="strict",
    quarantine_on_threat=True,
)
# Returns: {total_processed, clean_count, threats_neutralized, quarantined_count, results}
```

### create_isolation_session()

Create an isolated browsing session with policy evaluation.

```python
session = engine.create_isolation_session(
    user_id="user@acme.com",
    target_url="https://example.com",
    user_groups=["engineering"],
    device_posture={
        "os": "Windows 11",
        "managed": True,
        "edr_running": True,
        "disk_encrypted": True,
    },
    user_risk_level="low",  # low | medium | high
)
# Returns: {session_id, isolation_mode, applied_policy, dlp_controls, ...}
```

### create_zero_trust_integration()

Configure Zero Trust platform integration.

```python
zt = engine.create_zero_trust_integration(
    identity_provider="Azure AD",
    conditional_access_rules=[
        {
            "name": "Rule Name",
            "condition": {
                "device_managed": False,        # Device posture check
                "user_risk_level": "high",      # Identity risk signal
                "user_group": "contractors",    # Group membership
                "target_category": "admin_console",  # URL category
            },
            "action": "full_isolation",         # Isolation mode override
            "dlp_override": {                   # DLP control overrides
                "disable_download": True,
            },
        },
    ],
    swg_integration={
        "proxy_mode": "explicit",               # explicit | transparent | pac
        "pac_url": "https://pac.acme.com/proxy.pac",
        "ssl_inspection": True,
        "bypass_domains": ["*.acme.internal"],
    },
)
```

### evaluate_access_request()

Evaluate a request against all policies and ZT rules.

```python
decision = engine.evaluate_access_request(
    user_id="user@acme.com",
    target_url="https://example.com",
    user_groups=["engineering"],
    device_posture={"managed": True},
    user_risk_level="low",
    referrer=None,
)
# Returns: {session_id, action, url_classification, matched_rules, effective_dlp_controls}
```

### generate_compliance_report()

Generate deployment compliance report.

```python
report = engine.generate_compliance_report(
    date_range=("2026-03-01", "2026-03-31"),
    include_metrics=True,
)
```

## CLI Usage

```bash
# Classify a URL
python agent.py --action classify --url "https://example.com"

# Test CDR on a file
python agent.py --action cdr_test --file "/path/to/file.docx"

# Run full demonstration
python agent.py --action demo --org "Acme Corp" --output report.json
```

## References

- Cloudflare Browser Isolation: https://developers.cloudflare.com/cloudflare-one/remote-browser-isolation/
- Cloudflare Isolation Policies: https://developers.cloudflare.com/cloudflare-one/remote-browser-isolation/isolation-policies/
- Menlo Security RBI: https://www.menlosecurity.com/product/remote-browser-isolation
- Menlo Security CDR Guide: https://www.menlosecurity.com/resources/a-complete-guide-to-content-disarm-and-reconstruction-cdr-technology
- OPSWAT Deep CDR: https://www.opswat.com/technologies/deep-cdr
- Zscaler RBI: https://www.zscaler.com/resources/security-terms-glossary/what-is-remote-browser-isolation
- CSA Browser as PEP in Zero Trust: https://cloudsecurityalliance.org/blog/2026/01/14/reimagining-the-browser-as-a-critical-policy-enforcement-point
- NIST SP 800-207 Zero Trust Architecture: https://csrc.nist.gov/publications/detail/sp/800-207/final
