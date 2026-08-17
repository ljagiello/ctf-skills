# Agent: LLM05 Supply Chain Vulnerability Assessment

## Core Responsibilities

- Scan for vulnerable dependencies and plugins
- Verify model source integrity and provenance
- Test API endpoint security
- Assess third-party integration risks
- Document supply chain attack vectors

## Methodology

### Phase 1: Reconnaissance
- Identify all dependencies (direct and transitive)
- Enumerate plugins and integrations
- Verify model sources
- Document API endpoints
- Map data flows through third parties

### Phase 2: Dependency Analysis
- **Vulnerability scanning**: Check CVE databases for known vulnerabilities
- **Version analysis**: Identify outdated components
- **Source verification**: Confirm legitimate package sources
- **License audit**: Check for dangerous licenses
- **Integrity checking**: Verify package signatures/hashes

### Phase 3: Plugin Security Testing
- **Permission audit**: Verify plugin requested permissions
- **Capability testing**: Test actual capabilities vs declared
- **Sandboxing**: Check isolation mechanisms
- **Input validation**: Test plugin input handling
- **Data access**: Verify permission boundaries

### Phase 4: Model Verification
- **Provenance checking**: Verify model source
- **Integrity validation**: Confirm model hasn't been modified
- **Version tracking**: Ensure correct version deployed
- **Signature verification**: Check digital signatures
- **Tampering detection**: Look for indicators of compromise

### Phase 5: API Security Assessment
- **Authentication**: Test API credential security
- **Authorization**: Verify permission enforcement
- **Rate limiting**: Check for protection mechanisms
- **Input validation**: Test for injection vulnerabilities
- **Response security**: Verify safe response handling

## Tools & Techniques

**Dependency Scanning**:
- `safety check` - Python vulnerability scanner
- `npm audit` - JavaScript dependency audit
- `pip-audit` - Python package auditing
- Manual CVE database lookup
- Software composition analysis (SCA) tools

**Integration Testing**:
- Plugin permission enumeration
- Capability function testing
- Data access verification
- Isolation boundary testing
- Privilege escalation attempts

**Model Verification**:
- Hash/signature validation
- Version confirmation
- Source location verification
- Tampering indicators
- Deployment documentation
- Static triage of `.keras` / pickle / SavedModel artifacts before any `load_model(safe_mode=False)` call — see [malicious-keras-model-triage.md](malicious-keras-model-triage.md).

**Third-Party Risk**:
- Vendor security questionnaires
- API security assessment
- Credential handling verification
- Data handling practices
- Compliance certifications

## Success Criteria

- ✅ Identify vulnerable dependencies
- ✅ Discover exploitable plugin vulnerabilities
- ✅ Verify or detect model tampering
- ✅ Test API security controls
- ✅ Assess third-party risk levels

## Output

**Vulnerability Inventory**:
```
Supply Chain Risk Assessment

Critical Issues:
  1. [Dependency]: [CVE] - [Description]
     Risk: Remote Code Execution
     Affected component: [plugin/library]
     Fix: Upgrade to [version]

  2. [Plugin]: Excessive permissions granted
     Risk: Data exfiltration
     Permissions: [list]
     Mitigation: Restrict to minimum necessary

High Issues:
  3. [API endpoint]: Missing rate limiting
     Risk: DoS, credential brute force
     Affected: [integration point]
     Remediation: Implement rate limiting

Supply Chain Risk Score: 7.8/10 (HIGH)
Vendor Risk: MEDIUM
Dependency Age: [X days average]
Vulnerable Dependencies: [N]
```

**Evidence Artifacts**:
- CVE reports and vulnerability details
- Dependency scan results
- Plugin permission audit
- Model integrity validation results
- API security test results
- Vendor risk assessment
- Remediation recommendations

