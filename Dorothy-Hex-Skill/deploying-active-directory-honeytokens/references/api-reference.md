# API Reference: Active Directory Honeytoken Deployment

## PowerShellGenerator

Generates PowerShell scripts for AD honeytoken deployment operations.

### Methods

#### `generate_create_honeytoken_account(...)`
Generate PowerShell to create a honeytoken AD account with AdminCount=1, backdated password, group memberships, and SACL audit rules.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `sam_account_name` | `str` | required | sAMAccountName for the honeytoken |
| `display_name` | `str` | required | Display name |
| `description` | `str` | required | Description field |
| `ou_dn` | `str` | required | Distinguished Name of target OU |
| `password_length` | `int` | `128` | Random password length |
| `set_admin_count` | `bool` | `True` | Set AdminCount=1 |
| `account_age_days` | `int` | `5475` | Days to backdate password (~15 years) |

**Returns:** `str` -- Complete PowerShell script.

**AD Operations Performed:**
- Creates AD user account with strong random password
- Sets AdminCount=1 (appears as privileged account to BloodHound)
- Backdates pwdLastSet to simulate aged service account
- Adds to Remote Desktop Users group
- Configures SACL audit rule (Everyone/ReadProperty/Success)

**Detection:** Event ID 4662 (directory service object accessed)

#### `generate_add_honey_spn(...)`
Generate PowerShell to add a fake SPN for Kerberoasting detection (honeyroasting).

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `sam_account_name` | `str` | required | Account to add SPN to |
| `service_class` | `str` | `"MSSQLSvc"` | SPN service class |
| `hostname` | `str` | required | Fake hostname |
| `port` | `int` | `1433` | Service port |

**Returns:** `str` -- PowerShell script that registers the SPN and enables RC4+AES encryption.

**Detection:** Event ID 4769 (Kerberos TGS ticket requested) where ServiceName matches the honeytoken account. Any TGS request for this SPN is definitively malicious.

#### `generate_decoy_gpo(...)`
Generate PowerShell to create a decoy GPO with cpassword credential trap in SYSVOL.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `gpo_name` | `str` | required | GPO display name |
| `decoy_username` | `str` | required | Username in cpassword trap |
| `decoy_domain` | `str` | required | Short domain name (e.g., CORP) |
| `sysvol_path` | `str` | required | SYSVOL Policies path |
| `enable_sacl` | `bool` | `True` | Set SACL audit on GPO folder |

**Returns:** `str` -- PowerShell script that creates GPO folder structure, plants Groups.xml with cpassword, creates trap AD account with different password, and sets SACL.

**Detection Chain:**
1. Event ID 4663 (SYSVOL folder read)
2. Offline: Attacker decrypts cpassword
3. Event ID 4625 (failed logon with decoy credentials)
4. Correlation: 4663 + 4625 from same source IP = confirmed attacker

#### `generate_deceptive_bloodhound_path(...)`
Generate PowerShell to create fake BloodHound attack paths leading to monitored honeytokens.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `honeytoken_sam` | `str` | required | Honeytoken account name |
| `target_group` | `str` | `"Domain Admins"` | High-value group for deceptive path |
| `intermediate_ou` | `str` | `"OU=Service Accounts"` | OU for intermediate objects |

**Returns:** `str` -- PowerShell script that creates GenericAll ACE, deceptive intermediate group, and WriteDacl edge with deny safety net.

**BloodHound Path Created:**
```
Remote Desktop Users -[GenericAll]-> honeytoken_account
honeytoken_account -[MemberOf]-> IT-Infrastructure-Admins
honeytoken_account -[WriteDacl]-> Domain Admins (blocked by deny ACE)
```

#### `generate_validation_script(sam_account_name)`
Generate PowerShell to validate honeytoken deployment integrity.

**Checks Performed:**

| Check | Pass Criteria |
|-------|---------------|
| Account Exists | Account found in AD |
| Account Enabled | Enabled = True |
| AdminCount=1 | AdminCount attribute is 1 |
| SPN Configured | At least one SPN registered |
| Password Age | > 365 days |
| SACL Audit | At least one audit rule configured |
| Group Memberships | Lists all group memberships |
| RC4 Supported | msDS-SupportedEncryptionTypes includes 0x4 |
| Kerberos Audit | auditpol shows Kerberos TGS auditing enabled |

---

## SIEMRuleGenerator

Generates detection rules for SIEM platforms targeting honeytoken activity.

### Methods

#### `generate_detection_rules(honeytoken_accounts, honey_spns, gpo_trap_accounts, siem="sigma")`

| Parameter | Type | Description |
|-----------|------|-------------|
| `honeytoken_accounts` | `list[str]` | Account names to monitor |
| `honey_spns` | `list[str]` | SPN values to monitor |
| `gpo_trap_accounts` | `list[str]` | GPO credential trap usernames |
| `siem` | `str` | Target platform: `sigma`, `splunk`, or `sentinel` |

**Returns:** `list[dict]` -- Each rule contains `title`, `detection_logic`, and `rule` (full query text).

### Generated Rules by Platform

**Sigma Rules:**

| Rule | Event ID | MITRE Technique |
|------|----------|-----------------|
| Honeytoken Kerberoast Detected | 4769 | T1558.003 |
| Honeytoken GPO Credential Use Detected | 4624, 4625 | T1552.006 |
| Honeytoken AD Object Accessed | 4662 | T1087.002 |

**Splunk SPL Rules:**

| Rule | Description |
|------|-------------|
| Honeytoken Kerberoast Detection | Index wineventlog EventCode=4769 with ServiceName filter |
| Honeytoken GPO Credential Use | EventCode 4624/4625 with TargetUserName filter |
| Attack Chain Correlation | SYSVOL enum (4663) -> credential use (4625) by same source IP |

**Microsoft Sentinel KQL Rules:**

| Rule | Description |
|------|-------------|
| Honeytoken Kerberoast Detection | SecurityEvent EventID 4769 with ServiceName filter |
| Honeytoken GPO Credential Use | SecurityEvent EventID 4624/4625 with TargetUserName filter |

#### `export_rules(output_dir, format="json")`
Export all generated rules to files on disk.

**Returns:** `list[str]` of saved file paths.

---

## ADHoneytokenMonitor

Monitors Windows Event Logs for honeytoken interactions and generates alerts.

### Constructor
```python
ADHoneytokenMonitor(config_path=None)
```

### Methods

#### `register_honeytoken(identifier, token_type="admin_account", metadata=None)`
Register a honeytoken for monitoring.

| Token Type | Description |
|------------|-------------|
| `admin_account` | Fake privileged AD account |
| `spn` | Fake Service Principal Name |
| `gpo_credential` | Decoy GPO cpassword trap account |

#### `analyze_event_log(events)`
Analyze Windows Event Log entries for honeytoken interactions.

| Event ID | Alert Type | Severity |
|----------|------------|----------|
| 4769 | `KERBEROAST_HONEYTOKEN` | critical |
| 4624 | `HONEYTOKEN_LOGON` | critical |
| 4625 | `HONEYTOKEN_LOGON_FAILED` | critical |
| 4662 | `HONEYTOKEN_DACL_READ` | high |
| 5136 | `HONEYTOKEN_GPO_MODIFIED` | critical |

**Returns:** `list[dict]` -- Alerts with `alert_id`, `alert_type`, `severity`, `description`, `mitre_technique`, `source_ip`, `source_host`.

#### `generate_detection_rules(siem="sigma")`
Generate SIEM detection rules for all registered honeytokens.

#### `get_alert_summary()`
Get aggregated summary of all alerts by severity, type, and source IP.

---

## HoneytokenDeployer

Orchestrates full honeytoken deployment and generates all artifacts.

### Constructor
```python
HoneytokenDeployer(domain="corp.example.com",
                   service_account_ou="OU=Service Accounts",
                   sysvol_path="")
```

### Methods

#### `generate_realistic_name()`
Generate a realistic service account name using templates matching common organizational patterns.

**Returns:** `dict` with `sam_account_name`, `display_name`, `hostname`.

#### `deploy_full_suite(...)`
Generate complete deployment artifacts for a full honeytoken suite.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `token_count` | `int` | `3` | Number of honeytoken accounts |
| `include_spn` | `bool` | `True` | Add fake SPNs |
| `include_gpo` | `bool` | `True` | Create decoy GPO |
| `include_bloodhound` | `bool` | `True` | Create deceptive BloodHound paths |
| `siem_type` | `str` | `"sigma"` | Target SIEM for detection rules |

**Returns:** `dict` with `deployment_id`, `tokens`, `scripts`, `detection_rules`.

#### `save_deployment(deployment, output_dir)`
Save all deployment artifacts (PowerShell scripts, detection rules, manifest) to disk.

**Returns:** `list[str]` of saved file paths.

---

## PowerShell Module: Deploy-ADHoneytokens.ps1

### Exported Functions

| Function | Description |
|----------|-------------|
| `New-HoneytokenAdmin` | Create honeytoken AD account with AdminCount=1, SACL, backdated password |
| `Add-HoneytokenSPN` | Register fake SPN for Kerberoasting detection |
| `New-DecoyGPO` | Create decoy GPO with cpassword trap in SYSVOL |
| `New-DeceptiveBloodHoundPath` | Create fake BloodHound attack paths |
| `Test-HoneytokenDeployment` | Validate honeytoken deployment integrity |
| `Deploy-FullHoneytokenSuite` | Deploy complete honeytoken suite |

### Prerequisites
```powershell
#Requires -Modules ActiveDirectory
#Requires -Version 5.1
```

---

## Windows Event IDs for Honeytoken Detection

| Event ID | Description | Honeytoken Use |
|----------|-------------|----------------|
| 4769 | Kerberos TGS ticket requested | Kerberoast against honey SPN |
| 4768 | Kerberos TGT requested | AS-REP roasting of honey account |
| 4625 | Failed logon attempt | Credential use from decoy GPO |
| 4624 | Successful logon | Honeytoken account compromise |
| 4662 | Directory service object accessed | DACL read on honeytoken user |
| 4648 | Logon with explicit credentials | Pass-the-hash detection |
| 5136 | Directory service object modified | GPO modification |
| 5137 | Directory service object created | GPO creation |
| 4663 | Attempt to access object | SYSVOL decoy file read |

---

## CLI Usage

```bash
# Full deployment (generates all scripts, rules, and manifest)
python agent.py --action full_deploy \
    --domain corp.example.com \
    --ou "OU=Service Accounts" \
    --token-count 3 \
    --siem sigma \
    --output-dir honeytoken_deployment

# Generate detection rules only
python agent.py --action generate_rules \
    --account-name svc_sqlbackup_legacy \
    --siem splunk

# Generate single account creation script
python agent.py --action deploy_account \
    --account-name svc_sqlbackup_legacy \
    --domain corp.example.com

# Generate SPN addition script
python agent.py --action deploy_spn \
    --account-name svc_sqlbackup_legacy

# Generate decoy GPO script
python agent.py --action deploy_gpo \
    --domain corp.example.com

# Generate BloodHound deception script
python agent.py --action deploy_bloodhound \
    --account-name svc_sqlbackup_legacy

# Validate deployment
python agent.py --action validate \
    --account-name svc_sqlbackup_legacy

# Analyze event logs for honeytoken alerts
python agent.py --action analyze_logs \
    --account-name svc_sqlbackup_legacy \
    --event-log events.json
```

### CLI Arguments

| Argument | Default | Description |
|----------|---------|-------------|
| `--action` | `full_deploy` | Action to perform |
| `--domain` | `corp.example.com` | AD domain FQDN |
| `--ou` | `OU=Service Accounts` | OU for honeytoken accounts |
| `--sysvol` | auto | SYSVOL Policies path |
| `--account-name` | `svc_sqlbackup_legacy` | Honeytoken account name |
| `--token-count` | `3` | Number of honeytokens to deploy |
| `--siem` | `sigma` | Target SIEM: `sigma`, `splunk`, `sentinel` |
| `--output-dir` | `honeytoken_deployment` | Output directory |
| `--include-spn` | `True` | Include fake SPNs |
| `--include-gpo` | `True` | Include decoy GPO |
| `--include-bloodhound` | `True` | Include BloodHound deception |
| `--event-log` | `None` | Path to event log JSON for analysis |
