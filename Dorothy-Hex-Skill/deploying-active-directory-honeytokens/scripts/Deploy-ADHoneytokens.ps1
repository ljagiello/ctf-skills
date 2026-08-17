<#
.SYNOPSIS
    Active Directory Honeytoken Deployment Module

.DESCRIPTION
    Deploys deception-based honeytokens in Active Directory including:
    - Fake privileged accounts with AdminCount=1
    - Fake SPNs for Kerberoasting detection (honeyroasting)
    - Decoy GPOs with cpassword traps
    - Deceptive BloodHound attack paths
    - SACL audit rules for detection

.NOTES
    Author: mukul975
    Version: 1.0
    References:
        - Trimarc Security: The Art of the Honeypot Account
        - ADSecurity.org: Detecting Kerberoasting Activity Part 2
        - Microsoft Defender for Identity Honeytokens
        - SpecterOps: Kerberoasting and AES-256
#>

#Requires -Modules ActiveDirectory
#Requires -Version 5.1

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ---------------------------------------------------------------------------
# Module-level variables
# ---------------------------------------------------------------------------

$Script:DeployedTokens = @()
$Script:DeploymentLog = @()

# ---------------------------------------------------------------------------
# Helper Functions
# ---------------------------------------------------------------------------

function Write-DeployLog {
    param(
        [string]$Message,
        [ValidateSet("INFO", "WARN", "ERROR", "SUCCESS")]
        [string]$Level = "INFO"
    )
    $entry = [PSCustomObject]@{
        Timestamp = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
        Level     = $Level
        Message   = $Message
    }
    $Script:DeploymentLog += $entry
    $color = switch ($Level) {
        "INFO"    { "White" }
        "WARN"    { "Yellow" }
        "ERROR"   { "Red" }
        "SUCCESS" { "Green" }
    }
    Write-Host "[$Level] $Message" -ForegroundColor $color
}

function New-SecureRandomPassword {
    param([int]$Length = 128)
    $chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{}|;:,.<>?'
    $password = -join (1..$Length | ForEach-Object { $chars[(Get-Random -Maximum $chars.Length)] })
    return $password
}

# ---------------------------------------------------------------------------
# New-HoneytokenAdmin
# ---------------------------------------------------------------------------

function New-HoneytokenAdmin {
    <#
    .SYNOPSIS
        Creates a honeytoken admin account in Active Directory.

    .DESCRIPTION
        Creates a realistic-looking service account with AdminCount=1 set,
        backdated password age, group memberships, and SACL audit rules.
        The account appears as a high-value target to attackers using
        BloodHound, SharpHound, or manual AD enumeration.

    .PARAMETER SamAccountName
        The sAMAccountName for the honeytoken account.

    .PARAMETER DisplayName
        The display name for the account.

    .PARAMETER Description
        The description field (should look legitimate).

    .PARAMETER OU
        The Distinguished Name of the OU to create the account in.

    .PARAMETER PasswordLength
        Length of the random password (default: 128).

    .PARAMETER SetAdminCount
        If true, sets AdminCount=1 on the account (default: true).

    .PARAMETER AccountAgeDays
        Number of days to backdate the password (default: 5475 = ~15 years).

    .EXAMPLE
        New-HoneytokenAdmin -SamAccountName "svc_sqlbackup_legacy" `
            -DisplayName "SQL Backup Service (Legacy)" `
            -Description "Legacy SQL Server backup service account - DO NOT DELETE" `
            -OU "OU=Service Accounts,DC=corp,DC=example,DC=com"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$SamAccountName,

        [Parameter(Mandatory)]
        [string]$DisplayName,

        [string]$Description = "Legacy service account - DO NOT DELETE",

        [Parameter(Mandatory)]
        [string]$OU,

        [int]$PasswordLength = 128,

        [bool]$SetAdminCount = $true,

        [int]$AccountAgeDays = 5475
    )

    Write-DeployLog "Creating honeytoken admin: $SamAccountName" "INFO"

    # Generate strong random password
    $Password = New-SecureRandomPassword -Length $PasswordLength
    $SecurePassword = ConvertTo-SecureString -String $Password -AsPlainText -Force

    # Create the account
    $Domain = Get-ADDomain
    $UPN = "$SamAccountName@$($Domain.DNSRoot)"

    $UserParams = @{
        Name                 = $DisplayName
        SamAccountName       = $SamAccountName
        UserPrincipalName    = $UPN
        DisplayName          = $DisplayName
        Description          = $Description
        Path                 = $OU
        AccountPassword      = $SecurePassword
        Enabled              = $true
        PasswordNeverExpires = $true
        CannotChangePassword = $true
        ChangePasswordAtLogon = $false
    }

    try {
        New-ADUser @UserParams
        Write-DeployLog "Account created: $SamAccountName" "SUCCESS"
    }
    catch {
        Write-DeployLog "Failed to create account: $_" "ERROR"
        throw
    }

    # Set AdminCount=1
    if ($SetAdminCount) {
        Set-ADUser -Identity $SamAccountName -Replace @{AdminCount = 1}
        Write-DeployLog "AdminCount set to 1" "SUCCESS"
    }

    # Backdate password
    $AgeDate = (Get-Date).AddDays(-$AccountAgeDays)
    $FileTime = $AgeDate.ToFileTime()
    Set-ADUser -Identity $SamAccountName -Replace @{pwdLastSet = $FileTime}
    Write-DeployLog "Password backdated to: $($AgeDate.ToString('yyyy-MM-dd'))" "SUCCESS"

    # Add to visible groups
    Add-ADGroupMember -Identity "Remote Desktop Users" -Members $SamAccountName
    Write-DeployLog "Added to Remote Desktop Users" "SUCCESS"

    # Set SACL for audit
    $UserDN = (Get-ADUser -Identity $SamAccountName).DistinguishedName
    $Acl = Get-Acl "AD:\$UserDN"
    $AuditRule = New-Object System.DirectoryServices.ActiveDirectoryAuditRule(
        [System.Security.Principal.SecurityIdentifier]"S-1-1-0",
        [System.DirectoryServices.ActiveDirectoryRights]"ReadProperty",
        [System.Security.AccessControl.AuditFlags]"Success",
        [System.DirectoryServices.ActiveDirectorySecurityInheritance]"None"
    )
    $Acl.AddAuditRule($AuditRule)
    Set-Acl "AD:\$UserDN" $Acl
    Write-DeployLog "SACL audit rule configured (Event ID 4662)" "SUCCESS"

    $result = Get-ADUser -Identity $SamAccountName -Properties *
    $Script:DeployedTokens += $result

    return $result
}

# ---------------------------------------------------------------------------
# Add-HoneytokenSPN
# ---------------------------------------------------------------------------

function Add-HoneytokenSPN {
    <#
    .SYNOPSIS
        Adds a fake SPN to a honeytoken account for Kerberoasting detection.

    .DESCRIPTION
        Registers a fake Service Principal Name on a honeytoken account.
        Any TGS ticket request for this SPN is definitively malicious since
        the associated service does not exist. This is known as "honeyroasting".

    .PARAMETER SamAccountName
        The honeytoken account to add the SPN to.

    .PARAMETER ServiceClass
        The SPN service class (default: MSSQLSvc).

    .PARAMETER Hostname
        The fake hostname for the SPN.

    .PARAMETER Port
        The service port (default: 1433).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$SamAccountName,

        [string]$ServiceClass = "MSSQLSvc",

        [Parameter(Mandatory)]
        [string]$Hostname,

        [int]$Port = 1433
    )

    $SPN = "$ServiceClass/${Hostname}:$Port"
    Write-DeployLog "Adding honey SPN: $SPN to $SamAccountName" "INFO"

    # Verify account exists
    $User = Get-ADUser -Identity $SamAccountName -Properties ServicePrincipalNames -ErrorAction Stop

    # Add SPN
    Set-ADUser -Identity $SamAccountName -ServicePrincipalNames @{Add = $SPN}
    Write-DeployLog "SPN registered: $SPN" "SUCCESS"

    # Enable RC4 + AES encryption (makes it attractive to Kerberoast tools)
    Set-ADUser -Identity $SamAccountName -Replace @{"msDS-SupportedEncryptionTypes" = 28}
    Write-DeployLog "Encryption types set to RC4+AES128+AES256" "SUCCESS"

    return [PSCustomObject]@{
        SamAccountName = $SamAccountName
        SPN            = $SPN
        ServiceClass   = $ServiceClass
        Hostname       = $Hostname
        Port           = $Port
    }
}

# ---------------------------------------------------------------------------
# New-DecoyGPO
# ---------------------------------------------------------------------------

function New-DecoyGPO {
    <#
    .SYNOPSIS
        Creates a decoy GPO with cpassword credential trap.

    .DESCRIPTION
        Creates a fake GPO folder in SYSVOL containing a Groups.xml with
        encrypted credentials (cpassword). Attackers using Get-GPPPassword,
        gpp-decrypt, or CrackMapExec will find and attempt to use these
        credentials, which triggers Event ID 4625 (failed logon).

    .PARAMETER GPOName
        Descriptive name for the decoy GPO.

    .PARAMETER DecoyUsername
        The username to embed in the cpassword trap.

    .PARAMETER DecoyDomain
        The short domain name (e.g., CORP).

    .PARAMETER SYSVOLPath
        The path to the SYSVOL Policies folder.

    .PARAMETER EnableAuditSACL
        Whether to set SACL audit on the GPO folder (default: true).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$GPOName,

        [Parameter(Mandatory)]
        [string]$DecoyUsername,

        [Parameter(Mandatory)]
        [string]$DecoyDomain,

        [Parameter(Mandatory)]
        [string]$SYSVOLPath,

        [bool]$EnableAuditSACL = $true
    )

    $GPOGuid = [guid]::NewGuid().ToString().ToUpper()
    Write-DeployLog "Creating decoy GPO: $GPOName (GUID: $GPOGuid)" "INFO"

    # Create folder structure
    $GPOPath = Join-Path $SYSVOLPath "{$GPOGuid}"
    $MachinePath = Join-Path $GPOPath "Machine\Preferences\Groups"
    New-Item -ItemType Directory -Path $MachinePath -Force | Out-Null

    # Generate fake cpassword
    $FakePassword = "H0n3yT0k3n_Tr4p_$(Get-Date -Format 'yyyy')!"
    $FakeCPassword = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($FakePassword))
    $UserGuid = [guid]::NewGuid().ToString().ToUpper()

    # Create Groups.xml with cpassword trap
    $GroupsXml = @"
<?xml version="1.0" encoding="utf-8"?>
<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}">
  <User clsid="{DF5F1855-51E5-4d24-8B1A-D9BDE98BA1D1}"
        name="$DecoyUsername"
        image="2"
        changed="2011-07-15 08:30:22"
        uid="{$UserGuid}">
    <Properties action="U"
                newName=""
                fullName="Maintenance Administrator"
                description="Legacy maintenance account"
                cpassword="$FakeCPassword"
                changeLogon="0"
                noChange="1"
                neverExpires="1"
                acctDisabled="0"
                userName="$DecoyDomain\$DecoyUsername" />
  </User>
</Groups>
"@

    $GroupsXml | Out-File -FilePath (Join-Path $MachinePath "Groups.xml") -Encoding UTF8
    Write-DeployLog "Groups.xml planted with cpassword trap" "SUCCESS"

    # Create corresponding trap AD account with different password
    $TrapPassword = New-SecureRandomPassword -Length 64
    $SecureTrap = ConvertTo-SecureString -String $TrapPassword -AsPlainText -Force

    try {
        New-ADUser -Name $DecoyUsername `
                   -SamAccountName $DecoyUsername `
                   -Description "Maintenance account - legacy" `
                   -AccountPassword $SecureTrap `
                   -Enabled $true `
                   -PasswordNeverExpires $true
        Write-DeployLog "Trap account created: $DecoyUsername (password differs from GPP)" "SUCCESS"
    }
    catch {
        Write-DeployLog "Trap account creation: $_" "WARN"
    }

    # Set SACL
    if ($EnableAuditSACL) {
        $FolderAcl = Get-Acl $GPOPath
        $AuditRule = New-Object System.Security.AccessControl.FileSystemAuditRule(
            "Everyone", "ReadData", "ContainerInherit,ObjectInherit", "None", "Success"
        )
        $FolderAcl.AddAuditRule($AuditRule)
        Set-Acl $GPOPath $FolderAcl
        Write-DeployLog "SACL set on GPO folder (Event ID 4663)" "SUCCESS"
    }

    return [PSCustomObject]@{
        GPOGuid       = $GPOGuid
        GPOName       = $GPOName
        GPOPath       = $GPOPath
        DecoyUsername = $DecoyUsername
        DecoyDomain   = $DecoyDomain
    }
}

# ---------------------------------------------------------------------------
# New-DeceptiveBloodHoundPath
# ---------------------------------------------------------------------------

function New-DeceptiveBloodHoundPath {
    <#
    .SYNOPSIS
        Creates fake BloodHound attack paths pointing to monitored honeytokens.

    .DESCRIPTION
        Sets ACL permissions that create apparent attack paths visible to
        BloodHound/SharpHound reconnaissance. These paths lead attackers toward
        monitored honeytoken accounts, triggering alerts when abused.

    .PARAMETER HoneytokenSamAccount
        The honeytoken account to create paths toward.

    .PARAMETER TargetHighValueGroup
        The high-value group to create a deceptive path to (default: Domain Admins).

    .PARAMETER IntermediateOU
        OU path for intermediate objects.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$HoneytokenSamAccount,

        [string]$TargetHighValueGroup = "Domain Admins",

        [string]$IntermediateOU = "OU=Service Accounts"
    )

    Write-DeployLog "Creating deceptive BloodHound paths for: $HoneytokenSamAccount" "INFO"

    $UserDN = (Get-ADUser -Identity $HoneytokenSamAccount).DistinguishedName

    # Create GenericAll edge from regular group to honeytoken
    $GroupSID = (Get-ADGroup -Identity "Remote Desktop Users").SID
    $Acl = Get-Acl "AD:\$UserDN"
    $AceRule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
        $GroupSID,
        [System.DirectoryServices.ActiveDirectoryRights]"GenericAll",
        [System.Security.AccessControl.AccessControlType]"Allow"
    )
    $Acl.AddAccessRule($AceRule)
    Set-Acl "AD:\$UserDN" $Acl
    Write-DeployLog "GenericAll ACE: Remote Desktop Users -> $HoneytokenSamAccount" "SUCCESS"

    # Create deceptive intermediate group
    $DeceptiveGroup = "IT-Infrastructure-Admins"
    try {
        New-ADGroup -Name $DeceptiveGroup -GroupScope DomainLocal `
                    -GroupCategory Security `
                    -Description "Infrastructure administration delegation"
        Write-DeployLog "Created deceptive group: $DeceptiveGroup" "SUCCESS"
    }
    catch {
        Write-DeployLog "Deceptive group may already exist" "WARN"
    }

    Add-ADGroupMember -Identity $DeceptiveGroup -Members $HoneytokenSamAccount
    Write-DeployLog "Added honeytoken to $DeceptiveGroup" "SUCCESS"

    # Create WriteDacl edge with deny safety net
    $DAGroupDN = (Get-ADGroup -Identity $TargetHighValueGroup).DistinguishedName
    $HoneySID = (Get-ADUser -Identity $HoneytokenSamAccount).SID

    $DAGroupAcl = Get-Acl "AD:\$DAGroupDN"
    $DenyRule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
        $HoneySID,
        [System.DirectoryServices.ActiveDirectoryRights]"GenericAll",
        [System.Security.AccessControl.AccessControlType]"Deny"
    )
    $WriteDaclRule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
        $HoneySID,
        [System.DirectoryServices.ActiveDirectoryRights]"WriteDacl",
        [System.Security.AccessControl.AccessControlType]"Allow"
    )
    $DAGroupAcl.AddAccessRule($DenyRule)
    $DAGroupAcl.AddAccessRule($WriteDaclRule)
    Set-Acl "AD:\$DAGroupDN" $DAGroupAcl
    Write-DeployLog "Deceptive WriteDacl path created (with deny safety)" "SUCCESS"

    return [PSCustomObject]@{
        HoneytokenAccount = $HoneytokenSamAccount
        PathDescription   = "Remote Desktop Users -> $HoneytokenSamAccount -> $DeceptiveGroup -> $TargetHighValueGroup (blocked)"
        DeceptiveGroup    = $DeceptiveGroup
    }
}

# ---------------------------------------------------------------------------
# Test-HoneytokenDeployment
# ---------------------------------------------------------------------------

function Test-HoneytokenDeployment {
    <#
    .SYNOPSIS
        Validates honeytoken deployment integrity.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$SamAccountName,

        [switch]$ValidateAdminCount,
        [switch]$ValidateSPN,
        [switch]$ValidateGPODecoy,
        [switch]$ValidateAuditPolicy
    )

    $Results = @()

    # Account existence
    $User = Get-ADUser -Identity $SamAccountName -Properties * -ErrorAction SilentlyContinue
    if ($User) {
        $Results += [PSCustomObject]@{Check="Account Exists"; Status="PASS"; Details=$User.DistinguishedName}
        $Results += [PSCustomObject]@{Check="Account Enabled"; Status=$(if($User.Enabled){"PASS"}else{"FAIL"}); Details=$(if($User.Enabled){"Enabled"}else{"Disabled"})}
    } else {
        $Results += [PSCustomObject]@{Check="Account Exists"; Status="FAIL"; Details="Not found"}
        return $Results
    }

    if ($ValidateAdminCount) {
        $Results += [PSCustomObject]@{
            Check   = "AdminCount=1"
            Status  = $(if($User.AdminCount -eq 1){"PASS"}else{"WARN"})
            Details = "AdminCount=$($User.AdminCount)"
        }
    }

    if ($ValidateSPN) {
        $SPNs = $User.ServicePrincipalNames
        $Results += [PSCustomObject]@{
            Check   = "SPN Configured"
            Status  = $(if($SPNs -and $SPNs.Count -gt 0){"PASS"}else{"WARN"})
            Details = $(if($SPNs){$SPNs -join ", "}else{"No SPNs"})
        }
    }

    if ($ValidateAuditPolicy) {
        $AuditCheck = auditpol /get /subcategory:"Kerberos Service Ticket Operations" 2>$null
        $Results += [PSCustomObject]@{
            Check   = "Kerberos TGS Auditing"
            Status  = $(if($AuditCheck -match "Success"){"PASS"}else{"FAIL"})
            Details = $(if($AuditCheck -match "Success"){"Enabled"}else{"Run: auditpol /set /subcategory:'Kerberos Service Ticket Operations' /success:enable"})
        }
    }

    # Password age
    $PwdAge = (Get-Date) - $User.PasswordLastSet
    $Results += [PSCustomObject]@{
        Check   = "Password Age"
        Status  = $(if($PwdAge.Days -gt 365){"PASS"}else{"WARN"})
        Details = "$($PwdAge.Days) days"
    }

    return $Results
}

# ---------------------------------------------------------------------------
# Deploy-FullHoneytokenSuite
# ---------------------------------------------------------------------------

function Deploy-FullHoneytokenSuite {
    <#
    .SYNOPSIS
        Deploys a complete honeytoken suite in Active Directory.
    #>
    [CmdletBinding()]
    param(
        [string]$Environment = "Production",
        [Parameter(Mandatory)]
        [string]$ServiceAccountOU,
        [Parameter(Mandatory)]
        [string]$SYSVOLPath,
        [int]$TokenCount = 3,
        [bool]$IncludeSPN = $true,
        [bool]$IncludeGPODecoy = $true,
        [bool]$IncludeBloodHoundPath = $true,
        [string]$SIEMType = "Splunk"
    )

    Write-DeployLog "Starting full honeytoken suite deployment for $Environment" "INFO"
    Write-DeployLog "Token count: $TokenCount, SPN: $IncludeSPN, GPO: $IncludeGPODecoy" "INFO"

    $Tokens = @()

    # Service account name templates
    $ServiceNames = @(
        @{Sam="svc_sqlbackup_legacy"; Display="SQL Backup Service (Legacy)"; SPN_Class="MSSQLSvc"; Host="sql-bak-legacy01"; Port=1433},
        @{Sam="svc_exchange_transport"; Display="Exchange Transport Agent"; SPN_Class="exchangeMDB"; Host="exch-hub-legacy02"; Port=443},
        @{Sam="svc_scom_monitor"; Display="SCOM Monitoring Service"; SPN_Class="HTTP"; Host="scom-legacy-mgmt01"; Port=5723},
        @{Sam="svc_adfs_proxy_old"; Display="ADFS Proxy Service (Old)"; SPN_Class="HTTP"; Host="adfs-proxy-legacy01"; Port=443},
        @{Sam="svc_citrix_storefront"; Display="Citrix StoreFront Service"; SPN_Class="HTTP"; Host="ctx-sf-legacy01"; Port=443}
    )

    $Domain = (Get-ADDomain).DNSRoot

    for ($i = 0; $i -lt [Math]::Min($TokenCount, $ServiceNames.Count); $i++) {
        $svc = $ServiceNames[$i]

        # Create admin account
        $admin = New-HoneytokenAdmin `
            -SamAccountName $svc.Sam `
            -DisplayName $svc.Display `
            -Description "Legacy $($svc.Display.ToLower()) - DO NOT DELETE" `
            -OU $ServiceAccountOU

        $tokenInfo = [PSCustomObject]@{
            Name          = $svc.Sam
            Type          = "admin_account"
            SPN           = ""
            DetectionRule = "Event ID 4662 (object access)"
        }

        # Add SPN
        if ($IncludeSPN) {
            $Hostname = "$($svc.Host).$Domain"
            $spnResult = Add-HoneytokenSPN `
                -SamAccountName $svc.Sam `
                -ServiceClass $svc.SPN_Class `
                -Hostname $Hostname `
                -Port $svc.Port
            $tokenInfo.SPN = $spnResult.SPN
            $tokenInfo.DetectionRule = "Event ID 4769 (Kerberoast)"
        }

        $Tokens += $tokenInfo
    }

    # Deploy GPO decoy
    if ($IncludeGPODecoy) {
        $DomainShort = ($Domain -split '\.')[0].ToUpper()
        $gpo = New-DecoyGPO `
            -GPOName "Server Maintenance Policy (Legacy)" `
            -DecoyUsername "admin_maintenance" `
            -DecoyDomain $DomainShort `
            -SYSVOLPath $SYSVOLPath

        $Tokens += [PSCustomObject]@{
            Name          = "admin_maintenance"
            Type          = "gpo_credential"
            SPN           = ""
            DetectionRule = "Event ID 4625 (failed logon with GPP creds)"
        }
    }

    # Create BloodHound deception
    if ($IncludeBloodHoundPath -and $Tokens.Count -gt 0) {
        $bhPath = New-DeceptiveBloodHoundPath `
            -HoneytokenSamAccount $Tokens[0].Name
    }

    $deployment = [PSCustomObject]@{
        Environment = $Environment
        Tokens      = $Tokens
        DeployedAt  = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
        Log         = $Script:DeploymentLog
    }

    Write-DeployLog "Deployment complete: $($Tokens.Count) tokens deployed" "SUCCESS"
    return $deployment
}

# ---------------------------------------------------------------------------
# Export module members
# ---------------------------------------------------------------------------

Export-ModuleMember -Function @(
    'New-HoneytokenAdmin',
    'Add-HoneytokenSPN',
    'New-DecoyGPO',
    'New-DeceptiveBloodHoundPath',
    'Test-HoneytokenDeployment',
    'Deploy-FullHoneytokenSuite'
)
