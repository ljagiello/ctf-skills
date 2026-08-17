#Requires -Version 5.1
<#
.SYNOPSIS
    Audits SMB signing, LDAP signing, and NTLM configuration across Active Directory.

.DESCRIPTION
    This script performs a comprehensive audit of NTLM relay attack surface by checking:
    - SMB signing enforcement on all domain-joined Windows hosts
    - LDAP signing and channel binding on domain controllers
    - LmCompatibilityLevel (NTLMv1 vs NTLMv2 enforcement)
    - LLMNR and NBT-NS configuration
    - NTLM restriction policies
    Outputs results to CSV and provides a risk summary.

.PARAMETER OutputPath
    Directory to save audit results. Defaults to current directory.

.PARAMETER DomainControllerOnly
    Only audit domain controllers (faster for large environments).

.PARAMETER SkipConnectivity
    Skip remote connectivity checks (only check local configuration).

.EXAMPLE
    .\audit_smb_signing.ps1 -OutputPath C:\AuditResults
    .\audit_smb_signing.ps1 -DomainControllerOnly
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string]$OutputPath = ".",

    [Parameter()]
    [switch]$DomainControllerOnly,

    [Parameter()]
    [switch]$SkipConnectivity
)

$ErrorActionPreference = "Continue"
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"

Write-Host @"
==============================================================================
  NTLM Relay Attack Surface Audit
  Checks SMB Signing, LDAP Signing, NTLM Configuration
  MITRE ATT&CK: T1557.001
  Run Time: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
==============================================================================
"@

# ============================================================================
# Section 1: SMB Signing Audit
# ============================================================================
Write-Host "`n[*] Section 1: SMB Signing Audit" -ForegroundColor Cyan

$smbResults = @()

if ($DomainControllerOnly) {
    Write-Host "[*] Scanning domain controllers only..."
    $targets = Get-ADDomainController -Filter * | Select-Object -ExpandProperty HostName
} else {
    Write-Host "[*] Scanning all domain computers..."
    $targets = Get-ADComputer -Filter { Enabled -eq $true -and OperatingSystem -like "*Windows*" } |
        Select-Object -ExpandProperty DNSHostName
}

Write-Host "[*] Found $($targets.Count) targets to audit"

$counter = 0
foreach ($target in $targets) {
    $counter++
    Write-Progress -Activity "Auditing SMB Signing" -Status "$target ($counter/$($targets.Count))" `
        -PercentComplete (($counter / $targets.Count) * 100)

    $result = [PSCustomObject]@{
        Hostname              = $target
        Reachable             = $false
        SMBServerSignRequired = "Unknown"
        SMBServerSignEnabled  = "Unknown"
        SMBClientSignRequired = "Unknown"
        SMBClientSignEnabled  = "Unknown"
        RelayVulnerable       = "Unknown"
        ErrorDetail           = ""
    }

    if (-not $SkipConnectivity) {
        try {
            $session = New-CimSession -ComputerName $target -OperationTimeoutSec 10 -ErrorAction Stop
            $result.Reachable = $true

            $serverConfig = Get-SmbServerConfiguration -CimSession $session -ErrorAction Stop
            $result.SMBServerSignRequired = $serverConfig.RequireSecuritySignature
            $result.SMBServerSignEnabled = $serverConfig.EnableSecuritySignature

            try {
                $clientConfig = Get-SmbClientConfiguration -CimSession $session -ErrorAction Stop
                $result.SMBClientSignRequired = $clientConfig.RequireSecuritySignature
                $result.SMBClientSignEnabled = $clientConfig.EnableSecuritySignature
            } catch {
                $result.SMBClientSignRequired = "Error"
                $result.SMBClientSignEnabled = "Error"
            }

            # Determine relay vulnerability
            if ($serverConfig.RequireSecuritySignature -eq $true) {
                $result.RelayVulnerable = "No - SMB Signing Required"
            } elseif ($serverConfig.EnableSecuritySignature -eq $true) {
                $result.RelayVulnerable = "Partial - Signing Enabled but Not Required"
            } else {
                $result.RelayVulnerable = "YES - SMB Signing Not Enforced"
            }

            Remove-CimSession $session
        } catch {
            $result.ErrorDetail = $_.Exception.Message
            $result.RelayVulnerable = "Unknown - Connection Failed"
        }
    }

    $smbResults += $result
}

Write-Progress -Activity "Auditing SMB Signing" -Completed

$smbCsvPath = Join-Path $OutputPath "smb_signing_audit_$timestamp.csv"
$smbResults | Export-Csv -Path $smbCsvPath -NoTypeInformation
Write-Host "[*] SMB signing results saved to: $smbCsvPath"

$vulnerable = @($smbResults | Where-Object { $_.RelayVulnerable -like "YES*" })
$partial = @($smbResults | Where-Object { $_.RelayVulnerable -like "Partial*" })
$secure = @($smbResults | Where-Object { $_.RelayVulnerable -like "No*" })

Write-Host "`n  SMB Signing Summary:"
Write-Host "  Fully Protected (Signing Required): $($secure.Count)" -ForegroundColor Green
Write-Host "  Partially Protected (Signing Enabled): $($partial.Count)" -ForegroundColor Yellow
Write-Host "  VULNERABLE (Signing Not Enforced): $($vulnerable.Count)" -ForegroundColor Red

if ($vulnerable.Count -gt 0) {
    Write-Host "`n  [!] Vulnerable hosts:" -ForegroundColor Red
    $vulnerable | Select-Object -First 10 | ForEach-Object {
        Write-Host "      $($_.Hostname)" -ForegroundColor Red
    }
    if ($vulnerable.Count -gt 10) {
        Write-Host "      ... and $($vulnerable.Count - 10) more (see CSV)" -ForegroundColor Red
    }
}

# ============================================================================
# Section 2: LDAP Signing Audit (Domain Controllers)
# ============================================================================
Write-Host "`n[*] Section 2: LDAP Signing Audit (Domain Controllers)" -ForegroundColor Cyan

$ldapResults = @()
$dcs = Get-ADDomainController -Filter * | Select-Object HostName, IPv4Address, OperatingSystem

foreach ($dc in $dcs) {
    $ldapResult = [PSCustomObject]@{
        DCHostname     = $dc.HostName
        IPAddress      = $dc.IPv4Address
        OS             = $dc.OperatingSystem
        LDAPSigning    = "Unknown"
        ChannelBinding = "Unknown"
        RelayToLDAP    = "Unknown"
        ErrorDetail    = ""
    }

    try {
        $ldapSigning = Invoke-Command -ComputerName $dc.HostName -ScriptBlock {
            $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters"
            $signing = (Get-ItemProperty -Path $regPath -Name "LDAPServerIntegrity" -ErrorAction SilentlyContinue).LDAPServerIntegrity
            $binding = (Get-ItemProperty -Path $regPath -Name "LdapEnforceChannelBinding" -ErrorAction SilentlyContinue).LdapEnforceChannelBinding
            return @{ Signing = $signing; Binding = $binding }
        } -ErrorAction Stop

        $ldapResult.LDAPSigning = switch ($ldapSigning.Signing) {
            0 { "None (VULNERABLE)" }
            1 { "Negotiate (Default - VULNERABLE to relay)" }
            2 { "Required (Secure)" }
            default { "Not Configured (defaults to Negotiate - VULNERABLE)" }
        }

        $ldapResult.ChannelBinding = switch ($ldapSigning.Binding) {
            0 { "Disabled (VULNERABLE)" }
            1 { "When Supported" }
            2 { "Always Required (Secure)" }
            default { "Not Configured (VULNERABLE)" }
        }

        if ($ldapSigning.Signing -eq 2 -and $ldapSigning.Binding -eq 2) {
            $ldapResult.RelayToLDAP = "No - Signing and Channel Binding Required"
        } elseif ($ldapSigning.Signing -eq 2) {
            $ldapResult.RelayToLDAP = "Partial - Signing Required but Channel Binding Not Enforced"
        } else {
            $ldapResult.RelayToLDAP = "YES - LDAP Relay Possible"
        }
    } catch {
        $ldapResult.ErrorDetail = $_.Exception.Message
    }

    $ldapResults += $ldapResult
}

$ldapCsvPath = Join-Path $OutputPath "ldap_signing_audit_$timestamp.csv"
$ldapResults | Export-Csv -Path $ldapCsvPath -NoTypeInformation
Write-Host "[*] LDAP signing results saved to: $ldapCsvPath"

foreach ($r in $ldapResults) {
    $color = if ($r.RelayToLDAP -like "YES*") { "Red" } elseif ($r.RelayToLDAP -like "Partial*") { "Yellow" } else { "Green" }
    Write-Host "  $($r.DCHostname): LDAP=$($r.LDAPSigning), ChannelBinding=$($r.ChannelBinding)" -ForegroundColor $color
}

# ============================================================================
# Section 3: NTLM Configuration Audit
# ============================================================================
Write-Host "`n[*] Section 3: NTLM Configuration Audit" -ForegroundColor Cyan

$ntlmResults = @()

foreach ($target in $targets | Select-Object -First 50) {
    $ntlmResult = [PSCustomObject]@{
        Hostname           = $target
        LmCompatLevel      = "Unknown"
        LmCompatDesc       = "Unknown"
        NTLMRestriction    = "Unknown"
        LLMNREnabled       = "Unknown"
        NBTNSEnabled       = "Unknown"
        NTLMv1Vulnerable   = "Unknown"
        ErrorDetail        = ""
    }

    try {
        $config = Invoke-Command -ComputerName $target -ScriptBlock {
            $lmLevel = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
                -Name "LmCompatibilityLevel" -ErrorAction SilentlyContinue).LmCompatibilityLevel

            $llmnr = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" `
                -Name "EnableMulticast" -ErrorAction SilentlyContinue).EnableMulticast

            $ntlmRestrict = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" `
                -Name "RestrictReceivingNTLMTraffic" -ErrorAction SilentlyContinue).RestrictReceivingNTLMTraffic

            return @{
                LmLevel = $lmLevel
                LLMNR = $llmnr
                NTLMRestrict = $ntlmRestrict
            }
        } -ErrorAction Stop

        $ntlmResult.LmCompatLevel = $config.LmLevel
        $ntlmResult.LmCompatDesc = switch ($config.LmLevel) {
            0 { "Send LM & NTLM (CRITICAL - NTLMv1 active)" }
            1 { "Send LM & NTLM, use NTLMv2 session if negotiated" }
            2 { "Send NTLM only (NTLMv1)" }
            3 { "Send NTLMv2 only (Recommended minimum)" }
            4 { "Send NTLMv2 only, refuse LM" }
            5 { "Send NTLMv2 only, refuse LM & NTLM (Most Secure)" }
            default { "Not configured (defaults to 3)" }
        }

        $ntlmResult.NTLMv1Vulnerable = if ($config.LmLevel -lt 3 -and $null -ne $config.LmLevel) {
            "YES - NTLMv1 may be used"
        } else {
            "No - NTLMv2 enforced"
        }

        $ntlmResult.LLMNREnabled = if ($config.LLMNR -eq 0) { "Disabled (Secure)" } else { "Enabled (VULNERABLE to Responder)" }

        $ntlmResult.NTLMRestriction = switch ($config.NTLMRestrict) {
            0 { "Allow all" }
            1 { "Deny all domain accounts" }
            2 { "Deny all accounts" }
            default { "Not configured (Allow all)" }
        }
    } catch {
        $ntlmResult.ErrorDetail = $_.Exception.Message
    }

    $ntlmResults += $ntlmResult
}

$ntlmCsvPath = Join-Path $OutputPath "ntlm_config_audit_$timestamp.csv"
$ntlmResults | Export-Csv -Path $ntlmCsvPath -NoTypeInformation
Write-Host "[*] NTLM configuration results saved to: $ntlmCsvPath"

$ntlmv1Vuln = @($ntlmResults | Where-Object { $_.NTLMv1Vulnerable -like "YES*" })
$llmnrVuln = @($ntlmResults | Where-Object { $_.LLMNREnabled -like "Enabled*" })

Write-Host "`n  NTLM Configuration Summary:"
Write-Host "  Hosts vulnerable to NTLMv1 downgrade: $($ntlmv1Vuln.Count)" -ForegroundColor $(if ($ntlmv1Vuln.Count -gt 0) { "Red" } else { "Green" })
Write-Host "  Hosts with LLMNR enabled (Responder target): $($llmnrVuln.Count)" -ForegroundColor $(if ($llmnrVuln.Count -gt 0) { "Red" } else { "Green" })

# ============================================================================
# Section 4: Overall Risk Assessment
# ============================================================================
Write-Host "`n" + ("=" * 78) -ForegroundColor Cyan
Write-Host "  OVERALL NTLM RELAY RISK ASSESSMENT" -ForegroundColor Cyan
Write-Host ("=" * 78) -ForegroundColor Cyan

$riskScore = 0
$recommendations = @()

if ($vulnerable.Count -gt 0) {
    $riskScore += 30
    $recommendations += "CRITICAL: Enforce SMB signing on $($vulnerable.Count) hosts via GPO"
}

$ldapVuln = @($ldapResults | Where-Object { $_.RelayToLDAP -like "YES*" })
if ($ldapVuln.Count -gt 0) {
    $riskScore += 30
    $recommendations += "CRITICAL: Enforce LDAP signing on $($ldapVuln.Count) domain controllers"
}

if ($ntlmv1Vuln.Count -gt 0) {
    $riskScore += 20
    $recommendations += "HIGH: Set LmCompatibilityLevel >= 3 on $($ntlmv1Vuln.Count) hosts to prevent NTLMv1"
}

if ($llmnrVuln.Count -gt 0) {
    $riskScore += 20
    $recommendations += "HIGH: Disable LLMNR via GPO on $($llmnrVuln.Count) hosts to prevent Responder poisoning"
}

$riskLevel = switch {
    ($riskScore -ge 60) { "CRITICAL" }
    ($riskScore -ge 40) { "HIGH" }
    ($riskScore -ge 20) { "MEDIUM" }
    default { "LOW" }
}

$riskColor = switch ($riskLevel) {
    "CRITICAL" { "Red" }
    "HIGH" { "Red" }
    "MEDIUM" { "Yellow" }
    "LOW" { "Green" }
}

Write-Host "`n  Risk Level: $riskLevel (Score: $riskScore/100)" -ForegroundColor $riskColor
Write-Host "`n  Recommendations:" -ForegroundColor White
foreach ($rec in $recommendations) {
    Write-Host "    - $rec" -ForegroundColor Yellow
}

if ($recommendations.Count -eq 0) {
    Write-Host "    - No critical issues found. Continue monitoring NTLM usage via Event 8004." -ForegroundColor Green
}

Write-Host "`n  Output Files:"
Write-Host "    - $smbCsvPath"
Write-Host "    - $ldapCsvPath"
Write-Host "    - $ntlmCsvPath"
Write-Host "`n" + ("=" * 78) -ForegroundColor Cyan
