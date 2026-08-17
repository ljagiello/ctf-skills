# Graph Activity Logs — Schema & KQL Reference

## Tables

| Table | Covers | Key fields |
|-------|--------|------------|
| `MicrosoftGraphActivityLogs` | graph.microsoft.com requests | `RequestUri`, `RequestMethod`, `UserAgent`, `UserId`, `AppId`, `IPAddress`/`CallerIpAddress`, `ResponseStatusCode`, `SignInActivityId`, `TimeGenerated` |
| `AADGraphActivityLogs` | legacy graph.windows.net requests | `RequestUri`, `RequestMethod`, `UserAgent`, `UserId`, `AppId`, `CallerIpAddress`, `SignInActivityId`, `TimeGenerated` |

## Correlation keys

| Field | Joins to | Note |
|-------|----------|------|
| `SignInActivityId` | `SigninLogs.UniqueTokenIdentifier` | AADGraphActivityLogs value may carry `==` padding; trim before join |
| `SessionId` | SigninLogs / MicrosoftGraphActivityLogs / Unified Audit Log | Cross-source session correlation |
| `UserId` | `SigninLogs.UserId` | Account entity |
| `AppId` | `SigninLogs.AppId` | Calling application |

## Reusable KQL building blocks

```kusto
// Confirm ingestion
union withsource=Tbl MicrosoftGraphActivityLogs, AADGraphActivityLogs
| where TimeGenerated > ago(1d)
| summarize count() by Tbl

// aiohttp / python UA (ROADtools)
AADGraphActivityLogs
| where UserAgent contains "python" and UserAgent contains "aiohttp"

// Toolkit UA strings
union MicrosoftGraphActivityLogs, AADGraphActivityLogs
| where UserAgent has_any ("AADInternals","azurehound","BloodHound","Go-http-client")

// Extract top-level Graph resource from RequestUri
| extend TopLevelResource = tolower(tostring(split(split(RequestUri,"?")[0],"/")[3]))

// Trim SignInActivityId padding for correlation
| extend TokenId = trim_end("=", tostring(SignInActivityId))
```

## Enabling the diagnostic settings (Azure CLI)

```bash
az monitor diagnostic-settings create \
  --name entra-graph-logs \
  --resource "/providers/microsoft.aadiam/diagnosticSettings" \
  --logs '[{"category":"MicrosoftGraphActivityLogs","enabled":true},{"category":"AADGraphActivityLogs","enabled":true}]' \
  --workspace "<log-analytics-workspace-id>"
```

## Sentinel analytics rule (REST API) — outline

| Method | Endpoint | Purpose |
|--------|----------|---------|
| PUT | `/subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.OperationalInsights/workspaces/{ws}/providers/Microsoft.SecurityInsights/alertRules/{ruleId}?api-version=2023-02-01` | Create/update a Scheduled analytics rule (body holds the KQL `query`, `queryFrequency`, `queryPeriod`, `tactics`, `techniques: ["T1078.004"]`, and `entityMappings`) |
