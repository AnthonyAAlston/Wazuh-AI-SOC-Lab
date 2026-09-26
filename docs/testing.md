# Testing

## Wazuh FIM — file creation

```powershell
"created $(Get-Date -Format o)" | Set-Content 'C:\Wazuh-FIM-Test\ai-test.txt'
```

Observed: **Rule 554 — File added to the system.**

## Wazuh FIM — modification

```powershell
"modified $(Get-Date -Format o)" | Add-Content 'C:\Wazuh-FIM-Test\ai-test.txt'
```

Observed: **Rule 550 — Integrity checksum changed.**

## NetAlertX API

```powershell
$token = Read-Host "Enter NetAlertX API token"
$headers = @{ Authorization = "Bearer $token" }
Invoke-RestMethod -Uri "http://192.168.1.245:20212/devices" -Headers $headers
```

Result: authenticated JSON response received successfully.

## AI API

```powershell
$key = Read-Host "Enter local API key"
$headers = @{ "X-API-Key" = $key }
Invoke-RestMethod -Uri "http://192.168.1.245:8010/api/latest" -Headers $headers
```

Result: structured AI analysis returned successfully.

## Scope note
Grafana was installed and its Infinity plugin was installed, but the final dashboard integration was not completed.
