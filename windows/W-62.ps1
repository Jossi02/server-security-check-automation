$OutputEncoding = [System.Text.Encoding]::UTF8
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

$logDir = Join-Path $PSScriptRoot 'KISA_LOG'
$resultDir = Join-Path $PSScriptRoot 'KISA_RESULT'
New-Item -ItemType Directory -Force -Path $logDir, $resultDir | Out-Null

$logFile = Join-Path $logDir 'W-62.log'
$jsonFile = Join-Path $resultDir 'W-62.json'
$regPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\PermittedManagers'
$detectStatus = 'ERROR'
$remediateStatus = 'NOT_APPLICABLE'
$detectMessage = ''
$managerCount = 0
$ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ssK'
$transcriptStarted = $false

try {
    Start-Transcript -Path $logFile -Append | Out-Null
    $transcriptStarted = $true
    Write-Host '========= [W-62] SNMP Access Control Check =========' -ForegroundColor Cyan
    Write-Host '[INFO] Historical control W-62; current guide mapping: W-31'

    try {
        $snmpService = Get-Service -Name 'SNMP' -ErrorAction SilentlyContinue
        if ($null -eq $snmpService) {
            $detectStatus = 'PASS'
            $detectMessage = 'SNMP service is not installed.'
        }
        elseif ($snmpService.Status -ne 'Running') {
            $detectStatus = 'PASS'
            $detectMessage = 'SNMP service is not running.'
        }
        elseif (-not (Test-Path -LiteralPath $regPath)) {
            $detectStatus = 'FAIL'
            $detectMessage = 'SNMP is running and PermittedManagers is absent.'
        }
        else {
            $key = Get-Item -LiteralPath $regPath -ErrorAction Stop
            $managerCount = @(
                $key.GetValueNames() | Where-Object {
                    -not [string]::IsNullOrWhiteSpace([string]$key.GetValue($_, $null, 'DoNotExpandEnvironmentNames'))
                }
            ).Count
            if ($managerCount -eq 0) {
                $detectStatus = 'FAIL'
                $detectMessage = 'SNMP is running and no non-empty permitted manager values exist.'
            }
            else {
                $detectStatus = 'PASS'
                $detectMessage = "$managerCount permitted manager value(s) are configured."
            }
        }
    }
    catch {
        $detectStatus = 'ERROR'
        $detectMessage = "SNMP configuration could not be read: $($_.Exception.Message)"
    }

    if ($detectStatus -eq 'FAIL') {
        $remediateStatus = 'MANUAL_REQUIRED'
        Write-Host '[MANUAL] Add only explicitly approved manager addresses, then restart SNMP and re-run this check.' -ForegroundColor Yellow
        Write-Host '[WARNING] No localhost value was injected and no existing manager was removed.' -ForegroundColor Yellow
    }

    $result = [PSCustomObject]@{
        date = $ts
        control_family = 'W-62'
        current_mapping = 'W-31'
        check_target = 'SNMP Access Control Configuration'
        results = @(
            [PSCustomObject]@{ phase = 'detect'; status = $detectStatus; permitted_manager_count = $managerCount; msg = $detectMessage },
            [PSCustomObject]@{ phase = 'remediate'; status = $remediateStatus; changed = $false; msg = 'Manual remediation only.' }
        )
    }
    $result | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $jsonFile -Encoding UTF8
    Write-Host "[RESULT] Detect status: $detectStatus ($detectMessage)"
    Write-Host "[RESULT] Remediation status: $remediateStatus"
}
finally {
    if ($transcriptStarted) { Stop-Transcript | Out-Null }
}
