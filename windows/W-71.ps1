$OutputEncoding = [System.Text.Encoding]::UTF8
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

$logDir = Join-Path $PSScriptRoot 'KISA_LOG'
$resultDir = Join-Path $PSScriptRoot 'KISA_RESULT'
New-Item -ItemType Directory -Force -Path $logDir, $resultDir | Out-Null

$logFile = Join-Path $logDir 'W-71.log'
$jsonFile = Join-Path $resultDir 'W-71.json'
$targetPath = Join-Path $env:SystemRoot 'System32\config'
$detectStatus = 'ERROR'
$remediateStatus = 'NOT_APPLICABLE'
$detectMessage = ''
$riskyAllowCount = 0
$ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ssK'
$transcriptStarted = $false

try {
    Start-Transcript -Path $logFile -Append | Out-Null
    $transcriptStarted = $true
    Write-Host '========= [W-71] Event Log File Access Check =========' -ForegroundColor Cyan
    Write-Host '[INFO] Historical control W-71; current guide mapping: W-43'

    if (-not (Test-Path -LiteralPath $targetPath)) {
        $detectMessage = "Target directory was not found: $targetPath"
    }
    else {
        try {
            $acl = Get-Acl -LiteralPath $targetPath -ErrorAction Stop
            $everyoneSid = 'S-1-1-0'
            $writeMask = [int][System.Security.AccessControl.FileSystemRights]::WriteData -bor
                [int][System.Security.AccessControl.FileSystemRights]::AppendData -bor
                [int][System.Security.AccessControl.FileSystemRights]::WriteAttributes -bor
                [int][System.Security.AccessControl.FileSystemRights]::WriteExtendedAttributes -bor
                [int][System.Security.AccessControl.FileSystemRights]::Delete -bor
                [int][System.Security.AccessControl.FileSystemRights]::ChangePermissions -bor
                [int][System.Security.AccessControl.FileSystemRights]::TakeOwnership

            $riskyRules = @($acl.Access | Where-Object {
                try {
                    $sid = $_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
                }
                catch {
                    $sid = $_.IdentityReference.Value
                }
                $sid -eq $everyoneSid -and
                    $_.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Allow -and
                    (([int]$_.FileSystemRights -band $writeMask) -ne 0)
            })
            $riskyAllowCount = $riskyRules.Count

            if ($riskyAllowCount -gt 0) {
                $detectStatus = 'FAIL'
                $detectMessage = "$riskyAllowCount Everyone Allow ACE(s) grant write-sensitive rights."
            }
            else {
                $detectStatus = 'PASS'
                $detectMessage = 'No Everyone Allow ACE grants write-sensitive rights on the inspected directory.'
            }
        }
        catch {
            $detectMessage = "ACL could not be read: $($_.Exception.Message)"
        }
    }

    if ($detectStatus -eq 'FAIL') {
        $remediateStatus = 'MANUAL_REQUIRED'
        Write-Host '[MANUAL] Review inheritance, Allow/Deny ordering, and effective access in a disposable VM before changing this ACL.' -ForegroundColor Yellow
        Write-Host '[WARNING] No ACL was changed and no automatic rollback is claimed.' -ForegroundColor Yellow
    }

    $result = [PSCustomObject]@{
        date = $ts
        control_family = 'W-71'
        current_mapping = 'W-43'
        check_target = 'Event Log File Access Restriction'
        scope_limit = 'Inspects Everyone Allow ACEs with write-sensitive rights on System32\config; it does not calculate full effective access for every principal.'
        results = @(
            [PSCustomObject]@{ phase = 'detect'; status = $detectStatus; risky_everyone_allow_count = $riskyAllowCount; msg = $detectMessage },
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
