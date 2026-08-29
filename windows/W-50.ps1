$OutputEncoding = [System.Text.Encoding]::UTF8
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

. (Join-Path $PSScriptRoot 'W-50.Parser.ps1')

$logDir = Join-Path $PSScriptRoot 'KISA_LOG'
$resultDir = Join-Path $PSScriptRoot 'KISA_RESULT'
$backupDir = Join-Path $PSScriptRoot 'KISA_BACKUP'
New-Item -ItemType Directory -Force -Path $logDir, $resultDir, $backupDir | Out-Null

$logFile = Join-Path $logDir 'W-50.log'
$jsonFile = Join-Path $resultDir 'W-50.json'
$detectStatus = 'ERROR'
$remediateStatus = 'NOT_APPLICABLE'
$detectMessage = ''
$remediateMessage = 'Detection did not identify a remediable finding.'
$displayAge = 'Unknown'
$backupFile = 'N/A'
$ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ssK'
$transcriptStarted = $false

try {
    Start-Transcript -Path $logFile -Append | Out-Null
    $transcriptStarted = $true
    Write-Host '========= [W-50] Windows Server Security Assessment =========' -ForegroundColor Cyan
    Write-Host '[INFO] Historical control W-50; current mapping: W-09 password management policy (partial check only)'

    $netOutput = & net.exe accounts 2>&1
    if ($LASTEXITCODE -ne 0) {
        $detectMessage = "net accounts failed with exit code $LASTEXITCODE."
    }
    else {
        $parsed = ConvertFrom-NetAccountsMaximumAge -Lines $netOutput
        $displayAge = $parsed.Display
        if ($parsed.Status -eq 'ERROR') {
            $detectMessage = 'Maximum password age could not be parsed; status is unknown.'
        }
        elseif ($null -eq $parsed.Age -or $parsed.Age -le 0 -or $parsed.Age -gt 90) {
            $detectStatus = 'FAIL'
            $detectMessage = "Local maximum password age is $displayAge."
        }
        else {
            $detectStatus = 'PASS'
            $detectMessage = "Local maximum password age is $displayAge."
            $remediateMessage = 'No remediation needed.'
        }
    }

    Write-Host "[RESULT] Detect status: $detectStatus ($detectMessage)"

    if ($detectStatus -eq 'FAIL') {
        $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
            [Security.Principal.WindowsBuiltInRole]::Administrator
        )
        if (-not $isAdmin) {
            $remediateStatus = 'MANUAL_REQUIRED'
            $remediateMessage = 'Administrator privileges are required; no change was attempted.'
        }
        else {
            $answer = Read-Host 'Set the local maximum password age to 90 days? (y/n)'
            if ($answer -notmatch '^[yY]$') {
                $remediateStatus = 'SKIPPED'
                $remediateMessage = 'Skipped by user; no change was made.'
            }
            else {
                $backupFile = Join-Path $backupDir "W-50_Backup_$(Get-Date -Format 'yyyyMMddHHmmss').inf"
                & secedit.exe /export /cfg $backupFile | Out-Null
                if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $backupFile)) {
                    $remediateStatus = 'ERROR'
                    $remediateMessage = 'Security policy backup failed; remediation was aborted.'
                    $backupFile = 'N/A'
                }
                else {
                    & net.exe accounts /maxpwage:90 | Out-Null
                    $setExitCode = $LASTEXITCODE
                    $verifyOutput = & net.exe accounts 2>&1
                    $verifyExitCode = $LASTEXITCODE
                    $verified = if ($verifyExitCode -eq 0) { ConvertFrom-NetAccountsMaximumAge -Lines $verifyOutput } else { $null }
                    if ($setExitCode -eq 0 -and $verified -and $verified.Status -eq 'OK' -and $verified.Age -eq 90) {
                        $remediateStatus = 'PASS'
                        $remediateMessage = 'Local maximum password age was re-read as 90 days.'
                        $displayAge = '90 days'
                    }
                    else {
                        & secedit.exe /configure /db (Join-Path $backupDir 'W-50-rollback.sdb') /cfg $backupFile /areas SECURITYPOLICY | Out-Null
                        $rollbackExitCode = $LASTEXITCODE
                        $remediateStatus = 'ERROR'
                        $remediateMessage = "Set or verification failed; rollback exit code: $rollbackExitCode."
                    }
                }
            }
        }
    }

    $result = [PSCustomObject]@{
        date = $ts
        control_family = 'W-50'
        current_mapping = 'W-09 (maximum password age sub-element only)'
        check_target = 'Local Maximum Password Age'
        scope_limit = 'Checks the local net accounts policy only; domain policy and the rest of W-09 are out of scope.'
        results = @(
            [PSCustomObject]@{ phase = 'detect'; status = $detectStatus; value = $displayAge; msg = $detectMessage },
            [PSCustomObject]@{ phase = 'remediate'; status = $remediateStatus; value = $displayAge; msg = $remediateMessage; backup = $backupFile }
        )
    }
    $result | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $jsonFile -Encoding UTF8
    Write-Host "[RESULT] Remediation status: $remediateStatus ($remediateMessage)"
    Write-Host "[INFO] Result saved to $jsonFile"
}
finally {
    if ($transcriptStarted) { Stop-Transcript | Out-Null }
}
