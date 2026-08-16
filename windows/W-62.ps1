$OutputEncoding = [System.Text.Encoding]::UTF8
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

$dir = $PSScriptRoot
$log_dir = Join-Path $dir "KISA_LOG"
$result_dir = Join-Path $dir "KISA_RESULT"
$backup_dir = Join-Path $dir "KISA_BACKUP"

# 디렉터리 생성
New-Item -ItemType Directory -Force -Path $log_dir, $result_dir, $backup_dir | Out-Null

$log_file = Join-Path $log_dir "W-62.log"
$json_file = Join-Path $result_dir "W-62.json"

$detect_status = "FAIL"
$remediate_status = "FAIL"
$ts = Get-Date -Format "yyyy-MM-dd HH:mm:ssK"
$detect_msg = ""
$remediate_msg = ""

try {
    Start-Transcript -Path $log_file -Append
    Write-Host "========= [W-62] SNMP Access Control Check =========" -ForegroundColor Cyan
    Write-Host "[$ts]"

    # --- Step 1. 탐지 (Detect) ---
    Write-Host "Step 1: Checking SNMP Service and Access Control settings..." -ForegroundColor Cyan

    $snmp_service = Get-Service -Name "SNMP" -ErrorAction SilentlyContinue
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\PermittedManagers"

    if ($null -eq $snmp_service) {
        $detect_status = "PASS" # 설치되지 않음 = 취약점 없음
        $detect_msg = "SNMP Service is NOT installed."
        Write-Host "[INFO] $detect_msg" -ForegroundColor Green
    }
    elseif ($snmp_service.Status -ne 'Running') {
        $detect_status = "PASS"
        $detect_msg = "SNMP Service is Stopped."
        Write-Host "[INFO] $detect_msg" -ForegroundColor Green
    }
    else {
        # 서비스 실행 중 -> 레지스트리 설정 확인
        $managers = Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue
        
        # PermittedManagers가 없거나 비어있으면 취약
        if ($null -eq $managers -or $managers.PSObject.Properties.Value.Count -eq 0) {
            $detect_status = "FAIL"
            $detect_msg = "SNMP Service running, but NO Access Control configured."
            Write-Host "[INFO] Vulnerability Detected: No SNMP Access Control." -ForegroundColor Red
        } else {
            $detect_status = "PASS"
            $detect_msg = "SNMP Access Control is configured."
            Write-Host "[INFO] Secure: $detect_msg" -ForegroundColor Green
        }
    }

    Write-Host "--------- Detect Result ---------"
    Write-Host "[RESULT] Status: $detect_status" -ForegroundColor Cyan
    Write-Host "---------------------------------"

    # --- Step 2. 조치 (Remediate) ---
    if ($detect_status -eq "FAIL") {
        
        # 사용자 입력 받기
        Write-Host -NoNewline "[QUESTION] Vulnerability found. Do you want to automatically fix it? (y/n): " -ForegroundColor Yellow
        $user_input = Read-Host

        if ($user_input -eq 'y' -or $user_input -eq 'Y') {
            Write-Host "[INFO] Starting Remediation..." -ForegroundColor Yellow
            
            # 2.1 백업
            $backup_file = Join-Path $backup_dir "W-62_RegBackup_$((Get-Date).ToString('yyyyMMddHHmmss')).reg"
            $reg_export_cmd = "reg export HKLM\SYSTEM\CurrentControlSet\Services\SNMP\Parameters $backup_file /y"
            
            # 실행 및 로그 출력
            cmd /c $reg_export_cmd | Out-Null
            
            if (Test-Path $backup_file) {
                Write-Host "[BACKUP] Registry backed up to: $backup_file" -ForegroundColor Gray
                
                try {
                    # 2.2 조치
                    Write-Host "[FIX] Configuring PermittedManagers to 127.0.0.1 (Localhost)..." -ForegroundColor Yellow
                    
                    if (!(Test-Path $regPath)) { New-Item -Path $regPath -Force | Out-Null }
                    
                    # 기존 값 덮어쓰기 or 새로 생성
                    New-ItemProperty -Path $regPath -Name "1" -Value "127.0.0.1" -PropertyType String -Force | Out-Null
                    
                    # 서비스 재시작
                    Restart-Service -Name "SNMP" -Force
                    
                    $remediate_status = "PASS"
                    $remediate_msg = "Changed PermittedManagers to '127.0.0.1' (Localhost only)."
                    Write-Host "[RESULT] Remediation Successful." -ForegroundColor Green
                }
                catch {
                    $remediate_msg = "Error during fix: $($_.Exception.Message)"
                    Write-Host "[ERROR] Remediation Failed." -ForegroundColor Red
                }
            } else {
                $remediate_msg = "Backup Failed. Remediation aborted."
                Write-Host "[ERROR] Backup failed. Remediation aborted for safety." -ForegroundColor Red
            }
        } else {
            # 사용자가 n을 입력한 경우
            Write-Host "[INFO] Remediation skipped by user." -ForegroundColor Yellow
            $remediate_status = "SKIPPED"
            $remediate_msg = "Skipped by user"
        }
    } else {
        $remediate_status = "PASS"
        $remediate_msg = "No change required."
        Write-Host "[RESULT] No change required." -ForegroundColor Cyan
    }

    # --- JSON 리포트 생성 ---
    $discussion = @"
Good: SNMP service is disabled or PermittedManagers are configured.
Vulnerable: SNMP service is running and accepts packets from any host.
"@
    $check_content = @"
1. Check if SNMP Service is running.
2. Check Registry: HKLM\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\PermittedManagers
"@

    $result = [PSCustomObject]@{
        date = $ts
        control_family = "W-62"
        check_target = "SNMP Access Control Configuration"
        discussion = $discussion
        check_content = $check_content
        fix_text = "Configure PermittedManagers to allow specific hosts only."
        payload = [PSCustomObject]@{
            severity = "Medium"
            port = "161"
            service = "SNMP"
            protocol = "UDP"
            threat = @("Network Sniffing", "Information Disclosure")
            TTP = @("T1040", "T1592")
            file_checked = $regPath
        }
        results = @(
            [PSCustomObject]@{
                phase = "detect"
                status = $detect_status
                msg = $detect_msg
            },
            [PSCustomObject]@{
                phase = "remediate"
                status = $remediate_status
                msg = $remediate_msg
                # 백업 파일은 실제 조치가 수행된 경우에만 기록
                backup = if ($detect_status -eq "FAIL" -and $remediate_status -ne "SKIPPED") { $backup_file } else { "N/A" }
            }
        )
    }

    $result | ConvertTo-Json -Depth 4 | Set-Content -Path $json_file -Encoding UTF8

    Write-Host "[INFO] Script execution finished. Result saved to $json_file" -ForegroundColor Cyan
}
finally {
    Stop-Transcript | Out-Null
}