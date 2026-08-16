$OutputEncoding = [System.Text.Encoding]::UTF8
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

$dir = $PSScriptRoot    
$log_dir = Join-Path $dir "KISA_LOG"   
$result_dir = Join-Path $dir "KISA_RESULT"    
$backup_dir = Join-Path $dir "KISA_BACKUP" 

New-Item -ItemType Directory -Force -Path $log_dir, $result_dir, $backup_dir | Out-Null

$log_file = Join-Path $log_dir "W-50.log"              # 로그 파일명
$json_file = Join-Path $result_dir "W-50.json"         # 결과 파일명

$detect_status = "FAIL"
$remediate_status = "FAIL"
$vuln_found = $false

$ts = Get-Date -Format "yyyy-MM-dd HH:mm:ssK" 

try {
    Start-Transcript -Path $log_file -Append
    Write-Host "========= [W-50] Windows Server Security Assessment =========" -ForegroundColor Cyan
    Write-Host "[$ts]"

    ## 1. 탐지
    Write-Host "Step 1: Detecting Password Policy..." -ForegroundColor Cyan

    # net accounts 결과를 문자열로 받음
    $net_output = net accounts

    # "최대 암호 사용 기간" 또는 "Maximum password age"가 포함된 줄을 찾음
    $target_line = $net_output | Where-Object { ($_ -match "최대 암호 사용 기간") -or ($_ -match "Maximum password age") }

    $current_age = -1
    $display_age = "Unknown"

    if ($target_line) {
        $value_str = $target_line.Split(":")[1].Trim()
        
        # "제한 없음" 또는 "Unlimited"인 경우 처리
        if ($value_str -match "제한 없음" -or $value_str -match "Unlimited") {
            $current_age = 99999 # 취약으로 판단하기 위해 매우 큰 수로 설정
            $display_age = "Unlimited"
        } else {
            try {
                $current_age = [int]$value_str
                $display_age = "$current_age days"
            } catch {
                $current_age = 99999
                $display_age = "Unknown ($value_str)"
            }
        }
    }

    Write-Host "[INFO] Current Maximum Password Age: $display_age" -ForegroundColor Cyan

    Write-Host "--------- Detect Result ---------"
    if ($current_age -gt 90 -or $current_age -le 0) {
        $detect_status = "FAIL"
        $vuln_found = $true
        Write-Host "[RESULT] Policy Compliance Status: FAIL" -ForegroundColor Red
    } else {
        $detect_status = "PASS"
        Write-Host "[RESULT] Policy Compliance Status: PASS" -ForegroundColor Green
    }
    Write-Host "----------------------------"

    ## 2. 조치 (Remediate)
    if ($detect_status -eq "FAIL") {
        
        # 사용자 입력 받기
        Write-Host -NoNewline "[QUESTION] Vulnerability found. Do you want to automatically fix it? (y/n): " -ForegroundColor Yellow
        $user_input = Read-Host

        if ($user_input -eq 'y' -or $user_input -eq 'Y') {
            Write-Host "Starting Remediation..." -ForegroundColor Yellow
            
            # 2.1 백업
            $backup_file = Join-Path $backup_dir "W-50_Backup_$(Get-Date -Format 'yyyyMMddHHmmss').inf"
            Write-Host "[BACKUP] Backing up current security policy to: $backup_file" -ForegroundColor Yellow
            secedit /export /cfg $backup_file | Out-Null
            
            if (Test-Path $backup_file) {
                Write-Host "[BACKUP] Backup successful." -ForegroundColor Green
                
                # 2.2 조치 수행
                Write-Host "[FIX] Setting Maximum Password Age to 90 days..." -ForegroundColor Yellow
                
                try {
                    # net accounts 명령어로 설정 변경
                    $null = net accounts /maxpwage:90
                    
                    if ($LASTEXITCODE -eq 0) {
                        Write-Host "[RESULT] Successfully changed password age to 90." -ForegroundColor Green
                        $remediate_status = "PASS"
                        $display_age = "90 days" # 결과 보고 업데이트
                    } else {
                        throw "Command failed"
                    }
                } catch {
                    Write-Host "[ERROR] Failed to set password age. Initiating Rollback..." -ForegroundColor Red
                    
                    # 2.3 롤백 
                    secedit /configure /db secedit.sdb /cfg $backup_file /areas SECURITYPOLICY | Out-Null
                    Write-Host "[ROLLBACK] System policy restored from backup." -ForegroundColor Red
                    $remediate_status = "FAIL"
                }
            } else {
                Write-Host "[ERROR] Backup failed. Remediation aborted for safety." -ForegroundColor Red
                $remediate_status = "FAIL"
            }
        } else {
            # 사용자가 n을 입력한 경우
            Write-Host "[INFO] Remediation skipped by user." -ForegroundColor Yellow
            $remediate_status = "SKIPPED"
        }
    } else {
        Write-Host "[RESULT] No change required." -ForegroundColor Cyan
        $remediate_status = "PASS"
    }

    # 결과 보고서 작성
    $discussion = @"
Good: Maximum password age is set to 90 days or less.
Vulnerable: Maximum password age is not set or greater than 90 days.
"@

    $check_content = @"
Step 1) Start > Run > SECPOL.MSC > Account Policies > Password Policy
Step 2) Set 'Maximum password age' to '90 days'.
"@

    $result = [PSCustomObject]@{
        date = $ts
        control_family = "W-50"
        check_target = "Maximum Password Age"
        discussion = $discussion
        check_content = $check_content
        fix_text = "Set Maximum password age to 90 days."
        payload = [PSCustomObject]@{
            severity = "medium"
            port = ""
            service = ""
            protocol = ""
            threat = @("Brute Force Attack", "Credential Stuffing")
            TTP = @("T1110.001") 
            file_checked = "Net Accounts Command"
            backup_file = if ($vuln_found -and $remediate_status -ne "SKIPPED") { $backup_file } else { "N/A" }
        }
        results = @(
            [PSCustomObject]@{
                phase = "detect"
                status = $detect_status
                value = $display_age
            },
            [PSCustomObject]@{
                phase = "remediate"
                status = $remediate_status
                value = if ($remediate_status -eq "PASS") { "90 days" } else { $display_age }
            }
        )
    }

    ## 결과 파일은 UTF-8로 인코딩하여 json 형식으로 저장
    $result | ConvertTo-Json -Depth 4 | Set-Content -Path $json_file -Encoding UTF8
    
    Write-Host "[INFO] Script execution finished. Result saved to $json_file" -ForegroundColor Cyan
}
finally {
    Stop-Transcript | Out-Null
}