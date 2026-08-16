$OutputEncoding = [System.Text.Encoding]::UTF8
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

$dir = $PSScriptRoot
$log_dir = Join-Path $dir "KISA_LOG"
$result_dir = Join-Path $dir "KISA_RESULT"
$backup_dir = Join-Path $dir "KISA_BACKUP"

# 디렉터리 생성
New-Item -ItemType Directory -Force -Path $log_dir, $result_dir, $backup_dir | Out-Null

$log_file = Join-Path $log_dir "W-71.log"
$json_file = Join-Path $result_dir "W-71.json"

$detect_status = "FAIL"
$remediate_status = "FAIL"
$ts = Get-Date -Format "yyyy-MM-dd HH:mm:ssK"
$detect_msg = ""
$remediate_msg = ""
$target_path = "$env:SystemRoot\System32\config"

try {
    Start-Transcript -Path $log_file -Append
    Write-Host "========= [W-71] Remote Event Log Access Block =========" -ForegroundColor Cyan
    Write-Host "[$ts]"

    # --- Step 1. 탐지 (Detect) ---
    Write-Host "Step 1: Checking Access Permissions for: $target_path" -ForegroundColor Cyan

    if (Test-Path $target_path) {
        $acl = Get-Acl -Path $target_path
        
        # 'Everyone' 권한 필터링
        $vulnerable = $acl.Access | Where-Object { 
            $_.IdentityReference -like "*Everyone*" -or $_.IdentityReference.Value -eq "Everyone" 
        }

        if ($vulnerable) {
            $detect_status = "FAIL"
            $detect_msg = "Vulnerability Detected: 'Everyone' permission exists."
            Write-Host "[INFO] $detect_msg" -ForegroundColor Red
        } else {
            $detect_status = "PASS"
            $detect_msg = "Secure: No 'Everyone' permission found."
            Write-Host "[INFO] $detect_msg" -ForegroundColor Green
        }
    } else {
        $detect_status = "ERROR"
        $detect_msg = "Target directory not found."
        Write-Host "[ERROR] $detect_msg" -ForegroundColor Red
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
            
            $backup_file = Join-Path $backup_dir "W-71_ACL_Backup_$((Get-Date).ToString('yyyyMMddHHmmss')).txt"
            
            try {
                # 2.1 백업 (Backup)
                $sddl = $acl.GetSecurityDescriptorSddlForm("All")
                $sddl | Out-File -FilePath $backup_file -Encoding UTF8
                Write-Host "[BACKUP] ACL backed up to: $backup_file" -ForegroundColor Gray
                
                # 2.2 제거 (Remove)
                Write-Host "[FIX] Removing 'Everyone' permission from ACL..." -ForegroundColor Yellow
                
                foreach ($rule in $vulnerable) {
                    $acl.RemoveAccessRule($rule) | Out-Null
                }
                # 2.3 적용 (Commit)
                Set-Acl -Path $target_path -AclObject $acl
                
                # 재검증 (Verification)
                $new_acl = Get-Acl -Path $target_path
                if (!($new_acl.Access | Where-Object { $_.IdentityReference -like "*Everyone*" })) {
                    $remediate_status = "PASS"
                    $remediate_msg = "Successfully removed 'Everyone' permission."
                    Write-Host "[RESULT] Remediation Successful." -ForegroundColor Green
                } else {
                    throw "Verification failed. 'Everyone' permission still exists."
                }
            }
            catch {
                $remediate_msg = "Error during fix: $($_.Exception.Message)"
                Write-Host "[ERROR] Remediation Failed." -ForegroundColor Red
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
Good: 'Everyone' permission is NOT present in Log directory.
Vulnerable: 'Everyone' permission IS present in Log directory.
"@
    $check_content = @"
Check ACL of $target_path for 'Everyone' group.
"@

    $result = [PSCustomObject]@{
        date = $ts
        control_family = "W-71"
        check_target = "Restrict Remote Access to Event Logs"
        discussion = $discussion
        check_content = $check_content
        fix_text = "Remove 'Everyone' from System32\config directory permissions."
        payload = [PSCustomObject]@{
            severity = "Medium"
            port = ""
            service = "EventLog"
            protocol = ""
            threat = @("Indicator Removal", "Defense Evasion")
            TTP = @("T1070", "T1562")
            file_checked = $target_path
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