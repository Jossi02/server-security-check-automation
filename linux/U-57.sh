#!/bin/bash

TS="$(date '+%Y-%m-%dT%H:%M:%S%z')"
TS_FILE="$(date '+%Y%m%d_%H%M%S')"
DIR="$(cd "$(dirname "$0")" && pwd)"
LOGFILE="$DIR/KISA_LOG/U-57.log"
JSON="$DIR/KISA_RESULT/U-57.json"

mkdir -p "$(dirname "$LOGFILE")" "$(dirname "$JSON")"

## 점검 대상 파일
FILE_PASSWD="/etc/passwd"

## 플래그 및 상태 변수
VULN_FOUND="no"
DETECT_STATUS="PASS"
REMEDIATE_STATUS="FAIL"

## ANSI 코드
RED=$'\e[1;31m'
GREEN=$'\e[1;32m'
BOLD=$'\e[1m'
RESET=$'\e[0m'

log () {
    printf '%s\n' "$*" | tee -a "$LOGFILE"
}

err () {
    printf "${RED}[ERROR] %s${RESET}\n" "$*" | tee -a "$LOGFILE" >&2
}

log "$BOLD============= [U-57] Linux Security Assessment =============$RESET"
log "$BOLD[INFO]$RESET Checking Home Directory Ownership & Permissions..."
log "$BOLD[INFO]$RESET Target: Regular users (UID >= 1000)"

# --- 1. 탐지 (Detect) ---
log "------------- Detect Result -------------"
VULN_DETAILS=""

# /etc/passwd를 한 줄씩 읽어서 홈 디렉터리 점검
while IFS=: read -r username password uid gid comment homedir shell; do
    
    # 시스템 계정(UID 1000 미만)은 건너뜀
    if [ "$uid" -lt 1000 ]; then
        continue
    fi

    # 1. 홈 디렉터리가 없거나 /dev/null, /bin/false 인 경우 건너뜀
    if [ ! -d "$homedir" ] || [ "$homedir" = "/dev/null" ] || [ "$homedir" = "/bin/false" ] || [ "$homedir" = "/" ]; then
        continue
    fi

    # 2. 소유자 및 권한 확인
    eval $(stat -c "OWNER_UID=%u PERM=%A" "$homedir")

    # 소유자 불일치 확인
    OWNER_MISMATCH="no"
    if [ "$OWNER_UID" -ne "$uid" ]; then
        OWNER_MISMATCH="yes"
    fi

    # 타 사용자(Other) 쓰기 권한 확인 
    OTHER_WRITE="no"
    if [[ "$PERM" =~ ........w. ]]; then  
        perm_other_write=${PERM:8:1}
        if [ "$perm_other_write" == "w" ]; then
            OTHER_WRITE="yes"
        fi
    fi

    if [ "$OWNER_MISMATCH" = "yes" ] || [ "$OTHER_WRITE" = "yes" ]; then
        VULN_FOUND="yes"
        DETECT_STATUS="FAIL"
        
        MSG="User: $username (UID:$uid), Home: $homedir"
        if [ "$OWNER_MISMATCH" = "yes" ]; then MSG="$MSG | [Issue] Wrong Owner (Current: $OWNER_UID)"; fi
        if [ "$OTHER_WRITE" = "yes" ]; then MSG="$MSG | [Issue] Other Write Permitted ($PERM)"; fi
        
        log "$RED[VULN]$RESET $MSG"
        VULN_DETAILS+="$MSG; "
    fi

done < "$FILE_PASSWD"

log "$BOLD[RESULT]$RESET Status: $DETECT_STATUS"
if [ "$VULN_FOUND" = "no" ]; then
    log "$BOLD[RESULT]$RESET All user home directories are secure."
else
    log "$BOLD[RESULT]$RESET Vulnerable home directories found."
fi

# 임시 저장
BF_VULN_FOUND=$VULN_FOUND

# --- 2. 조치 (Remediate) ---
log "------------- Remediate Result -------------"
if [ "$DETECT_STATUS" = "FAIL" ]; then
    
    # 사용자에게 조치 여부 확인
    echo -n "$BOLD[QUESTION]$RESET Vulnerabilities found. Do you want to automatically fix them? (y/n): "
    read user_input

    if [[ "$user_input" == "y" || "$user_input" == "Y" ]]; then
        
        # 백업(Rollback) 스크립트 생성 준비
        BACKUP_FILE="$DIR/KISA_LOG/U-57_rollback_${TS_FILE}.sh"
        echo "#!/bin/bash" > "$BACKUP_FILE"
        echo "# [U-57] Rollback Script Generated at $TS" >> "$BACKUP_FILE"
        echo "echo 'Starting Rollback for U-57...'" >> "$BACKUP_FILE"
        chmod +x "$BACKUP_FILE"
        
        log "$BOLD[BACKUP]$RESET Rollback script initialized at: $BACKUP_FILE"
        log "$BOLD[REMEDIATE]$RESET Attempting to fix ownership and permissions..."
        
        # 다시 반복하며 조치 수행
        while IFS=: read -r username password uid gid comment homedir shell; do
            
            # 시스템 계정 건너뜀 (재확인)
            if [ "$uid" -lt 1000 ]; then
                continue
            fi

            if [ ! -d "$homedir" ] || [ "$homedir" = "/" ]; then continue; fi

            # 현재 상태 확인 (stat)
            eval $(stat -c "OWNER_UID=%u PERM=%A OCTAL=%a GROUP_ID=%g" "$homedir")
            
            # 취약점 여부 재확인
            NEED_FIX="no"
            if [[ "$PERM" =~ ........w. ]]; then NEED_FIX="yes"; fi
            if [ "$OWNER_UID" -ne "$uid" ]; then NEED_FIX="yes"; fi

            # 취약점이 있는 경우에만 백업 및 조치
            if [ "$NEED_FIX" = "yes" ]; then
                # [추가된 부분] 현재 상태를 롤백 스크립트에 기록 (원상복구 명령)
                echo "echo 'Restoring $homedir...'" >> "$BACKUP_FILE"
                echo "chown $OWNER_UID:$GROUP_ID \"$homedir\"" >> "$BACKUP_FILE"
                echo "chmod $OCTAL \"$homedir\"" >> "$BACKUP_FILE"
                
                # 조치 1: Other 쓰기 권한 제거
                if [[ "$PERM" =~ ........w. ]]; then
                     chmod o-w "$homedir"
                     log "$GREEN[FIX]$RESET Removed 'other' write permission on $homedir"
                fi

                # 조치 2: 소유자 변경
                if [ "$OWNER_UID" -ne "$uid" ]; then
                    chown "$username" "$homedir"
                    log "$GREEN[FIX]$RESET Changed owner of $homedir to $username"
                fi
            fi

        done < "$FILE_PASSWD"
        
        REMEDIATE_STATUS="PASS"
        VULN_FOUND="no"
        log "$BOLD[RESULT]$RESET Remediation completed. (Backup saved)"
    else
        # 사용자가 n을 입력했을 때
        log "$BOLD[INFO]$RESET Remediation skipped by user."
        REMEDIATE_STATUS="SKIPPED"
        log "$BOLD[RESULT]$RESET No changes were made."
    fi
else
    log "$BOLD[RESULT]$RESET No remediation needed."
    REMEDIATE_STATUS="PASS"
fi

# --- 3. 결과 보고 (JSON) ---
cat > "$JSON" <<EOF
{
  "date": "$TS",
  "control_family": "AC-3",
  "check_target": "Home Directory Ownership & Permission",
  "payload": {
    "severity": "medium",
    "threat": ["Unauthorized modification", "Privilege Escalation"],
    "files_checked": ["/etc/passwd", "User Home Directories (UID >= 1000)"]
  },
  "results": [
    {
      "phase": "detect",
      "status": "$DETECT_STATUS",
      "details": "$VULN_DETAILS"
    },
    {
      "phase": "remediate",
      "status": "$REMEDIATE_STATUS",
      "fixed": "yes",
      "backup_file": "$BACKUP_FILE"
    }
  ]
}
EOF

log "$BOLD[INFO]$RESET Script execution finished. Results saved to $JSON$RESET"