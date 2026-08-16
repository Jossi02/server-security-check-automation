#!/bin/bash

TS="$(date '+%Y-%m-%dT%H:%M:%S%z')"  
DIR="$(cd "$(dirname "$0")" && pwd)"    
LOGFILE="$DIR/KISA_LOG/U-52.log"  
JSON="$DIR/KISA_RESULT/U-52.json"  

mkdir -p "$(dirname "$LOGFILE")" "$(dirname "$JSON")"

FILE_PASSWD="/etc/passwd"

DETECT_STATUS="FAIL"
REMEDIATE_STATUS="FAIL"
DETECT_MSG=""
REMEDIATE_MSG=""

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

log "$BOLD============= [U-52] Linux Security Assessment =============$RESET"
log "$BOLD[INFO]$RESET Checking for duplicate UIDs in: $FILE_PASSWD"

# --- 1. 탐지 (Detect) ---
# cut으로 3번째 필드(UID) 추출 -> sort -> uniq -d로 중복값만 추출
DUPLICATE_UIDS=$(cut -f3 -d: "$FILE_PASSWD" | sort | uniq -d)

if [ -z "$DUPLICATE_UIDS" ]; then
    DETECT_STATUS="PASS"
    DETECT_MSG="No duplicate UIDs found."
else
    DETECT_STATUS="FAIL"
    UID_LIST=$(echo $DUPLICATE_UIDS | tr '\n' ' ')
    DETECT_MSG="Duplicate UIDs detected: $UID_LIST"
fi

log "------------- Detect Result -------------"
log "$BOLD[RESULT]$RESET Status: $DETECT_STATUS"

if [ "$DETECT_STATUS" = "FAIL" ]; then
    log "$BOLD[INFO]$RESET Detailed Analysis:"
    for uid in $DUPLICATE_UIDS; do
        # 해당 UID를 사용하는 계정명 추출
        ACCOUNTS=$(awk -F: -v uid="$uid" '$3==uid {print $1}' "$FILE_PASSWD" | tr '\n' ', ')
        ACCOUNTS=${ACCOUNTS%, }
        log " -> UID [$uid] is shared by: [$ACCOUNTS]"
    done
else
    log "$BOLD[RESULT]$RESET $DETECT_MSG"
fi
log "------------------------------------"

# --- 2. 조치 (Remediate) ---
if [ "$DETECT_STATUS" = "FAIL" ]; then
    log "$BOLD[INFO]$RESET Starting Remediation Process..."
    
    # 자동 조치 불가 메시지 출력
    err "Automatic remediation is NOT SUPPORTED for U-52 to prevent system instability."
    log "$BOLD[INFO]$RESET Reason: Changing UIDs automatically can break file ownerships, running processes, and system consistency."
    
    # 상세 수동 조치 가이드
    log ""
    log "$BOLD[MANUAL REMEDIATION GUIDE]$RESET"
    log "This vulnerability requires manual action. Please follow the steps below:"
    
    log ""
    log "$BOLD 1. Check Impact Range:$RESET"
    log "   Check how many files are owned by the duplicate UID before changing it."
    log "   (e.g., if duplicate UID is 1001)"
    log "   $ find / -user <OLD_UID>"
    
    log ""
    log "$BOLD 2. Change Account UID:$RESET"
    log "   Change the UID of one of the duplicate accounts to a new, unused UID."
    log "   (e.g., changing 'testuser2' to UID 1002)"
    log "   $ usermod -u <NEW_UID> <USERNAME>"
    
    log ""
    log "$BOLD 3. Change Home Directory Ownership:$RESET"
    log "   Recursively reset ownership so the user can access their home directory correctly."
    log "   (e.g., fixing ownership for testuser2)"
    log "   $ chown -R <USERNAME>:<USERNAME> /home/<USERNAME>"
    
    log ""
    log "$RED[WARNING]$RESET: This operation affects system stability. Perform a SYSTEM BACKUP before proceeding."
    
    REMEDIATE_STATUS="FAIL"
    REMEDIATE_MSG="Manual remediation required. Check the log for the guide."
else
    REMEDIATE_STATUS="PASS"
    REMEDIATE_MSG="No remediation needed."
    log "$BOLD[RESULT]$RESET No changes required."
fi

# --- 3. 결과 보고 (JSON) ---
cat > "$JSON" <<EOF
{
  "date": "$TS",
  "control_family": "U-52",
  "check_target": "Prohibition of duplicate UIDs",
  "discussion": "Good: No duplicate UIDs exist in /etc/passwd.\nVulnerable: Duplicate UIDs exist, which may lead to privilege escalation or audit confusion.",
  "check_content": "#cat /etc/passwd\nCheck 3rd field (UID) for duplicates using 'cut -f3 -d: | sort | uniq -d'.",
  "fix_text": "Manually change the UID using 'usermod -u' and update home directory ownership using 'chown -R'. Ensure to check 'find / -user <UID>' before applying changes.",
  "payload": {
    "severity": "medium",
    "port": [],
    "service": [],
    "protocol": "",
    "threat": ["Privilege Escalation", "Audit Trail Obfuscation", "Identity Confusion"],
    "TTP": ["T1078", "T1098"],
    "files_checked": ["$FILE_PASSWD"]
  },
  "results": [
    {
      "phase": "detect",
      "status": "$DETECT_STATUS",
      "msg": "$DETECT_MSG"
    },
    {
      "phase": "remediate",
      "status": "$REMEDIATE_STATUS",
      "msg": "$REMEDIATE_MSG"
    }
  ]
}
EOF

log "$BOLD[INFO]$RESET Script execution finished. Results saved to $JSON$RESET"