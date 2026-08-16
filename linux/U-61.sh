#!/bin/bash

TS="$(date '+%Y-%m-%dT%H:%M:%S%z')"         # 점검 실행 날짜(KST)
TS_FILE="$(date '+%Y%m%d_%H%M%S')"          # 파일 저장용 타임스탬프
DIR="$(cd "$(dirname "$0")" && pwd)"        # 점검 스크립트가 위치한 경로
LOGFILE="$DIR/KISA_LOG/U-61.log"            # 로그 파일 저장 경로 및 파일명
JSON="$DIR/KISA_RESULT/U-61.json"           # 결과 파일 저장 경로 및 파일명(json형식)

mkdir -p "$(dirname "$LOGFILE")" "$(dirname "$JSON")" 

## 점검 할 파일명
FILE_INETD="/etc/inetd.conf"
FILE_VSFTPD="/etc/vsftpd.conf"
FILE_PROFTPD="/etc/proftpd.conf"

## 서비스 활성화 여부 플래그
FTP_ACTIVE="no"

DETECT_STATUS="PASS" 
REMEDIATE_STATUS="FAIL"

RED=$'\e[1;31m' 
GREEN=$'\e[1;32m' 
BOLD=$'\e[1m'  
RESET=$'\e[0m'  

## 화면에 출력한 내용 그대로 log 파일로 저장
log () {
    printf '%s\n' "$*" | tee -a "$LOGFILE"
}

## 표준 에러로 출력 후 log 파일에 저장
err() {
    printf "${RED}[ERROR] %s${RESET}\n" "$*" | tee -a "$LOGFILE" >&2
}

log "$BOLD============= [U-61] Linux Security Assessment =============$RESET"
log "$BOLD[INFO]$RESET FTP service activation assessment"
log "$BOLD[INFO]$RESET Check targets: vsftpd, proftpd, inetd, Port 21"

# --- 1. 탐지 (Detect) ---
log "------------- Detect Result -------------"
DETECT_MSG=""

# 방법 1: systemd 서비스 또는 소켓 확인 (vsftpd, proftpd)
if systemctl is-active --quiet vsftpd.service 2>/dev/null; then
    FTP_ACTIVE="yes"
    DETECT_MSG="Detected active systemd service: vsftpd.service"
elif systemctl is-active --quiet vsftpd.socket 2>/dev/null; then
    FTP_ACTIVE="yes"
    DETECT_MSG="Detected active systemd socket: vsftpd.socket"
elif systemctl is-active --quiet proftpd.service 2>/dev/null; then
    FTP_ACTIVE="yes"
    DETECT_MSG="Detected active systemd service: proftpd.service"
fi

# 방법 2: Port 21 LISTENING 확인 (lport 로 수정)
if [ "$FTP_ACTIVE" = "no" ] && ss -ltn '( lport = :21 )' 2>/dev/null | grep -q .; then
    FTP_ACTIVE="yes"
    DETECT_MSG="Detected active service listening on TCP/21"
fi

# 방법 3: inetd.conf 확인 (구형 방식)
if [ "$FTP_ACTIVE" = "no" ] && [ -r "$FILE_INETD" ] && \
   grep -Eq '^[[:space:]]*ftp[[:space:]]+stream[[:space:]]+tcp' "$FILE_INETD"; then
    FTP_ACTIVE="yes"
    DETECT_MSG="Detected 'ftp' entry in $FILE_INETD"
fi

# 최종 탐지 결과
if [ "$FTP_ACTIVE" = "yes" ]; then
    DETECT_STATUS="FAIL"
    log "$BOLD[INFO]$RESET $DETECT_MSG"
fi

log "$BOLD[RESULT]$RESET Status: $DETECT_STATUS"
log "$BOLD[RESULT]$RESET FTP activation: $FTP_ACTIVE"
log "------------------------------------"

## 탐지 결과 임시 저장
BF_FTP_ACTIVE=$FTP_ACTIVE

# --- 2. 수정 (Remediate) ---
if [ "$DETECT_STATUS" = "FAIL" ]; then
    
    # 사용자에게 조치 여부 확인
    echo -n "$BOLD[QUESTION]$RESET Vulnerability found. Do you want to disable FTP service? (y/n): "
    read user_input

    if [[ "$user_input" == "y" || "$user_input" == "Y" ]]; then
        
        # 롤백 스크립트 생성 준비
        BACKUP_SCRIPT="$DIR/KISA_LOG/U-61_rollback_${TS_FILE}.sh"
        echo "#!/bin/bash" > "$BACKUP_SCRIPT"
        echo "# [U-61] Rollback Script Generated at $TS" >> "$BACKUP_SCRIPT"
        echo "echo 'Starting Rollback for U-61...'" >> "$BACKUP_SCRIPT"
        chmod +x "$BACKUP_SCRIPT"
        
        log "$BOLD[BACKUP]$RESET Rollback script initialized at: $BACKUP_SCRIPT"
        log "$BOLD[REMEDIATE]$RESET Attempting to disable FTP services..."
        
        # 조치 1: vsftpd 서비스 및 소켓 중지/비활성화
        if systemctl list-unit-files vsftpd.service 2>/dev/null | grep -q "vsftpd.service"; then
            # 롤백 명령어 추가
            echo "systemctl enable --now vsftpd.service" >> "$BACKUP_SCRIPT"
            
            systemctl stop vsftpd.service 
            systemctl disable vsftpd.service 
            log "$GREEN[RESULT] Stopped and disabled vsftpd.service.$RESET"
        fi
        if systemctl list-unit-files vsftpd.socket 2>/dev/null | grep -q "vsftpd.socket"; then
            # 롤백 명령어 추가
            echo "systemctl enable --now vsftpd.socket" >> "$BACKUP_SCRIPT"
            
            systemctl stop vsftpd.socket
            systemctl disable vsftpd.socket
            log "$GREEN[RESULT] Stopped and disabled vsftpd.socket.$RESET"
        fi

        # 조치 2: proftpd 중지 및 비활성화
        if systemctl list-unit-files proftpd.service 2>/dev/null | grep -q "proftpd.service"; then
            # 롤백 명령어 추가
            echo "systemctl enable --now proftpd.service" >> "$BACKUP_SCRIPT"
            
            systemctl stop proftpd.service
            systemctl disable proftpd.service
            log "$GREEN[RESULT] Stopped and disabled proftpd.service.$RESET"
        fi

        # 조치 3: inetd.conf 설정 주석 처리
        if [ -r "$FILE_INETD" ] && grep -Eq '^[[:space:]]*ftp[[:space:]]+stream[[:space:]]+tcp' "$FILE_INETD"; then
            # 원본 파일 백업
            INETD_BAK="${FILE_INETD}.bak.${TS_FILE}"
            cp -p "$FILE_INETD" "$INETD_BAK"
            log "$BOLD[BACKUP]$RESET Created backup: $INETD_BAK"
            
            # 롤백 명령어 추가 (백업본으로 원복 및 서비스 재시작)
            echo "cp -f \"$INETD_BAK\" \"$FILE_INETD\"" >> "$BACKUP_SCRIPT"
            echo "killall -HUP inetd" >> "$BACKUP_SCRIPT"
            
            # 조치 수행
            sed -i 's/^\([[:space:]]*ftp[[:space:]]\+stream[[:space:]]\+tcp.*\)/#\1/' "$FILE_INETD"
            log "$GREEN[RESULT] Commented out FTP line in $FILE_INETD.$RESET"
            if pgrep inetd > /dev/null; then
                killall -HUP inetd
                log "$GREEN[RESULT] Reloaded inetd service.$RESET"
            fi
        fi

        # --- 수정 후 재점검  ---
        sleep 1
        RE_CHECK_FTP_ACTIVE="no"
        if systemctl is-active --quiet vsftpd.service 2>/dev/null || \
           systemctl is-active --quiet vsftpd.socket 2>/dev/null || \
           systemctl is-active --quiet proftpd.service 2>/dev/null || \
           (ss -ltn '( lport = :21 )' 2>/dev/null | grep -q .); then
            RE_CHECK_FTP_ACTIVE="yes"
        fi
        
        if [ "$RE_CHECK_FTP_ACTIVE" = "no" ]; then
            REMEDIATE_STATUS="PASS"
            FTP_ACTIVE="no" # 최종 상태 업데이트
            log "$GREEN[RESULT] FTP service successfully disabled.$RESET"
            log "$BOLD[INFO]$RESET Rollback script created: $BACKUP_SCRIPT"
        else
            log "$RED[RESULT] Failed to disable FTP service (re-check failed).$RESET"
        fi
    else
        # 사용자가 n을 입력했을 때
        log "$BOLD[INFO]$RESET Remediation skipped by user."
        REMEDIATE_STATUS="SKIPPED"
        log "$BOLD[RESULT]$RESET No changes were made."
    fi
else
    log "$BOLD[RESULT]$RESET FTP service is already disabled.$RESET"
    REMEDIATE_STATUS="PASS" # 조치할 필요가 없으므로 PASS
fi

# --- 3. 결과 보고 (JSON) ---
cat > "$JSON" <<EOF
{
  "date": "$TS",
  "control_family": "CM-7",
  "check_target": "Disable unnecessary FTP service",
  "discussion": "Good: FTP service is disabled.\nVulnerable: FTP service is enabled.",
  "check_content": "[LINUX]\nCheck Process\n#ps -ef | egrep \"vsftpd|proftpd\"\nCheck inetd.conf\n#vi /etc/inetd.conf\n(Check if 'ftp' line is commented out)",
  "fix_text": "[vsFTPd, ProFTPd]\n#service vsftpd(proftpd) stop\n(or #systemctl stop vsftpd)\n#kill -9 [PID]\n\n[inetd]\n#vi /etc/inetd.conf\n(Before) ftp stream tcp ...\n(After) #ftp stream tcp ...\n#kill -HUP [inetd PID]",
  "payload": {
    "severity": "low",
    "port": [21],
    "service": ["ftp"],
    "protocol": "TCP",
    "threat": ["Sniffing attack", "Plaintext credential transmission", "Data leakage"],
    "TTP": ["T1040"],
    "files_checked": ["$FILE_INETD", "$FILE_VSFTPD", "$FILE_PROFTPD"]
  },
  "results": [
    {
      "phase": "detect",
      "status": "$DETECT_STATUS",
      "ftp_active": "$BF_FTP_ACTIVE"
    },
    {
      "phase": "remediate",
      "status": "$REMEDIATE_STATUS",
      "ftp_active": "$FTP_ACTIVE",
      "backup_file": "$BACKUP_SCRIPT"
    }
  ]
}
EOF

log "$BOLD[INFO]$RESET Script execution finished. Results saved to $JSON$RESET"