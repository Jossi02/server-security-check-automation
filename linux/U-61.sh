#!/bin/bash

TS="$(date '+%Y-%m-%dT%H:%M:%S%z')"
DIR="$(cd "$(dirname "$0")" && pwd)"
LOGFILE="$DIR/KISA_LOG/U-61.log"
JSON="$DIR/KISA_RESULT/U-61.json"
FILE_INETD="/etc/inetd.conf"

[ -d "$(dirname "$LOGFILE")" ] || mkdir -p "$(dirname "$LOGFILE")"
[ -d "$(dirname "$JSON")" ] || mkdir -p "$(dirname "$JSON")"

DETECT_STATUS="PASS"
REMEDIATE_STATUS="NOT_APPLICABLE"
FTP_ACTIVE="no"
CHECK_METHODS=0
FILES_CHECKED_JSON="[]"

log() { printf '%s\n' "$*" | tee -a "$LOGFILE"; }

log "============= [U-61] Linux Security Assessment ============="
log "[INFO] Historical control U-61; closest current concept: U-54 (disable unencrypted FTP)"

if command -v systemctl >/dev/null 2>&1 && systemctl list-unit-files --no-legend >/dev/null 2>&1; then
    CHECK_METHODS=$((CHECK_METHODS + 1))
    for unit in vsftpd.service vsftpd.socket proftpd.service; do
        if systemctl is-active --quiet "$unit" 2>/dev/null; then
            FTP_ACTIVE="yes"
            log "[VULN] Active systemd unit: $unit"
        fi
    done
fi

if command -v ss >/dev/null 2>&1 && listeners=$(ss -H -ltn 'sport = :21' 2>/dev/null); then
    CHECK_METHODS=$((CHECK_METHODS + 1))
    if [ -n "$listeners" ]; then
        FTP_ACTIVE="yes"
        log "[VULN] A TCP listener is bound to port 21."
    fi
fi

if [ -r "$FILE_INETD" ]; then
    CHECK_METHODS=$((CHECK_METHODS + 1))
    FILES_CHECKED_JSON='["/etc/inetd.conf"]'
    if grep -Eq '^[[:space:]]*ftp[[:space:]]+stream[[:space:]]+tcp' "$FILE_INETD"; then
        FTP_ACTIVE="yes"
        log "[VULN] Active FTP entry found in $FILE_INETD"
    fi
fi

if [ "$FTP_ACTIVE" = "yes" ]; then
    DETECT_STATUS="FAIL"
    REMEDIATE_STATUS="MANUAL_REQUIRED"
    log "[MANUAL] Confirm the owning service and business need, then disable only the active FTP unit or inetd entry."
    log "[WARNING] No service, socket, or configuration was changed. Record enabled/active state before any VM remediation."
elif [ "$CHECK_METHODS" -eq 0 ]; then
    DETECT_STATUS="ERROR"
    REMEDIATE_STATUS="NOT_APPLICABLE"
    log "[ERROR] No supported FTP detection method was available."
fi

log "[RESULT] Detect status: $DETECT_STATUS"
log "[RESULT] FTP activation: $FTP_ACTIVE"
log "[RESULT] Remediation status: $REMEDIATE_STATUS"

cat > "$JSON" <<EOF
{
  "date": "$TS",
  "control_family": "U-61",
  "current_mapping": "U-54 (closest concept)",
  "check_target": "Disable unencrypted FTP service",
  "payload": {
    "severity": "low",
    "port": [21],
    "service": ["ftp"],
    "protocol": "TCP",
    "files_checked": $FILES_CHECKED_JSON,
    "ttp_mapping": "historical metadata removed; not revalidated"
  },
  "results": [
    {"phase": "detect", "status": "$DETECT_STATUS", "ftp_active": "$FTP_ACTIVE"},
    {"phase": "remediate", "status": "$REMEDIATE_STATUS", "changed": false}
  ]
}
EOF

log "[INFO] Script execution finished. Results saved to $JSON"
