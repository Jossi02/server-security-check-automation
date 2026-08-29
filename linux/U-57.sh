#!/bin/bash

TS="$(date '+%Y-%m-%dT%H:%M:%S%z')"
DIR="$(cd "$(dirname "$0")" && pwd)"
LOGFILE="$DIR/KISA_LOG/U-57.log"
JSON="$DIR/KISA_RESULT/U-57.json"
FILE_PASSWD="${PASSWD_FILE:-/etc/passwd}"

[ -d "$(dirname "$LOGFILE")" ] || mkdir -p "$(dirname "$LOGFILE")"
[ -d "$(dirname "$JSON")" ] || mkdir -p "$(dirname "$JSON")"

DETECT_STATUS="PASS"
REMEDIATE_STATUS="NOT_APPLICABLE"
VULN_COUNT=0
ERROR_COUNT=0

log() { printf '%s\n' "$*" | tee -a "$LOGFILE"; }

log "============= [U-57] Linux Security Assessment ============="
log "[INFO] Historical control U-57; current guide mapping: U-31"
log "[INFO] Checking home directory ownership and other-write permission"

if [ ! -r "$FILE_PASSWD" ]; then
    DETECT_STATUS="ERROR"
    ERROR_COUNT=1
    log "[ERROR] Account database is not readable: $FILE_PASSWD"
else
    while IFS=: read -r username _ uid _ _ homedir _; do
        [[ "$uid" =~ ^[0-9]+$ ]] || continue
        [ "$uid" -ge 1000 ] || continue
        [ "$homedir" != "/" ] || continue
        [ -d "$homedir" ] || continue

        if ! stat_output=$(stat -c '%u %a' -- "$homedir" 2>/dev/null); then
            ERROR_COUNT=$((ERROR_COUNT + 1))
            log "[ERROR] Could not inspect home directory for user [$username]: $homedir"
            continue
        fi

        read -r owner_uid mode <<< "$stat_output"
        owner_mismatch="no"
        other_write="no"
        [ "$owner_uid" = "$uid" ] || owner_mismatch="yes"
        other_digit="${mode: -1}"
        if [[ "$other_digit" =~ ^[0-7]$ ]] && (( (10#$other_digit & 2) != 0 )); then
            other_write="yes"
        fi

        if [ "$owner_mismatch" = "yes" ] || [ "$other_write" = "yes" ]; then
            VULN_COUNT=$((VULN_COUNT + 1))
            log "[VULN] User=[$username] Home=[$homedir] OwnerUID=[$owner_uid] ExpectedUID=[$uid] Mode=[$mode]"
        fi
    done < "$FILE_PASSWD"

    if [ "$VULN_COUNT" -gt 0 ]; then
        DETECT_STATUS="FAIL"
    elif [ "$ERROR_COUNT" -gt 0 ]; then
        DETECT_STATUS="ERROR"
    fi
fi

if [ "$DETECT_STATUS" = "FAIL" ]; then
    REMEDIATE_STATUS="MANUAL_REQUIRED"
    log "[MANUAL] Review each account, then use chown/chmod only after confirming the intended owner and access requirements."
    log "[WARNING] No automatic chmod or chown was performed. Validate changes in a disposable VM and re-run this script."
fi

log "[RESULT] Detect status: $DETECT_STATUS (vulnerable=$VULN_COUNT, errors=$ERROR_COUNT)"
log "[RESULT] Remediation status: $REMEDIATE_STATUS"

cat > "$JSON" <<EOF
{
  "date": "$TS",
  "control_family": "U-57",
  "current_mapping": "U-31",
  "check_target": "Home Directory Ownership and Permission",
  "payload": {
    "severity": "medium",
    "files_checked": ["account database", "existing home directories for UID >= 1000"]
  },
  "results": [
    {"phase": "detect", "status": "$DETECT_STATUS", "vulnerable_count": $VULN_COUNT, "error_count": $ERROR_COUNT},
    {"phase": "remediate", "status": "$REMEDIATE_STATUS", "fixed": false}
  ]
}
EOF

log "[INFO] Script execution finished. Results saved to $JSON"
