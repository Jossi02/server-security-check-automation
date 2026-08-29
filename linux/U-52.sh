#!/bin/bash

TS="$(date '+%Y-%m-%dT%H:%M:%S%z')"
DIR="$(cd "$(dirname "$0")" && pwd)"
LOGFILE="$DIR/KISA_LOG/U-52.log"
JSON="$DIR/KISA_RESULT/U-52.json"
FILE_PASSWD="${PASSWD_FILE:-/etc/passwd}"

[ -d "$(dirname "$LOGFILE")" ] || mkdir -p "$(dirname "$LOGFILE")"
[ -d "$(dirname "$JSON")" ] || mkdir -p "$(dirname "$JSON")"

DETECT_STATUS="ERROR"
REMEDIATE_STATUS="NOT_APPLICABLE"
DETECT_MSG="Unable to read the account database."
REMEDIATE_MSG="Detection did not complete."

log() { printf '%s\n' "$*" | tee -a "$LOGFILE"; }

log "============= [U-52] Linux Security Assessment ============="
log "[INFO] Historical control U-52; current guide mapping: U-10"
log "[INFO] Checking for duplicate UIDs in: $FILE_PASSWD"

DUPLICATE_UIDS=""
if [ -r "$FILE_PASSWD" ]; then
    if DUPLICATE_UIDS=$(cut -d: -f3 "$FILE_PASSWD" | awk '/^[0-9]+$/' | sort -n | uniq -d); then
        if [ -z "$DUPLICATE_UIDS" ]; then
            DETECT_STATUS="PASS"
            DETECT_MSG="No duplicate UIDs found."
            REMEDIATE_STATUS="NOT_APPLICABLE"
            REMEDIATE_MSG="No remediation needed."
        else
            DETECT_STATUS="FAIL"
            DETECT_MSG="Duplicate UIDs detected; see the log for affected accounts."
            REMEDIATE_STATUS="MANUAL_REQUIRED"
            REMEDIATE_MSG="Manual remediation required; no automatic changes were made."
        fi
    fi
fi

log "------------- Detect Result -------------"
log "[RESULT] Status: $DETECT_STATUS"
if [ "$DETECT_STATUS" = "FAIL" ]; then
    while IFS= read -r uid; do
        accounts=$(awk -F: -v uid="$uid" '$3 == uid { print $1 }' "$FILE_PASSWD" | paste -sd, -)
        log "[VULN] UID [$uid] is shared by: [$accounts]"
    done <<< "$DUPLICATE_UIDS"
    log "[MANUAL] Review account ownership and dependencies, select a new unused UID, then update affected file ownerships."
    log "[WARNING] Back up the system and test the change in a disposable VM first."
elif [ "$DETECT_STATUS" = "ERROR" ]; then
    log "[ERROR] $DETECT_MSG"
else
    log "[RESULT] $DETECT_MSG"
fi

cat > "$JSON" <<EOF
{
  "date": "$TS",
  "control_family": "U-52",
  "current_mapping": "U-10",
  "check_target": "Prohibition of duplicate UIDs",
  "payload": {
    "severity": "medium",
    "files_checked": ["account database"],
    "ttp_mapping": "historical metadata removed; not revalidated"
  },
  "results": [
    {"phase": "detect", "status": "$DETECT_STATUS", "msg": "$DETECT_MSG"},
    {"phase": "remediate", "status": "$REMEDIATE_STATUS", "msg": "$REMEDIATE_MSG"}
  ]
}
EOF

log "[INFO] Script execution finished. Results saved to $JSON"
