#!/bin/bash
set -u

APP_PATH=""
HOURS=24
OUTPUT_DIR=""

usage() {
  echo "Usage: macos_platform_security_audit.sh [--app /Applications/Name.app] [--hours N] [--output DIR]"
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --app) APP_PATH="${2:-}"; shift 2 ;;
    --hours) HOURS="${2:-24}"; shift 2 ;;
    --output) OUTPUT_DIR="${2:-}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; usage; exit 2 ;;
  esac
done

case "$HOURS" in
  ''|*[!0-9]*) echo "--hours must be numeric" >&2; exit 2 ;;
esac

if [ "$(uname -s)" != "Darwin" ]; then
  echo "This toolkit must run on macOS." >&2
  exit 1
fi

STAMP="$(date +%Y%m%d_%H%M%S)"
OUTPUT_DIR="${OUTPUT_DIR:-./platform-security-audit-$STAMP}"
mkdir -p "$OUTPUT_DIR"
REPORT="$OUTPUT_DIR/platform-security-report.txt"
CSV="$OUTPUT_DIR/security-components.csv"
JSON="$OUTPUT_DIR/summary.json"
ERRORS="$OUTPUT_DIR/command-errors.log"
: > "$REPORT"
: > "$ERRORS"
echo 'component,path,version_or_state,present' > "$CSV"

section() {
  title="$1"
  shift
  {
    printf '\n===== %s =====\n' "$title"
    "$@"
  } >> "$REPORT" 2>> "$ERRORS" || true
}

run_shell() {
  title="$1"
  command="$2"
  {
    printf '\n===== %s =====\n' "$title"
    /bin/bash -c "$command"
  } >> "$REPORT" 2>> "$ERRORS" || true
}

record_component() {
  component="$1"
  path="$2"
  state="$3"
  present="$4"
  safe_component=$(printf '%s' "$component" | sed 's/"/""/g')
  safe_path=$(printf '%s' "$path" | sed 's/"/""/g')
  safe_state=$(printf '%s' "$state" | sed 's/"/""/g')
  printf '"%s","%s","%s","%s"\n' "$safe_component" "$safe_path" "$safe_state" "$present" >> "$CSV"
}

plist_value() {
  plist="$1"
  key="$2"
  /usr/libexec/PlistBuddy -c "Print :$key" "$plist" 2>/dev/null || true
}

section "Collection metadata" /bin/bash -c 'date -u +%Y-%m-%dT%H:%M:%SZ; hostname; sw_vers; uname -a; id'
section "Gatekeeper status" /usr/sbin/spctl --status
section "System Integrity Protection status" /usr/bin/csrutil status
section "System Integrity Protection configuration" /usr/bin/csrutil authenticated-root status
section "Security update history" /usr/sbin/system_profiler SPInstallHistoryDataType
run_shell "Security-related packages" '/usr/sbin/pkgutil --pkgs | grep -Ei "XProtect|MRT|Gatekeeper|Security|RapidSecurityResponse" | sort || true'

GATEKEEPER_RAW="$(/usr/sbin/spctl --status 2>/dev/null | tr '\n' ' ' | sed 's/"/\\"/g')"
SIP_RAW="$(/usr/bin/csrutil status 2>/dev/null | tr '\n' ' ' | sed 's/"/\\"/g')"
AUTH_ROOT_RAW="$(/usr/bin/csrutil authenticated-root status 2>/dev/null | tr '\n' ' ' | sed 's/"/\\"/g')"

GATEKEEPER_ENABLED=false
echo "$GATEKEEPER_RAW" | grep -qi 'assessments enabled' && GATEKEEPER_ENABLED=true
SIP_ENABLED=false
echo "$SIP_RAW" | grep -qi 'enabled' && SIP_ENABLED=true

XPROTECT_VERSION="unknown"
XPROTECT_REMEDIATOR_VERSION="unknown"
MRT_VERSION="unknown"

for plist in \
  /Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Info.plist \
  /System/Library/CoreServices/XProtect.bundle/Contents/Info.plist; do
  if [ -f "$plist" ]; then
    XPROTECT_VERSION="$(plist_value "$plist" CFBundleShortVersionString)"
    [ -z "$XPROTECT_VERSION" ] && XPROTECT_VERSION="$(plist_value "$plist" CFBundleVersion)"
    record_component "XProtect" "$plist" "${XPROTECT_VERSION:-unknown}" "true"
    section "XProtect bundle information" /usr/bin/plutil -p "$plist"
    break
  fi
done

for plist in \
  /Library/Apple/System/Library/CoreServices/XProtect.app/Contents/Resources/XProtect.meta.plist \
  /Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Resources/XProtect.meta.plist; do
  if [ -f "$plist" ]; then
    section "XProtect metadata" /usr/bin/plutil -p "$plist"
    record_component "XProtect metadata" "$plist" "present" "true"
    break
  fi
done

for plist in \
  /Library/Apple/System/Library/CoreServices/XProtectRemediator.bundle/Contents/Info.plist \
  /System/Library/CoreServices/XProtectRemediator.bundle/Contents/Info.plist; do
  if [ -f "$plist" ]; then
    XPROTECT_REMEDIATOR_VERSION="$(plist_value "$plist" CFBundleShortVersionString)"
    [ -z "$XPROTECT_REMEDIATOR_VERSION" ] && XPROTECT_REMEDIATOR_VERSION="$(plist_value "$plist" CFBundleVersion)"
    record_component "XProtect Remediator" "$plist" "${XPROTECT_REMEDIATOR_VERSION:-unknown}" "true"
    section "XProtect Remediator information" /usr/bin/plutil -p "$plist"
    break
  fi
done

for plist in \
  /System/Library/CoreServices/MRT.app/Contents/Info.plist \
  /Library/Apple/System/Library/CoreServices/MRT.app/Contents/Info.plist; do
  if [ -f "$plist" ]; then
    MRT_VERSION="$(plist_value "$plist" CFBundleShortVersionString)"
    [ -z "$MRT_VERSION" ] && MRT_VERSION="$(plist_value "$plist" CFBundleVersion)"
    record_component "Malware Removal Tool" "$plist" "${MRT_VERSION:-unknown}" "true"
    section "MRT information" /usr/bin/plutil -p "$plist"
    break
  fi
done

run_shell "Recent platform security events" "/usr/bin/log show --last ${HOURS}h --style compact --predicate '(process CONTAINS[c] \"XProtect\") OR (process CONTAINS[c] \"MRT\") OR (process == \"syspolicyd\") OR (process == \"trustd\") OR (eventMessage CONTAINS[c] \"malware\") OR (eventMessage CONTAINS[c] \"Gatekeeper\") OR (eventMessage CONTAINS[c] \"notarization\")' 2>/dev/null | tail -n 3000"

QUARANTINE_DATABASES=0
QUARANTINE_RECORDS=0
for db in /Users/*/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2; do
  [ -f "$db" ] || continue
  QUARANTINE_DATABASES=$((QUARANTINE_DATABASES + 1))
  if command -v sqlite3 >/dev/null 2>&1; then
    count="$(sqlite3 "$db" 'select count(*) from LSQuarantineEvent;' 2>>"$ERRORS" || echo 0)"
    case "$count" in ''|*[!0-9]*) count=0 ;; esac
    QUARANTINE_RECORDS=$((QUARANTINE_RECORDS + count))
  fi
done
record_component "Quarantine databases" "/Users/*/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2" "$QUARANTINE_DATABASES databases; $QUARANTINE_RECORDS records" "$([ "$QUARANTINE_DATABASES" -gt 0 ] && echo true || echo false)"

APP_ASSESSED=false
APP_SIGNATURE_VALID=false
APP_GATEKEEPER_ACCEPTED=false
APP_NOTARISATION="not-tested"
APP_QUARANTINED=false

if [ -n "$APP_PATH" ]; then
  APP_ASSESSED=true
  if [ -e "$APP_PATH" ]; then
    section "Application metadata" /bin/ls -ldeO@ "$APP_PATH"
    section "Application signature details" /usr/bin/codesign -dvvv --entitlements :- "$APP_PATH"

    if /usr/bin/codesign --verify --deep --strict --verbose=2 "$APP_PATH" >> "$REPORT" 2>> "$ERRORS"; then
      APP_SIGNATURE_VALID=true
    fi

    if /usr/sbin/spctl --assess --type execute -vv "$APP_PATH" >> "$REPORT" 2>> "$ERRORS"; then
      APP_GATEKEEPER_ACCEPTED=true
    fi

    APP_NOTARISATION="$(/usr/sbin/spctl --assess --type execute -vv "$APP_PATH" 2>&1 | tr '\n' ' ' | sed 's/"/\\"/g')"
    /usr/bin/xattr -p com.apple.quarantine "$APP_PATH" >/dev/null 2>&1 && APP_QUARANTINED=true
  else
    printf '\n===== Application assessment =====\nPath not found: %s\n' "$APP_PATH" >> "$REPORT"
  fi
fi

OVERALL="Compliant"
if ! $GATEKEEPER_ENABLED || ! $SIP_ENABLED; then
  OVERALL="Attention required"
fi
if $APP_ASSESSED && { ! $APP_SIGNATURE_VALID || ! $APP_GATEKEEPER_ACCEPTED; }; then
  OVERALL="Attention required"
fi

cat > "$JSON" <<EOF
{
  "collected_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "hostname": "$(hostname)",
  "gatekeeper_enabled": $GATEKEEPER_ENABLED,
  "sip_enabled": $SIP_ENABLED,
  "gatekeeper_status": "$GATEKEEPER_RAW",
  "sip_status": "$SIP_RAW",
  "authenticated_root_status": "$AUTH_ROOT_RAW",
  "xprotect_version": "${XPROTECT_VERSION:-unknown}",
  "xprotect_remediator_version": "${XPROTECT_REMEDIATOR_VERSION:-unknown}",
  "mrt_version": "${MRT_VERSION:-unknown}",
  "quarantine_database_count": $QUARANTINE_DATABASES,
  "quarantine_record_count": $QUARANTINE_RECORDS,
  "application_path": "$APP_PATH",
  "application_assessed": $APP_ASSESSED,
  "application_signature_valid": $APP_SIGNATURE_VALID,
  "application_gatekeeper_accepted": $APP_GATEKEEPER_ACCEPTED,
  "application_has_quarantine_attribute": $APP_QUARANTINED,
  "application_assessment": "$APP_NOTARISATION",
  "overall_status": "$OVERALL"
}
EOF

printf '\nmacOS platform security audit completed: %s\n' "$OUTPUT_DIR" | tee -a "$REPORT"
