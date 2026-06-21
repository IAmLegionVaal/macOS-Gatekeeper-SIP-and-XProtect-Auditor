#!/bin/bash
set -u

APP_PATH=""
HOURS=24
OUTPUT_DIR=""
REPAIR=false
DRY_RUN=false
ASSUME_YES=false

usage() {
  cat <<'EOF'
Usage: macos_platform_security_audit.sh [options]

Options:
  --app PATH      Assess an application bundle
  --hours N       Log lookback in hours (default: 24)
  --output DIR    Report directory
  --repair        Enable Gatekeeper, refresh security data, and restart syspolicyd
  --dry-run       Show repair commands without executing them
  --yes           Skip the repair confirmation prompt
  -h, --help      Show help

SIP cannot be enabled from a normal macOS boot; the report provides guidance.
Exit codes: 0 compliant/success, 10 attention required, 20 repair failed,
            2 invalid arguments, 3 platform/privilege error.
EOF
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --app) APP_PATH="${2:-}"; shift 2 ;;
    --hours) HOURS="${2:-24}"; shift 2 ;;
    --output) OUTPUT_DIR="${2:-}"; shift 2 ;;
    --repair) REPAIR=true; shift ;;
    --dry-run) DRY_RUN=true; shift ;;
    --yes) ASSUME_YES=true; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; usage; exit 2 ;;
  esac
done
case "$HOURS" in ''|*[!0-9]*) echo "--hours must be numeric" >&2; exit 2 ;; esac
[ "$(uname -s)" = "Darwin" ] || { echo "This toolkit must run on macOS." >&2; exit 3; }
if $REPAIR && [ "$(id -u)" -ne 0 ]; then echo "Repair mode requires sudo." >&2; exit 3; fi

STAMP="$(date +%Y%m%d_%H%M%S)"
OUTPUT_DIR="${OUTPUT_DIR:-./platform-security-audit-$STAMP}"
mkdir -p "$OUTPUT_DIR"
REPORT="$OUTPUT_DIR/platform-security-report.txt"
CSV="$OUTPUT_DIR/security-components.csv"
JSON="$OUTPUT_DIR/summary.json"
ERRORS="$OUTPUT_DIR/command-errors.log"
ACTION_LOG="$OUTPUT_DIR/repair-actions.log"
BACKUP_DIR="$OUTPUT_DIR/pre-repair-backup"
: > "$REPORT"; : > "$ERRORS"; : > "$ACTION_LOG"
echo 'component,path,version_or_state,present' > "$CSV"

section() { title="$1"; shift; { printf '\n===== %s =====\n' "$title"; "$@"; } >> "$REPORT" 2>> "$ERRORS" || true; }
run_shell() { title="$1"; command="$2"; { printf '\n===== %s =====\n' "$title"; /bin/bash -c "$command"; } >> "$REPORT" 2>> "$ERRORS" || true; }
log_action() { printf '%s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" | tee -a "$ACTION_LOG"; }
run_action() {
  description="$1"; shift
  if $DRY_RUN; then log_action "DRY-RUN: $description :: $*"; return 0; fi
  log_action "RUN: $description :: $*"
  if "$@" >> "$ACTION_LOG" 2>&1; then log_action "OK: $description"; return 0; fi
  log_action "FAILED: $description"; return 1
}
confirm_repair() {
  $ASSUME_YES && return 0
  printf 'Apply guarded platform-security repairs? [y/N] '
  read answer
  case "$answer" in y|Y|yes|YES) return 0 ;; *) echo "Repair cancelled."; exit 10 ;; esac
}
record_component() {
  component="$1"; path="$2"; state="$3"; present="$4"
  printf '"%s","%s","%s","%s"\n' \
    "$(printf '%s' "$component" | sed 's/"/""/g')" \
    "$(printf '%s' "$path" | sed 's/"/""/g')" \
    "$(printf '%s' "$state" | sed 's/"/""/g')" "$present" >> "$CSV"
}
plist_value() { /usr/libexec/PlistBuddy -c "Print :$2" "$1" 2>/dev/null || true; }

section "Collection metadata" /bin/bash -c 'date -u +%Y-%m-%dT%H:%M:%SZ; hostname; sw_vers; uname -a; id'
section "Gatekeeper status" /usr/sbin/spctl --status
section "System Integrity Protection status" /usr/bin/csrutil status
section "Authenticated root status" /usr/bin/csrutil authenticated-root status
section "Security update history" /usr/sbin/system_profiler SPInstallHistoryDataType
run_shell "Security-related packages" '/usr/sbin/pkgutil --pkgs | grep -Ei "XProtect|MRT|Gatekeeper|Security|RapidSecurityResponse" | sort || true'
run_shell "Recent platform security events" "/usr/bin/log show --last ${HOURS}h --style compact --predicate '(process CONTAINS[c] \"XProtect\") OR (process CONTAINS[c] \"MRT\") OR (process == \"syspolicyd\") OR (process == \"trustd\") OR (eventMessage CONTAINS[c] \"malware\") OR (eventMessage CONTAINS[c] \"Gatekeeper\")' 2>/dev/null | tail -n 3000"

GATEKEEPER_RAW="$(/usr/sbin/spctl --status 2>/dev/null | tr '\n' ' ' | sed 's/"/\\"/g')"
SIP_RAW="$(/usr/bin/csrutil status 2>/dev/null | tr '\n' ' ' | sed 's/"/\\"/g')"
AUTH_ROOT_RAW="$(/usr/bin/csrutil authenticated-root status 2>/dev/null | tr '\n' ' ' | sed 's/"/\\"/g')"
GATEKEEPER_ENABLED=false
echo "$GATEKEEPER_RAW" | grep -qi 'assessments enabled' && GATEKEEPER_ENABLED=true
SIP_ENABLED=false
echo "$SIP_RAW" | grep -qi 'enabled' && SIP_ENABLED=true

XPROTECT_VERSION="unknown"; XPROTECT_REMEDIATOR_VERSION="unknown"; MRT_VERSION="unknown"
for plist in /Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Info.plist /System/Library/CoreServices/XProtect.bundle/Contents/Info.plist; do
  [ -f "$plist" ] || continue
  XPROTECT_VERSION="$(plist_value "$plist" CFBundleShortVersionString)"; [ -n "$XPROTECT_VERSION" ] || XPROTECT_VERSION="$(plist_value "$plist" CFBundleVersion)"
  record_component "XProtect" "$plist" "${XPROTECT_VERSION:-unknown}" true; section "XProtect information" /usr/bin/plutil -p "$plist"; break
done
for plist in /Library/Apple/System/Library/CoreServices/XProtectRemediator.bundle/Contents/Info.plist /System/Library/CoreServices/XProtectRemediator.bundle/Contents/Info.plist; do
  [ -f "$plist" ] || continue
  XPROTECT_REMEDIATOR_VERSION="$(plist_value "$plist" CFBundleShortVersionString)"; [ -n "$XPROTECT_REMEDIATOR_VERSION" ] || XPROTECT_REMEDIATOR_VERSION="$(plist_value "$plist" CFBundleVersion)"
  record_component "XProtect Remediator" "$plist" "${XPROTECT_REMEDIATOR_VERSION:-unknown}" true; break
done
for plist in /System/Library/CoreServices/MRT.app/Contents/Info.plist /Library/Apple/System/Library/CoreServices/MRT.app/Contents/Info.plist; do
  [ -f "$plist" ] || continue
  MRT_VERSION="$(plist_value "$plist" CFBundleShortVersionString)"; [ -n "$MRT_VERSION" ] || MRT_VERSION="$(plist_value "$plist" CFBundleVersion)"
  record_component "Malware Removal Tool" "$plist" "${MRT_VERSION:-unknown}" true; break
done

APP_ASSESSED=false; APP_SIGNATURE_VALID=false; APP_GATEKEEPER_ACCEPTED=false; APP_QUARANTINED=false
if [ -n "$APP_PATH" ]; then
  APP_ASSESSED=true
  if [ -e "$APP_PATH" ]; then
    section "Application metadata" /bin/ls -ldeO@ "$APP_PATH"
    section "Application signature details" /usr/bin/codesign -dvvv --entitlements :- "$APP_PATH"
    /usr/bin/codesign --verify --deep --strict --verbose=2 "$APP_PATH" >> "$REPORT" 2>> "$ERRORS" && APP_SIGNATURE_VALID=true
    /usr/sbin/spctl --assess --type execute -vv "$APP_PATH" >> "$REPORT" 2>> "$ERRORS" && APP_GATEKEEPER_ACCEPTED=true
    /usr/bin/xattr -p com.apple.quarantine "$APP_PATH" >/dev/null 2>&1 && APP_QUARANTINED=true
  else
    printf '\nApplication path not found: %s\n' "$APP_PATH" >> "$REPORT"
  fi
fi

REPAIR_FAILURES=0
if $REPAIR; then
  confirm_repair
  mkdir -p "$BACKUP_DIR"
  /usr/sbin/spctl --status > "$BACKUP_DIR/gatekeeper-before.txt" 2>/dev/null || true
  /usr/bin/csrutil status > "$BACKUP_DIR/sip-before.txt" 2>/dev/null || true
  /usr/sbin/pkgutil --pkgs | grep -Ei 'XProtect|MRT|Security|RapidSecurityResponse' > "$BACKUP_DIR/security-packages-before.txt" 2>/dev/null || true
  if [ -n "$APP_PATH" ] && [ -e "$APP_PATH" ]; then /usr/bin/xattr -l "$APP_PATH" > "$BACKUP_DIR/app-xattrs-before.txt" 2>/dev/null || true; fi

  if ! $GATEKEEPER_ENABLED; then
    if $DRY_RUN; then
      log_action "DRY-RUN: enable Gatekeeper using supported spctl command"
    else
      log_action "RUN: enable Gatekeeper"
      if /usr/sbin/spctl --global-enable >> "$ACTION_LOG" 2>&1 || /usr/sbin/spctl --master-enable >> "$ACTION_LOG" 2>&1; then log_action "OK: Gatekeeper enabled"; else log_action "FAILED: Gatekeeper enable"; REPAIR_FAILURES=$((REPAIR_FAILURES + 1)); fi
    fi
  fi
  if $DRY_RUN; then
    log_action "DRY-RUN: request background critical security-data update"
  else
    log_action "RUN: request background critical security-data update"
    if /usr/sbin/softwareupdate --background-critical >> "$ACTION_LOG" 2>&1 || /usr/sbin/softwareupdate --background >> "$ACTION_LOG" 2>&1; then log_action "OK: security-data update requested"; else log_action "FAILED: security-data update request"; REPAIR_FAILURES=$((REPAIR_FAILURES + 1)); fi
  fi
  run_action "Restart syspolicyd" /bin/launchctl kickstart -k system/com.apple.syspolicyd || REPAIR_FAILURES=$((REPAIR_FAILURES + 1))
  if ! $SIP_ENABLED; then log_action "MANUAL ACTION REQUIRED: enable SIP from macOS Recovery with 'csrutil enable', then restart."; fi

  printf '\n===== Post-repair verification =====\n' >> "$REPORT"
  /usr/sbin/spctl --status >> "$REPORT" 2>> "$ERRORS" || true
  /usr/bin/csrutil status >> "$REPORT" 2>> "$ERRORS" || true
  if [ -n "$APP_PATH" ] && [ -e "$APP_PATH" ]; then /usr/sbin/spctl --assess --type execute -vv "$APP_PATH" >> "$REPORT" 2>> "$ERRORS" || true; fi
  GATEKEEPER_RAW="$(/usr/sbin/spctl --status 2>/dev/null | tr '\n' ' ' | sed 's/"/\\"/g')"
  GATEKEEPER_ENABLED=false; echo "$GATEKEEPER_RAW" | grep -qi 'assessments enabled' && GATEKEEPER_ENABLED=true
fi

OVERALL="Compliant"
if ! $GATEKEEPER_ENABLED || ! $SIP_ENABLED; then OVERALL="Attention required"; fi
if $APP_ASSESSED && { ! $APP_SIGNATURE_VALID || ! $APP_GATEKEEPER_ACCEPTED; }; then OVERALL="Attention required"; fi
[ "$REPAIR_FAILURES" -gt 0 ] && OVERALL="Repair failed"

safe_app=$(printf '%s' "$APP_PATH" | sed 's/\\/\\\\/g; s/"/\\"/g')
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
  "application_path": "$safe_app",
  "application_assessed": $APP_ASSESSED,
  "application_signature_valid": $APP_SIGNATURE_VALID,
  "application_gatekeeper_accepted": $APP_GATEKEEPER_ACCEPTED,
  "application_has_quarantine_attribute": $APP_QUARANTINED,
  "repair_requested": $REPAIR,
  "dry_run": $DRY_RUN,
  "repair_failures": $REPAIR_FAILURES,
  "overall_status": "$OVERALL"
}
EOF

printf '\nmacOS platform security audit completed: %s\n' "$OUTPUT_DIR" | tee -a "$REPORT"
if [ "$REPAIR_FAILURES" -gt 0 ]; then exit 20; fi
[ "$OVERALL" = "Compliant" ] && exit 0
exit 10
