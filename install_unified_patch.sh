#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="/opt/CAPEv2"
PATCH_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STAMP="$(date +%Y%m%d_%H%M%S)"
WORKDIR="$PATCH_ROOT/.work_$STAMP"
LOG="$PATCH_ROOT/install_unified_patch_$STAMP.log"
BACKUP_DIR="$ROOT/unified_patch_backups/$STAMP"

DO_ATTACK_STORY=1
DO_CUSTOM_SIGS=1
DO_KO_UI=1
DO_SIGNATURE_JS=1
DO_BACKEND_SIG_TRANSLATE=0
DO_SUBMISSION_ONLY=0

usage() {
  cat <<EOF
Usage: sudo ./install_unified_patch.sh [options]

Options:
  --root PATH                    CAPEv2 root (default: /opt/CAPEv2)
  --no-attack-story              Skip Attack Story reporting/web patch
  --no-custom-signatures         Skip custom signature pack install
  --no-ko-ui                     Skip Korean UI diff patch
  --no-signature-js              Skip JS-based Korean signature helper injection
  --backend-signature-translate  Also apply backend analysis_tags translation patch (extra, optional)
  --submission-only              Apply submission-only Korean patch instead of full ko-ui patch
  -h, --help                     Show help

Default behavior:
  attack_story + custom_signatures + ko_ui + signature_js
EOF
}

log() { printf '%s %s\n' "[$(date '+%F %T')]" "$*" | tee -a "$LOG"; }
warn() { log "WARN: $*"; }
fail() { log "ERROR: $*"; exit 1; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --root) ROOT="$2"; shift 2 ;;
    --no-attack-story) DO_ATTACK_STORY=0; shift ;;
    --no-custom-signatures) DO_CUSTOM_SIGS=0; shift ;;
    --no-ko-ui) DO_KO_UI=0; shift ;;
    --no-signature-js) DO_SIGNATURE_JS=0; shift ;;
    --backend-signature-translate) DO_BACKEND_SIG_TRANSLATE=1; shift ;;
    --submission-only) DO_SUBMISSION_ONLY=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) fail "Unknown option: $1" ;;
  esac
done

[[ -d "$ROOT" ]] || fail "CAPE root not found: $ROOT"
mkdir -p "$WORKDIR" "$BACKUP_DIR"
trap 'rm -rf "$WORKDIR"' EXIT

backup_file() {
  local src="$1"
  if [[ -f "$src" ]]; then
    local rel="${src#$ROOT/}"
    mkdir -p "$BACKUP_DIR/$(dirname "$rel")"
    cp -a "$src" "$BACKUP_DIR/$rel"
  fi
}

apply_diff_if_possible() {
  local diff_file="$1"
  local label="$2"
  [[ -f "$diff_file" ]] || fail "Missing diff: $diff_file"
  log "Checking $label"
  if (cd "$ROOT" && patch --dry-run -p1 --forward < "$diff_file" >/dev/null 2>&1); then
    log "Applying $label"
    (cd "$ROOT" && patch -p1 --forward --backup --suffix=".unified_${STAMP}.bak" < "$diff_file") | tee -a "$LOG"
  else
    warn "$label dry-run failed. Base template may differ; skipped."
  fi
}

restart_services_best_effort() {
  if command -v systemctl >/dev/null 2>&1; then
    for svc in cape cape-processor cape-web; do
      if systemctl list-unit-files | grep -q "^${svc}\.service"; then
        log "Restarting ${svc}"
        systemctl restart "$svc" || warn "Failed to restart ${svc}"
      fi
    done
  else
    warn "systemctl not found; skipped service restart"
  fi
}

log "Unified CAPE patch start"
log "ROOT=$ROOT"
log "BACKUP_DIR=$BACKUP_DIR"

# Pre-backup common files
for f in \
  "$ROOT/web/templates/analysis/report.html" \
  "$ROOT/web/templates/analysis/overview/index.html" \
  "$ROOT/web/templates/analysis/overview/_info.html" \
  "$ROOT/web/templates/analysis/overview/_signatures.html" \
  "$ROOT/web/templates/analysis/overview/_korean_summary.html" \
  "$ROOT/web/templates/submission/index.html" \
  "$ROOT/web/analysis/templatetags/analysis_tags.py" \
  "$ROOT/web/analysis/urls.py" \
  "$ROOT/custom/conf/reporting.conf"; do
  backup_file "$f"
done

if [[ "$DO_ATTACK_STORY" -eq 1 ]]; then
  log "Installing Attack Story patch"
  unzip -q "$PATCH_ROOT/payload/cape_attack_story_web_patch.zip" -d "$WORKDIR"
  chmod +x "$WORKDIR/cape_attack_story_web_patch/install_attack_story_web.sh"
  "$WORKDIR/cape_attack_story_web_patch/install_attack_story_web.sh" "$ROOT" | tee -a "$LOG"
else
  log "Skipping Attack Story patch"
fi

if [[ "$DO_KO_UI" -eq 1 ]]; then
  apply_diff_if_possible "$PATCH_ROOT/payload/cape_ko_ui_patch.diff" "Korean UI patch"
elif [[ "$DO_SUBMISSION_ONLY" -eq 1 ]]; then
  apply_diff_if_possible "$PATCH_ROOT/payload/cape_ko_submission_only.diff" "Submission-only Korean patch"
else
  log "Skipping Korean UI diff patch"
fi

if [[ "$DO_CUSTOM_SIGS" -eq 1 ]]; then
  log "Installing custom signatures pack"
  unzip -q "$PATCH_ROOT/payload/cape_custom_signatures_pack.zip" -d "$WORKDIR"
  mkdir -p "$ROOT/modules/signatures/windows"
  find "$WORKDIR/cape_custom_signatures_pack/windows" -maxdepth 1 -type f -name '*.py' -print0 | while IFS= read -r -d '' f; do
    backup_file "$ROOT/modules/signatures/windows/$(basename "$f")"
    install -m 0644 "$f" "$ROOT/modules/signatures/windows/$(basename "$f")"
    log "Installed $(basename "$f")"
  done
else
  log "Skipping custom signatures pack"
fi

if [[ "$DO_SIGNATURE_JS" -eq 1 ]]; then
  log "Applying signature JS helper patches"
  python3 "$PATCH_ROOT/payload/cape_apply_signature_ko_from_catalog_full.py" | tee -a "$LOG"
  python3 "$PATCH_ROOT/payload/cape_fix_signature_hint_dedupe_bodyonly.py" | tee -a "$LOG"
  python3 "$PATCH_ROOT/payload/cape_manual_signature_kofix_visible_set.py" | tee -a "$LOG"
else
  log "Skipping signature JS helper patches"
fi

if [[ "$DO_BACKEND_SIG_TRANSLATE" -eq 1 ]]; then
  log "Applying optional backend signature translation enhancement"
  python3 "$PATCH_ROOT/extras/cape_fix_signature_v3.py" | tee -a "$LOG"
else
  log "Skipping optional backend signature translation enhancement"
fi

restart_services_best_effort

cat <<EOF | tee -a "$LOG"

[OK] Unified CAPE patch completed.
Backups:
  $BACKUP_DIR
Log:
  $LOG

Recommended follow-up:
  1) Browser hard refresh (Ctrl+Shift+R)
  2) Re-run or reprocess one sample to confirm:
     - Attack Story section appears
     - Korean UI labels render
     - Custom signatures appear
     - Korean signature hints appear
EOF
