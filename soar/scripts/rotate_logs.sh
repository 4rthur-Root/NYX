#!/usr/bin/env bash
set -euo pipefail

SOAR_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
LOG_DIR="${SOAR_ROOT}/logs"
MAX_BYTES="${SOAR_LOG_MAX_BYTES:-5000000}"
KEEP="${LOG_ROTATE_KEEP:-5}"

audit_log="${LOG_DIR}/audit.log"
soar_log="${LOG_DIR}/soar.log"

rotate_file() {
    local file="$1"
    local max_bytes="$2"
    local keep="$3"

    if [[ ! -f "$file" ]]; then
        return
    fi

    local size
    size=$(stat -c%s "$file" 2>/dev/null || stat -f%z "$file" 2>/dev/null || echo 0)

    if [[ "$size" -lt "$max_bytes" ]]; then
        return
    fi

    local ts
    ts=$(date -u +"%Y%m%d_%H%M%S")
    local rotated="${file}.${ts}"

    mv "$file" "$rotated"
    gzip -9 "$rotated" || true

    local dir
    dir=$(dirname "$file")
    local base
    base=$(basename "$file")

    shopt -s nullglob
    local rotated_files=("${dir}/${base}".*)
    shopt -u nullglob

    if [[ "${#rotated_files[@]}" -gt "$keep" ]]; then
        local to_delete=("${rotated_files[@]:0:${#rotated_files[@]}-keep}")
        for f in "${to_delete[@]}"; do
            rm -f "$f" "${f}.gz" 2>/dev/null || true
        done
    fi

    echo "Rotated: $file -> ${rotated}.gz"
}

rotate_file "$audit_log" "$MAX_BYTES" "$KEEP"
rotate_file "$soar_log" "$MAX_BYTES" "$KEEP"

echo "Log rotation complete."
