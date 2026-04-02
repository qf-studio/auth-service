#!/usr/bin/env bash
# generate-secret.sh — Generate cryptographically secure random secrets
#
# Usage:
#   ./scripts/generate-secret.sh [OPTIONS]
#
# Options:
#   --name NAME      Variable name to use in output (default: SECRET)
#   --bytes N        Number of random bytes (default: 32, produces 64 hex chars)
#   --format FORMAT  Output format: hex (default), base64, base64url
#   --out FILE       Append export line to file instead of stdout
#   --force          Overwrite existing entry in --out file
#   --help           Show this help message
#
# Examples:
#   # Generate HMAC pepper
#   ./scripts/generate-secret.sh --name HMAC_PEPPER
#
#   # Generate session secret (URL-safe base64)
#   ./scripts/generate-secret.sh --name SESSION_SECRET --format base64url
#
#   # Append to .env file
#   ./scripts/generate-secret.sh --name HMAC_PEPPER --out .env

set -euo pipefail

NAME="SECRET"
BYTES=32
FORMAT="hex"
OUT_FILE=""
FORCE=false

usage() {
    sed -n '/^# Usage:/,/^[^#]/p' "$0" | grep '^#' | sed 's/^# \?//'
    exit 0
}

die() {
    echo "ERROR: $*" >&2
    exit 1
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --name)   NAME="$2";     shift 2 ;;
        --bytes)  BYTES="$2";    shift 2 ;;
        --format) FORMAT="$2";   shift 2 ;;
        --out)    OUT_FILE="$2"; shift 2 ;;
        --force)  FORCE=true;    shift   ;;
        --help|-h) usage ;;
        *) die "Unknown option: $1" ;;
    esac
done

# Validate bytes is a positive integer
[[ "$BYTES" =~ ^[1-9][0-9]*$ ]] || die "--bytes must be a positive integer"

# Validate format
case "$FORMAT" in
    hex|base64|base64url) ;;
    *) die "--format must be one of: hex, base64, base64url" ;;
esac

# Generate random bytes using /dev/urandom (preferred) or openssl fallback
generate_random() {
    local bytes="$1"
    if [[ -r /dev/urandom ]]; then
        dd if=/dev/urandom bs=1 count="$bytes" 2>/dev/null | od -An -tx1 | tr -d ' \n'
    elif command -v openssl >/dev/null 2>&1; then
        openssl rand -hex "$bytes"
    else
        die "No entropy source available: /dev/urandom not readable and openssl not found"
    fi
}

# Generate raw hex bytes
HEX_BYTES=$(generate_random "$BYTES")

# Format output
case "$FORMAT" in
    hex)
        SECRET="$HEX_BYTES"
        ;;
    base64)
        SECRET=$(echo "$HEX_BYTES" | xxd -r -p 2>/dev/null | base64)
        if [[ -z "$SECRET" ]]; then
            # xxd fallback via openssl
            SECRET=$(openssl rand -base64 "$BYTES")
        fi
        ;;
    base64url)
        SECRET=$(echo "$HEX_BYTES" | xxd -r -p 2>/dev/null | base64 | tr '+/' '-_' | tr -d '=')
        if [[ -z "$SECRET" ]]; then
            SECRET=$(openssl rand -base64 "$BYTES" | tr '+/' '-_' | tr -d '=')
        fi
        ;;
esac

EXPORT_LINE="$NAME=$SECRET"

if [[ -z "$OUT_FILE" ]]; then
    echo "$EXPORT_LINE"
else
    # Check if variable already exists in file
    if [[ -f "$OUT_FILE" ]] && grep -q "^$NAME=" "$OUT_FILE"; then
        if [[ "$FORCE" == false ]]; then
            die "$NAME already set in $OUT_FILE (use --force to overwrite)"
        fi
        # Replace existing line (grep -v exits 1 when no lines pass the filter, hence || true)
        TMP=$(mktemp)
        grep -v "^$NAME=" "$OUT_FILE" > "$TMP" || true
        echo "$EXPORT_LINE" >> "$TMP"
        cp "$TMP" "$OUT_FILE"
        echo "Updated $NAME in $OUT_FILE" >&2
    else
        echo "$EXPORT_LINE" >> "$OUT_FILE"
        echo "Appended $NAME to $OUT_FILE" >&2
    fi
fi
