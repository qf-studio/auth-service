#!/usr/bin/env bash
# generate-keys.sh — Generate ES256 EC key pair for JWT signing
#
# Usage:
#   ./scripts/generate-keys.sh [OPTIONS]
#
# Options:
#   --out-dir DIR    Output directory for key files (default: ./keys)
#   --name NAME      Base name for key files (default: jwt)
#   --force          Overwrite existing key files
#   --help           Show this help message
#
# Output files:
#   <name>.private.pem   EC private key (P-256, PKCS#8)
#   <name>.public.pem    EC public key (SPKI)
#
# Environment variables produced (print to stdout for sourcing):
#   JWT_PRIVATE_KEY_FILE   Path to private key file
#   JWT_PUBLIC_KEY_FILE    Path to public key file

set -euo pipefail

OUT_DIR="./keys"
NAME="jwt"
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
        --out-dir) OUT_DIR="$2"; shift 2 ;;
        --name)    NAME="$2";    shift 2 ;;
        --force)   FORCE=true;   shift   ;;
        --help|-h) usage ;;
        *) die "Unknown option: $1" ;;
    esac
done

# Verify openssl is available
command -v openssl >/dev/null 2>&1 || die "openssl is required but not found in PATH"

PRIVATE_KEY="$OUT_DIR/$NAME.private.pem"
PUBLIC_KEY="$OUT_DIR/$NAME.public.pem"

# Check for existing files
if [[ "$FORCE" == false ]]; then
    for f in "$PRIVATE_KEY" "$PUBLIC_KEY"; do
        if [[ -e "$f" ]]; then
            die "File already exists: $f (use --force to overwrite)"
        fi
    done
fi

mkdir -p "$OUT_DIR"
chmod 700 "$OUT_DIR"

echo "Generating ES256 EC key pair (P-256)..." >&2

# Generate private key (PKCS#8 format)
openssl genpkey -algorithm EC \
    -pkeyopt ec_paramgen_curve:P-256 \
    -out "$PRIVATE_KEY" 2>/dev/null

chmod 600 "$PRIVATE_KEY"

# Extract public key
openssl pkey -pubout -in "$PRIVATE_KEY" -out "$PUBLIC_KEY" 2>/dev/null

chmod 644 "$PUBLIC_KEY"

echo "Validating generated keys..." >&2

# Validate: check key type and curve
CURVE=$(openssl pkey -noout -text -in "$PRIVATE_KEY" 2>/dev/null | grep -i "NIST P-256\|prime256v1\|P-256" | head -1)
if [[ -z "$CURVE" ]]; then
    # Try alternate detection
    KEY_INFO=$(openssl pkey -noout -text -in "$PRIVATE_KEY" 2>/dev/null)
    if ! echo "$KEY_INFO" | grep -qi "256\|prime256"; then
        die "Key validation failed: expected P-256 curve"
    fi
fi

# Validate: sign and verify a test message
TEST_MSG=$(mktemp)
TEST_SIG=$(mktemp)
TEST_VERIFY=$(mktemp)
echo "validation-test" > "$TEST_MSG"

openssl dgst -sha256 -sign "$PRIVATE_KEY" -out "$TEST_SIG" "$TEST_MSG" 2>/dev/null
VERIFY_RESULT=$(openssl dgst -sha256 -verify "$PUBLIC_KEY" -signature "$TEST_SIG" "$TEST_MSG" 2>/dev/null)

rm -f "$TEST_MSG" "$TEST_SIG" "$TEST_VERIFY"

if [[ "$VERIFY_RESULT" != "Verified OK" ]]; then
    die "Key validation failed: sign/verify round-trip unsuccessful"
fi

echo "" >&2
echo "Keys generated and validated successfully:" >&2
echo "  Private key: $PRIVATE_KEY" >&2
echo "  Public key:  $PUBLIC_KEY" >&2
echo "" >&2
echo "Environment variables (add to .env):" >&2
echo "  JWT_PRIVATE_KEY_FILE=$PRIVATE_KEY" >&2
echo "  JWT_PUBLIC_KEY_FILE=$PUBLIC_KEY" >&2
