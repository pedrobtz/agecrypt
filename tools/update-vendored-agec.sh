#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

REPO_URL="${AGEC_REPO_URL:-git@github.com:pedrobtz/agec.git}"
REF="${1:-${AGEC_REF:-}}"
EXPECTED_COMMIT="${2:-${AGEC_EXPECTED_COMMIT:-}}"
DEST_DIR="${AGEC_DEST_DIR:-src/agec}"

usage() {
  cat <<EOF
Usage:
  $0 <ref> <expected-full-commit-sha>

Environment overrides:
  AGEC_REPO_URL          upstream repository URL
                         default: git@github.com:pedrobtz/agec.git
  AGEC_REF              ref to vendor, used when <ref> is omitted
  AGEC_EXPECTED_COMMIT  full commit SHA, used when the second argument is omitted
  AGEC_DEST_DIR         destination directory relative to the package root
                         default: src/agec

Example:
  $0 vendor-2026-07-09 5c95fe5b7bc0d9888333709eb7443a3a92fe5be7
EOF
}

if [ -z "$REF" ] || [ -z "$EXPECTED_COMMIT" ]; then
  usage >&2
  exit 2
fi

DEST_PATH="$ROOT_DIR/$DEST_DIR"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/agec-vendor.XXXXXX")"
trap 'rm -rf "$TMP_DIR"' EXIT

echo "Fetching $REPO_URL at $REF..."
git -C "$TMP_DIR" init -q repo
git -C "$TMP_DIR/repo" remote add origin "$REPO_URL"
git -C "$TMP_DIR/repo" fetch --depth 1 origin "$REF"
git -C "$TMP_DIR/repo" checkout -q --detach FETCH_HEAD

ACTUAL_COMMIT="$(git -C "$TMP_DIR/repo" rev-parse HEAD)"

if [ "$ACTUAL_COMMIT" != "$EXPECTED_COMMIT" ]; then
  echo "Commit mismatch!" >&2
  echo "Expected: $EXPECTED_COMMIT" >&2
  echo "Actual:   $ACTUAL_COMMIT" >&2
  exit 1
fi

echo "Updating vendored agec files in $DEST_DIR..."
mkdir -p "$DEST_PATH/crypto"

copy_root_file() {
  cp "$TMP_DIR/repo/$1" "$DEST_PATH/$1"
}

copy_crypto_file() {
  cp "$TMP_DIR/repo/crypto/$1" "$DEST_PATH/crypto/$1"
}

for file in \
  base64.c base64.h \
  bech32.c bech32.h \
  crypto.h \
  header.c header.h \
  io.c io.h \
  keyenc.c keyenc.h \
  parse.c parse.h \
  payload.c payload.h \
  scrypt.c scrypt.h \
  util.c util.h \
  x25519.c x25519.h
do
  copy_root_file "$file"
done

cp "$TMP_DIR/repo/unix/common.h" "$DEST_PATH/common.h"

for file in \
  chacha20poly1305.c \
  curve25519.c \
  hkdf.c \
  hmac.c \
  scrypt.c \
  sha256.c
do
  copy_crypto_file "$file"
done

cat <<EOF
Done.

Vendored commit:
  $ACTUAL_COMMIT

Next steps:
  1. Re-apply the local patches listed in inst/COPYRIGHTS.
  2. Update the agec revision in inst/COPYRIGHTS.
  3. Review changes with:
       git diff -- src/agec inst/COPYRIGHTS
EOF
