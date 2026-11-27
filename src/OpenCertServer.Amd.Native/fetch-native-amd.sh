#!/usr/bin/env bash
# fetch-native-amd.sh
# ─────────────────────────────────────────────────────────────────────────────
# Stages an ABI-compatible AMD SEV-SNP native library when installed locally.
#
# Usage:
#   cd src/OpenCertServer.Amd.Native
#   ./fetch-native-amd.sh
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

copy_if_found() {
    local src="$1"
    local dest="$2"
    [ -f "$src" ] || return 1
    echo "[amd-native] Copying $src → $dest"
    mkdir -p "$(dirname "$dest")"
    cp "$src" "$dest"
}

DEST_X64="$SCRIPT_DIR/runtimes/linux-x64/native/amd_snp_driver.so"

copy_if_found "/usr/lib/x86_64-linux-gnu/amd_snp_driver.so" "$DEST_X64" || \
copy_if_found "/usr/lib64/amd_snp_driver.so"                 "$DEST_X64" || true

if [ ! -f "$DEST_X64" ]; then
    echo "[amd-native] WARNING: amd_snp_driver.so not found."
    echo "  Supply a library implementing the ABI described in README.md."
fi
