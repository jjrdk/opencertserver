#!/usr/bin/env bash
# fetch-native-amd.sh
# ─────────────────────────────────────────────────────────────────────────────
# Fetches the AMD SEV-SNP native driver library and places it in the correct
# RID directory for NuGet packaging.
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
    if [ -f "$src" ]; then
        echo "[amd-native] Copying $src → $dest"
        mkdir -p "$(dirname "$dest")"
        cp "$src" "$dest"
    fi
}

DEST_X64="$SCRIPT_DIR/runtimes/linux-x64/native/amd_snp_driver.so"

copy_if_found "/usr/lib/x86_64-linux-gnu/amd_snp_driver.so" "$DEST_X64" || \
copy_if_found "/usr/lib64/amd_snp_driver.so"                 "$DEST_X64" || true

if [ ! -f "$DEST_X64" ]; then
    echo "[amd-native] WARNING: amd_snp_driver.so not found."
    echo "  Build from: https://github.com/AMDESE/AMDSEV"
fi
