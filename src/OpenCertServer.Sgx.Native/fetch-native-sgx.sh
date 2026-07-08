#!/usr/bin/env bash
# fetch-native-sgx.sh
# ─────────────────────────────────────────────────────────────────────────────
# Fetches the Intel SGX DCAP native library and places it in the correct RID
# directory so it will be included when this NuGet package is packed.
#
# Usage (on a Linux x64 CI agent with SGX DCAP available):
#   cd src/OpenCertServer.Sgx.Native
#   ./fetch-native-sgx.sh
#
# After running this script, build the NuGet package with:
#   dotnet pack -c Release
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

copy_if_found() {
    local src="$1"
    local dest="$2"
    if [ -f "$src" ]; then
        echo "[sgx-native] Copying $src → $dest"
        mkdir -p "$(dirname "$dest")"
        cp "$src" "$dest"
    fi
}

# ── Linux x64 ────────────────────────────────────────────────────────────────
DEST_X64="$SCRIPT_DIR/runtimes/linux-x64/native/libsgx_dcap_ql.so"

# Try common install locations (libsgx-dcap-ql package on Ubuntu/Debian)
copy_if_found "/usr/lib/x86_64-linux-gnu/libsgx_dcap_ql.so.1" "$DEST_X64" || \
copy_if_found "/usr/lib/x86_64-linux-gnu/libsgx_dcap_ql.so"   "$DEST_X64" || \
copy_if_found "/usr/lib64/libsgx_dcap_ql.so.1"                 "$DEST_X64" || \
copy_if_found "/usr/lib64/libsgx_dcap_ql.so"                   "$DEST_X64" || true

if [ ! -f "$DEST_X64" ]; then
    echo "[sgx-native] WARNING: libsgx_dcap_ql.so not found."
    echo "  Install the Intel DCAP package first:"
    echo "    sudo apt-get install -y libsgx-dcap-ql"
    echo "  Or download from https://github.com/intel/SGXDataCenterAttestationPrimitives"
fi
