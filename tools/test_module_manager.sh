#!/usr/bin/env bash
# Build and run the ModuleManager path/allowlist key tests only.
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$repo_root"

MINGW_ROOT="${MINGW_ROOT:-/mingw64}"
export PATH="$MINGW_ROOT/bin:/usr/bin:$PATH"
GXX="${GXX:-$MINGW_ROOT/bin/g++.exe}"

mkdir -p build
echo "[unit:modules] compiling tests/test_module_manager.cpp ..."
"$GXX" -std=c++17 -Wall -Wextra -O2 -Iinclude \
    tests/test_module_manager.cpp src/modules/ModuleManager.cpp src/common/PGLogger.cpp \
    -o build/test_module_manager.exe \
    -lwintrust -lole32 -lbcrypt

echo "[unit:modules] running ..."
./build/test_module_manager.exe
