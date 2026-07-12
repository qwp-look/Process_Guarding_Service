#!/usr/bin/env bash
# Build and run the core helper/unit tests only.
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$repo_root"

MINGW_ROOT="${MINGW_ROOT:-/mingw64}"
export PATH="$MINGW_ROOT/bin:/usr/bin:$PATH"
GXX="${GXX:-$MINGW_ROOT/bin/g++.exe}"

mkdir -p build
echo "[unit:core] compiling tests/test_pgs_core.cpp ..."
"$GXX" -std=c++17 -Wall -Wextra -O2 -Iinclude \
    tests/test_pgs_core.cpp \
    -o build/test_pgs_core.exe \
    -lbcrypt

echo "[unit:core] running ..."
./build/test_pgs_core.exe
