#!/usr/bin/env bash
# Build and run the PGS pure-helper unit tests.
# Reused by tools/verify_pgs.sh and CI (.github/workflows/build.yml) so the
# test path has exactly one implementation. Exits non-zero on any failure.
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$repo_root"

export PATH="/mingw64/bin:/usr/bin:$PATH"
GXX="${GXX:-/mingw64/bin/g++.exe}"

mkdir -p build
echo "[unit] compiling tests/test_pgs_core.cpp ..."
"$GXX" -std=c++17 -Wall -Wextra -Iinclude \
    tests/test_pgs_core.cpp \
    -o build/test_pgs_core.exe \
    -lbcrypt

echo "[unit] running ..."
./build/test_pgs_core.exe