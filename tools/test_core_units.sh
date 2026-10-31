#!/usr/bin/env bash
# Build and run the core helper/unit tests only.
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$repo_root"

MINGW_ROOT="${MINGW_ROOT:-/mingw64}"
export PATH="$MINGW_ROOT/bin:/usr/bin:$PATH"
GXX="${GXX:-$MINGW_ROOT/bin/g++.exe}"
BUILD_DIR="${PGS_BUILD_DIR:-build}"

mkdir -p "$BUILD_DIR"
echo "[unit:core] compiling tests/test_pgs_core.cpp ..."
"$GXX" -std=c++17 -Wall -Wextra -O2 -DPGS_ENABLE_TEST_HOOKS -Iinclude \
    tests/test_pgs_core.cpp modules/sched/pgs_sched_module.cpp \
    -o "$BUILD_DIR/test_pgs_core.exe" \
    -lbcrypt

echo "[unit:core] running ..."
"$BUILD_DIR/test_pgs_core.exe"
