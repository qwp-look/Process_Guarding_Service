#!/usr/bin/env bash
# Configure and build the Qt desktop admin app.
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$repo_root"

MINGW_ROOT="${MINGW_ROOT:-/mingw64}"
export PATH="$MINGW_ROOT/bin:/usr/bin:$PATH"
CMAKE="${CMAKE:-$MINGW_ROOT/bin/cmake.exe}"
GXX="${GXX:-$MINGW_ROOT/bin/g++.exe}"

build_dir="build/pgs_admin_qt"

echo "[qt-admin] configuring pgs_admin_qt ..."
rm -rf "$build_dir"
"$CMAKE" -S qt/pgs_admin_qt -B "$build_dir" -G "MinGW Makefiles" \
  -DCMAKE_PREFIX_PATH="$MINGW_ROOT" \
  -DCMAKE_CXX_COMPILER="$GXX" \
  -DCMAKE_BUILD_TYPE=Release

echo "[qt-admin] building pgs_admin_qt ..."
"$CMAKE" --build "$build_dir" -j "${PGS_BUILD_JOBS:-1}"
