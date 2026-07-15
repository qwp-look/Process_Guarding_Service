#!/usr/bin/env bash
# Configure and build the browser-based Qt web consoles.
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$repo_root"

MINGW_ROOT="${MINGW_ROOT:-/mingw64}"
export PATH="$MINGW_ROOT/bin:/usr/bin:$PATH"
CMAKE="${CMAKE:-$MINGW_ROOT/bin/cmake.exe}"
GXX="${GXX:-$MINGW_ROOT/bin/g++.exe}"
BUILD_DIR="${PGS_BUILD_DIR:-build}"

build_one() {
  local name="$1"
  local source_dir="$2"
  local build_dir="$BUILD_DIR/$name"

  echo "[qt-web] configuring $name ..."
  "$CMAKE" -S "$source_dir" -B "$build_dir" -G "MinGW Makefiles" \
    -DCMAKE_PREFIX_PATH="$MINGW_ROOT" \
    -DCMAKE_CXX_COMPILER="$GXX" \
    -DCMAKE_BUILD_TYPE=Release

  echo "[qt-web] building $name ..."
  # MinGW Makefiles can race while archiving target objects; keep the default
  # serial and remove the object archive explicitly so stale members never leak
  # into release builds.
  rm -f "$build_dir/CMakeFiles/$name.dir/objects.a"
  "$CMAKE" --build "$build_dir" --clean-first -j "${PGS_BUILD_JOBS:-1}"
}

build_one "pgs_admin_web" "qt/pgs_admin_web"
build_one "pgs_cluster_web" "qt/pgs_cluster_web"
