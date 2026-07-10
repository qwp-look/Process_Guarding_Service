#!/usr/bin/env bash
# Configure and build the browser-based Qt web consoles.
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$repo_root"

export PATH="/mingw64/bin:/usr/bin:$PATH"
CMAKE="${CMAKE:-/mingw64/bin/cmake.exe}"
GXX="${GXX:-/mingw64/bin/g++.exe}"

build_one() {
  local name="$1"
  local source_dir="$2"
  local build_dir="build/$name"

  echo "[qt-web] configuring $name ..."
  "$CMAKE" -S "$source_dir" -B "$build_dir" -G "MinGW Makefiles" \
    -DCMAKE_PREFIX_PATH=/mingw64 \
    -DCMAKE_CXX_COMPILER="$GXX"

  echo "[qt-web] building $name ..."
  "$CMAKE" --build "$build_dir" -j "${PGS_BUILD_JOBS:-4}"
}

build_one "pgs_admin_web" "qt/pgs_admin_web"
build_one "pgs_cluster_web" "qt/pgs_cluster_web"
