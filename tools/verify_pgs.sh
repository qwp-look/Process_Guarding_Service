#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$repo_root"

MINGW_ROOT="${MINGW_ROOT:-/mingw64}"
export PATH="$MINGW_ROOT/bin:/usr/bin:$PATH"
GXX="${GXX:-$MINGW_ROOT/bin/g++.exe}"
CMAKE="${CMAKE:-$MINGW_ROOT/bin/cmake.exe}"

# This script is intentionally broader than a plain compile:
# - verifies critical source files are present
# - builds the core binaries
# - runs a lightweight smoke test against console mode
# - builds the Qt desktop admin tool
# - builds the browser-based web console

echo "=========================================================="
echo "ProcessGuard verification (MSYS2 MinGW64)"
echo "=========================================================="
echo

for file in \
  "include/Process_Guard/PGS.h" \
  "include/Process_Guard/PGLogger.h" \
  "src/service/PGS.cpp" \
  "src/service/pgs_service.cpp" \
  "tools/pgs_bless.cpp" \
  "examples/guard_example.cpp" \
  "examples/quick_start.cpp" \
  "examples/smoke_worker.cpp" \
  "qt/pgs_admin_qt/CMakeLists.txt" \
  "qt/pgs_admin_qt/src/MainWindow.cpp" \
  "qt/pgs_admin_web/CMakeLists.txt" \
  "qt/pgs_admin_web/src/WebServer.cpp" \
  "qt/pgs_cluster_web/CMakeLists.txt" \
  "qt/pgs_cluster_web/src/ClusterServer.cpp" \
  "tools/build_pgs.sh" \
  "tools/build_qt_web.sh" \
  "tools/smoke_test_pgs.sh"
do
  if [[ -f "$file" ]]; then
    echo "[OK] $file"
  else
    echo "[MISS] $file"
    exit 1
  fi
done

echo
bash ./tools/build_pgs.sh

echo
bash ./tools/run_unit_tests.sh

echo
if [[ "${PGS_SKIP_SMOKE:-0}" == "1" ]]; then
  echo "[Smoke] skipped because PGS_SKIP_SMOKE=1"
else
  PGS_SMOKE_PORT="${PGS_SMOKE_PORT:-23456}" bash ./tools/smoke_test_pgs.sh
fi

echo
echo "[Qt] Configuring..."
rm -rf build/pgs_admin_qt
"$CMAKE" -S qt/pgs_admin_qt -B build/pgs_admin_qt -G "MinGW Makefiles" \
  -DCMAKE_PREFIX_PATH="$MINGW_ROOT" \
  -DCMAKE_CXX_COMPILER="$GXX"

echo "[Qt] Building..."
"$CMAKE" --build build/pgs_admin_qt -j "${PGS_BUILD_JOBS:-4}"

echo
echo "[Web] Building admin + cluster consoles..."
bash ./tools/build_qt_web.sh

echo
echo "Verification completed successfully."
