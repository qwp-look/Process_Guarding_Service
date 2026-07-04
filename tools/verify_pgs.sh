#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$repo_root"

export PATH="/mingw64/bin:/usr/bin"

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
  "tools/build_pgs.sh" \
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
./tools/build_pgs.sh

echo
./tools/run_unit_tests.sh

echo
if [[ "${PGS_SKIP_SMOKE:-0}" == "1" ]]; then
  echo "[Smoke] skipped because PGS_SKIP_SMOKE=1"
else
  ./tools/smoke_test_pgs.sh
fi

echo
echo "[Qt] Configuring..."
rm -rf build/pgs_admin_qt
cmake -S qt/pgs_admin_qt -B build/pgs_admin_qt -G "MinGW Makefiles" \
  -DCMAKE_PREFIX_PATH=/mingw64 \
  -DCMAKE_CXX_COMPILER=/mingw64/bin/g++.exe

echo "[Qt] Building..."
cmake --build build/pgs_admin_qt -j4

echo
echo "[Web] Configuring..."
rm -rf build/pgs_admin_web
cmake -S qt/pgs_admin_web -B build/pgs_admin_web -G "MinGW Makefiles" \
  -DCMAKE_PREFIX_PATH=/mingw64 \
  -DCMAKE_CXX_COMPILER=/mingw64/bin/g++.exe

echo "[Web] Building..."
cmake --build build/pgs_admin_web -j4

echo
echo "Verification completed successfully."
