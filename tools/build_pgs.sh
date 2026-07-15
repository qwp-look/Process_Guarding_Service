#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$repo_root"

MINGW_ROOT="${MINGW_ROOT:-/mingw64}"
export PATH="$MINGW_ROOT/bin:/usr/bin:$PATH"
GXX="${GXX:-$MINGW_ROOT/bin/g++.exe}"
BUILD_DIR="${PGS_BUILD_DIR:-build}"

# v3: NTDDI_VERSION >= Win8 enables MinGW's IApplicationActivationManager
# (used by restartAppGuard for WindowsApps activation), no WinRT headers needed.
CXXFLAGS="-std=c++17 -Wall -Wextra -O2 -Iinclude -DNTDDI_VERSION=0x06020000"
mkdir -p "$BUILD_DIR" "$BUILD_DIR/tmp"
export TMPDIR="${TMPDIR:-$PWD/$BUILD_DIR/tmp}"
export TEMP="${TEMP:-$TMPDIR}"
export TMP="${TMP:-$TMPDIR}"

# Keep this script close to the manual build instructions in README so local
# debugging and scripted verification use the same MinGW64 toolchain path.

echo "[1/15] Compiling logger..."
"$GXX" $CXXFLAGS -c src/common/PGLogger.cpp -o "$BUILD_DIR/PGLogger.o"

echo "[2/15] Compiling PGS core..."
"$GXX" $CXXFLAGS -c src/service/PGS.cpp -o "$BUILD_DIR/PGS.o"

# Module system: ModuleManager is linked into pgs_service.exe.
echo "[3/15] Compiling module manager..."
"$GXX" $CXXFLAGS -c src/modules/ModuleManager.cpp -o "$BUILD_DIR/ModuleManager.o"

echo "[4/15] Compiling PGS protocol layer..."
"$GXX" $CXXFLAGS -c src/service/PGSProtocol.cpp -o "$BUILD_DIR/PGSProtocol.o"

echo "[5/15] Compiling service host..."
"$GXX" $CXXFLAGS -c src/service/pgs_service.cpp -o "$BUILD_DIR/pgs_service.o"

echo "[6/15] Linking pgs_service.exe..."
"$GXX" -std=c++17 -Wall -Wextra -O2 \
  "$BUILD_DIR/PGLogger.o" "$BUILD_DIR/PGS.o" "$BUILD_DIR/PGSProtocol.o" "$BUILD_DIR/ModuleManager.o" "$BUILD_DIR/pgs_service.o" \
  -o "$BUILD_DIR/pgs_service.exe" \
  -lws2_32 -ladvapi32 -lwtsapi32 -luserenv -lbcrypt -lwintrust -lole32 -lshell32

echo "[7/15] Building guard_example.exe..."
"$GXX" $CXXFLAGS examples/guard_example.cpp -o "$BUILD_DIR/guard_example.exe" -lws2_32 -ladvapi32 -lbcrypt

echo "[8/15] Building quick_start.exe..."
"$GXX" $CXXFLAGS examples/quick_start.cpp -o "$BUILD_DIR/quick_start.exe" -lws2_32 -ladvapi32 -lbcrypt

echo "[9/15] Building smoke_worker.exe..."
"$GXX" $CXXFLAGS examples/smoke_worker.cpp -o "$BUILD_DIR/smoke_worker.exe" -lws2_32

echo "[10/15] Building pgs_bless.exe..."
"$GXX" $CXXFLAGS -c src/common/PGSClient.cpp -o "$BUILD_DIR/PGSClient.o"
"$GXX" $CXXFLAGS tools/pgs_bless.cpp "$BUILD_DIR/PGSClient.o" "$BUILD_DIR/ModuleManager.o" "$BUILD_DIR/PGLogger.o" -o "$BUILD_DIR/pgs_bless.exe" \
  -lws2_32 -ladvapi32 -lbcrypt -lwintrust -lole32

# Schedule module: cron/once/interval scheduler (ABI v2).
echo "[11/15] Building pgs_sched_module.dll..."
mkdir -p "$BUILD_DIR/modules/sched"
"$GXX" -std=c++17 -Wall -Wextra -O2 -shared -o "$BUILD_DIR/modules/sched/pgs_sched_module.dll" modules/sched/SchedCron.cpp modules/sched/pgs_sched_module.cpp -Iinclude
cp -f "$MINGW_ROOT/bin/libstdc++-6.dll" "$BUILD_DIR/modules/sched/" 2>/dev/null || true
cp -f "$MINGW_ROOT/bin/libgcc_s_seh-1.dll" "$BUILD_DIR/modules/sched/" 2>/dev/null || true
cp -f "$MINGW_ROOT/bin/libwinpthread-1.dll" "$BUILD_DIR/modules/sched/" 2>/dev/null || true
cp -f modules/sched/module.html "$BUILD_DIR/modules/sched/module.html"
cp -f modules/sched/module.manifest "$BUILD_DIR/modules/sched/module.manifest"

# Health module: lightweight service status wrapper around stats/list/events.
echo "[12/15] Building pgs_health_module.dll..."
mkdir -p "$BUILD_DIR/modules/health"
"$GXX" -std=c++17 -Wall -Wextra -O2 -shared -o "$BUILD_DIR/modules/health/pgs_health_module.dll" modules/health/pgs_health_module.cpp -Iinclude
cp -f "$MINGW_ROOT/bin/libstdc++-6.dll" "$BUILD_DIR/modules/health/" 2>/dev/null || true
cp -f "$MINGW_ROOT/bin/libgcc_s_seh-1.dll" "$BUILD_DIR/modules/health/" 2>/dev/null || true
cp -f "$MINGW_ROOT/bin/libwinpthread-1.dll" "$BUILD_DIR/modules/health/" 2>/dev/null || true
cp -f modules/health/module.html "$BUILD_DIR/modules/health/module.html"
cp -f modules/health/module.manifest "$BUILD_DIR/modules/health/module.manifest"

# Profile module: named restart-policy profiles, persisted beside the module.
echo "[13/15] Building pgs_profile_module.dll..."
mkdir -p "$BUILD_DIR/modules/profile"
"$GXX" -std=c++17 -Wall -Wextra -O2 -shared -o "$BUILD_DIR/modules/profile/pgs_profile_module.dll" modules/profile/pgs_profile_module.cpp -Iinclude
cp -f "$MINGW_ROOT/bin/libstdc++-6.dll" "$BUILD_DIR/modules/profile/" 2>/dev/null || true
cp -f "$MINGW_ROOT/bin/libgcc_s_seh-1.dll" "$BUILD_DIR/modules/profile/" 2>/dev/null || true
cp -f "$MINGW_ROOT/bin/libwinpthread-1.dll" "$BUILD_DIR/modules/profile/" 2>/dev/null || true
cp -f modules/profile/module.html "$BUILD_DIR/modules/profile/module.html"
cp -f modules/profile/module.manifest "$BUILD_DIR/modules/profile/module.manifest"

# Report module: base64 snapshots/backup exports from stats/list/events.
echo "[14/15] Building pgs_report_module.dll..."
mkdir -p "$BUILD_DIR/modules/report"
"$GXX" -std=c++17 -Wall -Wextra -O2 -shared -o "$BUILD_DIR/modules/report/pgs_report_module.dll" modules/report/pgs_report_module.cpp -Iinclude
cp -f "$MINGW_ROOT/bin/libstdc++-6.dll" "$BUILD_DIR/modules/report/" 2>/dev/null || true
cp -f "$MINGW_ROOT/bin/libgcc_s_seh-1.dll" "$BUILD_DIR/modules/report/" 2>/dev/null || true
cp -f "$MINGW_ROOT/bin/libwinpthread-1.dll" "$BUILD_DIR/modules/report/" 2>/dev/null || true
cp -f modules/report/module.html "$BUILD_DIR/modules/report/module.html"
cp -f modules/report/module.manifest "$BUILD_DIR/modules/report/module.manifest"

# Default module allowlist: approve the bundled modules.
mkdir -p "$BUILD_DIR/modules"
printf "ppl\nsched\nhealth\nprofile\nreport\n" > "$BUILD_DIR/modules/modules.allow"

# PPL module: built as a separate shared DLL. Per-folder layout
# build/modules/<name>/<name>.dll + module.html + assets. The folder name MUST
# match the module PG_GetName() return value so the Qt UI and
# `module call --name <folder>` resolve correctly.
echo "[15/15] Building pgs_ppl_module.dll..."
mkdir -p "$BUILD_DIR/modules/ppl"
"$GXX" -std=c++17 -Wall -Wextra -O2 -shared -o "$BUILD_DIR/modules/ppl/pgs_ppl_module.dll" modules/ppl/pgs_ppl_module.cpp -Iinclude -ladvapi32
cp -f modules/ppl/Sirius.sys "$BUILD_DIR/modules/ppl/Sirius.sys"
cp -f modules/ppl/module.html "$BUILD_DIR/modules/ppl/module.html"
cp -f modules/ppl/module.manifest "$BUILD_DIR/modules/ppl/module.manifest"
# MinGW runtime DLLs: copy into build/ (process dir) and build/modules/ppl/
# (module folder, self-contained) so binaries run without MSYS2 in PATH. The
# module DLL inherits libstdc++/libgcc from the already-loaded pgs_service.exe,
# but we copy them for standalone use too.
cp -f "$MINGW_ROOT/bin/libstdc++-6.dll" "$BUILD_DIR/" 2>/dev/null || true
cp -f "$MINGW_ROOT/bin/libgcc_s_seh-1.dll" "$BUILD_DIR/" 2>/dev/null || true
cp -f "$MINGW_ROOT/bin/libwinpthread-1.dll" "$BUILD_DIR/" 2>/dev/null || true
cp -f "$MINGW_ROOT/bin/libstdc++-6.dll" "$BUILD_DIR/modules/ppl/" 2>/dev/null || true
cp -f "$MINGW_ROOT/bin/libgcc_s_seh-1.dll" "$BUILD_DIR/modules/ppl/" 2>/dev/null || true
cp -f "$MINGW_ROOT/bin/libwinpthread-1.dll" "$BUILD_DIR/modules/ppl/" 2>/dev/null || true

echo
echo "Build completed:"
echo "- $BUILD_DIR/pgs_service.exe"
echo "- $BUILD_DIR/guard_example.exe"
echo "- $BUILD_DIR/quick_start.exe"
echo "- $BUILD_DIR/smoke_worker.exe"
echo "- $BUILD_DIR/pgs_bless.exe"
echo "- $BUILD_DIR/modules/sched/pgs_sched_module.dll"
echo "- $BUILD_DIR/modules/health/pgs_health_module.dll"
echo "- $BUILD_DIR/modules/profile/pgs_profile_module.dll"
echo "- $BUILD_DIR/modules/report/pgs_report_module.dll"
echo "- $BUILD_DIR/modules/ppl/pgs_ppl_module.dll"
echo "- $BUILD_DIR/modules/ppl/Sirius.sys"
echo "- $BUILD_DIR/modules/ppl/module.html"
