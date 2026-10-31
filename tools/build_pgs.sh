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
TOTAL_STEPS=22
mkdir -p "$BUILD_DIR" "$BUILD_DIR/tmp"
export TMPDIR="${TMPDIR:-$PWD/$BUILD_DIR/tmp}"
export TEMP="${TEMP:-$TMPDIR}"
export TMP="${TMP:-$TMPDIR}"

# Keep this script close to the manual build instructions in README so local
# debugging and scripted verification use the same MinGW64 toolchain path.

copy_mingw_runtime() {
  local dst="$1"
  cp -f "$MINGW_ROOT/bin/libstdc++-6.dll" "$dst/" 2>/dev/null || true
  cp -f "$MINGW_ROOT/bin/libgcc_s_seh-1.dll" "$dst/" 2>/dev/null || true
  cp -f "$MINGW_ROOT/bin/libwinpthread-1.dll" "$dst/" 2>/dev/null || true
  cp -f "$MINGW_ROOT/bin/libsqlite3-0.dll" "$dst/" 2>/dev/null || true
}

copy_module_assets() {
  local name="$1"
  cp -f "modules/$name/module.html" "$BUILD_DIR/modules/$name/module.html"

  cp -f "modules/$name/module.manifest.json" "$BUILD_DIR/modules/$name/module.manifest.json"
}

build_module() {
  local step="$1"
  local name="$2"
  local output="$3"
  local sources="$4"
  local libs="${5:-}"
  echo "[$step/$TOTAL_STEPS] Building $output.dll..."
  mkdir -p "$BUILD_DIR/modules/$name"
  # shellcheck disable=SC2086
  "$GXX" -std=c++17 -Wall -Wextra -O2 -shared -o "$BUILD_DIR/modules/$name/$output.dll" $sources -Iinclude $libs
  copy_mingw_runtime "$BUILD_DIR/modules/$name"
  copy_module_assets "$name"
}

# Manifest-driven modules.lock generation (manifest v2): the lock is derived
# from each module's module.manifest.json plus the built DLL hash, so the
# module set lives in the manifests instead of a hardcoded list here.
write_modules_lock() {
  powershell.exe -NoProfile -ExecutionPolicy Bypass \
    -File tools/write_modules_lock.ps1 \
    -ModulesRoot "$(cygpath -w "$BUILD_DIR/modules")" \
    -Output "$(cygpath -w "$BUILD_DIR/modules/modules.lock")" \
    -GeneratedAt build
}

echo "[1/$TOTAL_STEPS] Compiling logger..."
"$GXX" $CXXFLAGS -c src/common/PGLogger.cpp -o "$BUILD_DIR/PGLogger.o"

echo "[2/$TOTAL_STEPS] Compiling PGS core..."
"$GXX" $CXXFLAGS -c src/service/PGS.cpp -o "$BUILD_DIR/PGS.o"
"$GXX" $CXXFLAGS -c src/service/PGSServer.cpp -o "$BUILD_DIR/PGSServer.o"
"$GXX" $CXXFLAGS -c src/service/PGSMonitor.cpp -o "$BUILD_DIR/PGSMonitor.o"
"$GXX" $CXXFLAGS -c src/service/PGSHealth.cpp -o "$BUILD_DIR/PGSHealth.o"
"$GXX" $CXXFLAGS -c src/service/PGSGuardStore.cpp -o "$BUILD_DIR/PGSGuardStore.o"
"$GXX" $CXXFLAGS -c src/service/PGSSqliteStore.cpp -o "$BUILD_DIR/PGSSqliteStore.o"

# Module system: ModuleManager is linked into pgs_service.exe.
echo "[3/$TOTAL_STEPS] Compiling module manager..."
"$GXX" $CXXFLAGS -c src/modules/ModuleManager.cpp -o "$BUILD_DIR/ModuleManager.o"

echo "[4/$TOTAL_STEPS] Compiling PGS protocol and module install handlers..."
"$GXX" $CXXFLAGS -c src/service/PGSProtocol.cpp -o "$BUILD_DIR/PGSProtocol.o"
"$GXX" $CXXFLAGS -c src/service/PGSOperationStore.cpp -o "$BUILD_DIR/PGSOperationStore.o"
"$GXX" $CXXFLAGS -c src/service/PGSModuleInstall.cpp -o "$BUILD_DIR/PGSModuleInstall.o"

echo "[5/$TOTAL_STEPS] Compiling service host..."
"$GXX" $CXXFLAGS -c src/service/pgs_service.cpp -o "$BUILD_DIR/pgs_service.o"

echo "[6/$TOTAL_STEPS] Linking pgs_service.exe..."
"$GXX" -std=c++17 -Wall -Wextra -O2 \
  "$BUILD_DIR/PGLogger.o" "$BUILD_DIR/PGS.o" "$BUILD_DIR/PGSServer.o" "$BUILD_DIR/PGSMonitor.o" "$BUILD_DIR/PGSHealth.o" "$BUILD_DIR/PGSGuardStore.o" "$BUILD_DIR/PGSSqliteStore.o" "$BUILD_DIR/PGSProtocol.o" "$BUILD_DIR/PGSOperationStore.o" "$BUILD_DIR/PGSModuleInstall.o" "$BUILD_DIR/ModuleManager.o" "$BUILD_DIR/pgs_service.o" \
  -o "$BUILD_DIR/pgs_service.exe" \
  -lws2_32 -lwinhttp -ladvapi32 -lwtsapi32 -luserenv -lbcrypt -lwintrust -lole32 -lshell32 -lsqlite3

echo "[7/$TOTAL_STEPS] Building guard_example.exe..."
"$GXX" $CXXFLAGS examples/guard_example.cpp -o "$BUILD_DIR/guard_example.exe" -lws2_32 -ladvapi32 -lbcrypt

echo "[8/$TOTAL_STEPS] Building quick_start.exe..."
"$GXX" $CXXFLAGS examples/quick_start.cpp -o "$BUILD_DIR/quick_start.exe" -lws2_32 -ladvapi32 -lbcrypt

echo "[9/$TOTAL_STEPS] Building smoke_worker.exe..."
"$GXX" $CXXFLAGS examples/smoke_worker.cpp -o "$BUILD_DIR/smoke_worker.exe" -lws2_32

echo "[10/$TOTAL_STEPS] Building pgs_bless.exe..."
"$GXX" $CXXFLAGS -c src/common/PGSClient.cpp -o "$BUILD_DIR/PGSClient.o"
"$GXX" $CXXFLAGS -c tools/PGSRegistryInstall.cpp -o "$BUILD_DIR/PGSRegistryInstall.o"
"$GXX" $CXXFLAGS tools/pgs_bless.cpp "$BUILD_DIR/PGSRegistryInstall.o" "$BUILD_DIR/PGSClient.o" "$BUILD_DIR/ModuleManager.o" "$BUILD_DIR/PGLogger.o" -o "$BUILD_DIR/pgs_bless.exe" \
  -lws2_32 -lwinhttp -ladvapi32 -lbcrypt -lwintrust -lole32 -lshell32

build_module 11 sched pgs_sched_module "modules/sched/SchedCron.cpp modules/sched/pgs_sched_module.cpp"
build_module 12 health pgs_health_module "modules/health/pgs_health_module.cpp"
build_module 13 report pgs_report_module "modules/report/pgs_report_module.cpp"
build_module 14 notify pgs_notify_module "modules/notify/pgs_notify_module.cpp" "-ladvapi32 -luser32"
build_module 15 metrics pgs_metrics_module "modules/metrics/pgs_metrics_module.cpp"
build_module 16 backup pgs_backup_module "modules/backup/pgs_backup_module.cpp"
build_module 17 eventlog pgs_eventlog_module "modules/eventlog/pgs_eventlog_module.cpp" "-ladvapi32"
build_module 18 dump pgs_dump_module "modules/dump/pgs_dump_module.cpp" "-ldbghelp"
build_module 19 service_guard pgs_service_guard_module "modules/service_guard/pgs_service_guard_module.cpp" "-ladvapi32"
build_module 20 file_watch pgs_file_watch_module "modules/file_watch/pgs_file_watch_module.cpp" "-lbcrypt"
build_module 21 policy pgs_policy_module "modules/policy/pgs_policy_module.cpp"
build_module 22 winapp pgs_winapp_module "modules/winapp/pgs_winapp_module.cpp" "-lole32 -lshell32 -luser32"

copy_mingw_runtime "$BUILD_DIR"

# Default module allowlist: approve the bundled modules. winapp is trusted but
# NOT startup-enabled (provider class; opt in via --enable-launchers).
printf "sched\nhealth\nreport\nnotify\nmetrics\nbackup\neventlog\ndump\nservice_guard\nfile_watch\npolicy\nwinapp\n" > "$BUILD_DIR/modules/modules.allow"
write_modules_lock

echo
echo "Build completed:"
echo "- $BUILD_DIR/pgs_service.exe"
echo "- $BUILD_DIR/guard_example.exe"
echo "- $BUILD_DIR/quick_start.exe"
echo "- $BUILD_DIR/smoke_worker.exe"
echo "- $BUILD_DIR/pgs_bless.exe"
for name in sched health report notify metrics backup eventlog dump service_guard file_watch policy winapp; do
  echo "- $BUILD_DIR/modules/$name/pgs_${name}_module.dll"
done
