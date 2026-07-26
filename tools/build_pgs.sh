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
TOTAL_STEPS=26
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
}

copy_module_assets() {
  local name="$1"
  cp -f "modules/$name/module.html" "$BUILD_DIR/modules/$name/module.html"
  cp -f "modules/$name/module.manifest" "$BUILD_DIR/modules/$name/module.manifest"
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

write_modules_lock() {
  {
    echo '{"version":1,"generated_at":"build","modules":['
    local first=1
    local names=(sched health profile report notify metrics backup eventlog dump service_guard file_watch policy remote_agent update script_runner ppl)
    for name in "${names[@]}"; do
      local dll="$BUILD_DIR/modules/$name/pgs_${name}_module.dll"
      local hash
      hash="$(sha256sum "$dll" | awk '{print $1}')"
      [ "$first" -eq 1 ] || echo ','
      first=0
      local risk="low"
      local version="1.0.0"
      local caps='[]'
      case "$name" in
        sched)
          risk="medium"
          caps='["sched.add","sched.list","sched.remove","sched.enable","sched.disable","guard.register","guard.unregister","guard.intentional","guard.policy","guard.list"]'
          ;;
        health)
          caps='["health.summary","health.stats","guard.list","event.read"]'
          ;;
        profile)
          risk="medium"
          caps='["profile.set","profile.list","profile.apply","guard.policy"]'
          ;;
        report)
          version="1.1.0"
          caps='["report.snapshot","report.backup","event.read","guard.list","health.stats","pgs.operation.create","pgs.operation.update","pgs.operation.finish","pgs.operation.fail","pgs.artifact.put","pgs.artifact.get_meta"]'
          ;;
        notify)
          caps='["notify.eventlog","notify.popup","event.read"]'
          ;;
        metrics)
          caps='["metrics.summary","metrics.prometheus","health.stats","guard.list"]'
          ;;
        backup)
          caps='["backup.snapshot","pgs.operation.create","pgs.operation.finish","pgs.operation.fail","pgs.artifact.put"]'
          ;;
        eventlog)
          caps='["eventlog.read","event.read"]'
          ;;
        dump)
          risk="high"
          caps='["dump.collect","pgs.operation.create","pgs.operation.finish","pgs.operation.fail","pgs.artifact.put"]'
          ;;
        service_guard)
          risk="medium"
          caps='["service.query","service.start","service.stop"]'
          ;;
        file_watch)
          risk="medium"
          caps='["file.watch","event.emit"]'
          ;;
        policy)
          risk="medium"
          caps='["policy.template","guard.policy"]'
          ;;
        remote_agent)
          risk="medium"
          caps='["remote_agent.status","guard.list","health.stats"]'
          ;;
        update)
          risk="medium"
          caps='["update.verify"]'
          ;;
        script_runner)
          risk="high"
          caps='["script.run"]'
          ;;
        ppl)
          risk="critical"
          caps='["driver.kernel","driver.sirius.load","process.ppl.set","process.ppl.clear","ppl.set","ppl.get","ppl.clear"]'
          ;;
      esac
      printf '{"name":"%s","version":"%s","sha256":"%s","publisher":"PGS bundled","source":"bundled","capabilities":%s,"risk":"%s","trustedAt":"build","signature_policy":"hash","require_signed":false}' "$name" "$version" "$hash" "$caps" "$risk"
    done
    echo ']}'
  } > "$BUILD_DIR/modules/modules.lock"
}

echo "[1/$TOTAL_STEPS] Compiling logger..."
"$GXX" $CXXFLAGS -c src/common/PGLogger.cpp -o "$BUILD_DIR/PGLogger.o"

echo "[2/$TOTAL_STEPS] Compiling PGS core..."
"$GXX" $CXXFLAGS -c src/service/PGS.cpp -o "$BUILD_DIR/PGS.o"

# Module system: ModuleManager is linked into pgs_service.exe.
echo "[3/$TOTAL_STEPS] Compiling module manager..."
"$GXX" $CXXFLAGS -c src/modules/ModuleManager.cpp -o "$BUILD_DIR/ModuleManager.o"

echo "[4/$TOTAL_STEPS] Compiling PGS protocol and module install handlers..."
"$GXX" $CXXFLAGS -c src/service/PGSProtocol.cpp -o "$BUILD_DIR/PGSProtocol.o"
"$GXX" $CXXFLAGS -c src/service/PGSModuleInstall.cpp -o "$BUILD_DIR/PGSModuleInstall.o"

echo "[5/$TOTAL_STEPS] Compiling service host..."
"$GXX" $CXXFLAGS -c src/service/pgs_service.cpp -o "$BUILD_DIR/pgs_service.o"

echo "[6/$TOTAL_STEPS] Linking pgs_service.exe..."
"$GXX" -std=c++17 -Wall -Wextra -O2 \
  "$BUILD_DIR/PGLogger.o" "$BUILD_DIR/PGS.o" "$BUILD_DIR/PGSProtocol.o" "$BUILD_DIR/PGSModuleInstall.o" "$BUILD_DIR/ModuleManager.o" "$BUILD_DIR/pgs_service.o" \
  -o "$BUILD_DIR/pgs_service.exe" \
  -lws2_32 -lwinhttp -ladvapi32 -lwtsapi32 -luserenv -lbcrypt -lwintrust -lole32 -lshell32

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
build_module 13 profile pgs_profile_module "modules/profile/pgs_profile_module.cpp"
build_module 14 report pgs_report_module "modules/report/pgs_report_module.cpp"
build_module 15 notify pgs_notify_module "modules/notify/pgs_notify_module.cpp" "-ladvapi32 -luser32"
build_module 16 metrics pgs_metrics_module "modules/metrics/pgs_metrics_module.cpp"
build_module 17 backup pgs_backup_module "modules/backup/pgs_backup_module.cpp"
build_module 18 eventlog pgs_eventlog_module "modules/eventlog/pgs_eventlog_module.cpp" "-ladvapi32"
build_module 19 dump pgs_dump_module "modules/dump/pgs_dump_module.cpp" "-ldbghelp"
build_module 20 service_guard pgs_service_guard_module "modules/service_guard/pgs_service_guard_module.cpp" "-ladvapi32"
build_module 21 file_watch pgs_file_watch_module "modules/file_watch/pgs_file_watch_module.cpp" "-lbcrypt"
build_module 22 policy pgs_policy_module "modules/policy/pgs_policy_module.cpp"
build_module 23 remote_agent pgs_remote_agent_module "modules/remote_agent/pgs_remote_agent_module.cpp"
build_module 24 update pgs_update_module "modules/update/pgs_update_module.cpp" "-lbcrypt"
build_module 25 script_runner pgs_script_runner_module "modules/script_runner/pgs_script_runner_module.cpp"

# PPL module: built as a separate shared DLL. Per-folder layout
# build/modules/<name>/<name>.dll + module.html + assets. The folder name MUST
# match the module PG_GetName() return value so the Qt UI and
# `module call --name <folder>` resolve correctly.
build_module 26 ppl pgs_ppl_module "modules/ppl/pgs_ppl_module.cpp" "-ladvapi32"
cp -f modules/ppl/Sirius.sys "$BUILD_DIR/modules/ppl/Sirius.sys"
copy_mingw_runtime "$BUILD_DIR"

# Default module allowlist: approve the bundled modules.
printf "ppl\nsched\nhealth\nprofile\nreport\nnotify\nmetrics\nbackup\neventlog\ndump\nservice_guard\nfile_watch\npolicy\nremote_agent\nupdate\nscript_runner\n" > "$BUILD_DIR/modules/modules.allow"
write_modules_lock

echo
echo "Build completed:"
echo "- $BUILD_DIR/pgs_service.exe"
echo "- $BUILD_DIR/guard_example.exe"
echo "- $BUILD_DIR/quick_start.exe"
echo "- $BUILD_DIR/smoke_worker.exe"
echo "- $BUILD_DIR/pgs_bless.exe"
for name in sched health profile report notify metrics backup eventlog dump service_guard file_watch policy remote_agent update script_runner ppl; do
  echo "- $BUILD_DIR/modules/$name/pgs_${name}_module.dll"
done
echo "- $BUILD_DIR/modules/ppl/Sirius.sys"
echo "- $BUILD_DIR/modules/ppl/module.html"
