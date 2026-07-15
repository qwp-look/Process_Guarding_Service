#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$repo_root"

MINGW_ROOT="${MINGW_ROOT:-/mingw64}"
export PATH="$MINGW_ROOT/bin:/usr/bin:$PATH"
GXX="${GXX:-$MINGW_ROOT/bin/g++.exe}"

# v3: NTDDI_VERSION >= Win8 enables MinGW's IApplicationActivationManager
# (used by restartAppGuard for WindowsApps activation), no WinRT headers needed.
CXXFLAGS="-std=c++17 -Wall -Wextra -O2 -Iinclude -DNTDDI_VERSION=0x06020000"
mkdir -p build build/tmp
export TMPDIR="${TMPDIR:-$PWD/build/tmp}"
export TEMP="${TEMP:-$TMPDIR}"
export TMP="${TMP:-$TMPDIR}"

# Keep this script close to the manual build instructions in README so local
# debugging and scripted verification use the same MinGW64 toolchain path.

echo "[1/15] Compiling logger..."
"$GXX" $CXXFLAGS -c src/common/PGLogger.cpp -o build/PGLogger.o

echo "[2/15] Compiling PGS core..."
"$GXX" $CXXFLAGS -c src/service/PGS.cpp -o build/PGS.o

# Module system: ModuleManager is linked into pgs_service.exe.
echo "[3/15] Compiling module manager..."
"$GXX" $CXXFLAGS -c src/modules/ModuleManager.cpp -o build/ModuleManager.o

echo "[4/15] Compiling PGS protocol layer..."
"$GXX" $CXXFLAGS -c src/service/PGSProtocol.cpp -o build/PGSProtocol.o

echo "[5/15] Compiling service host..."
"$GXX" $CXXFLAGS -c src/service/pgs_service.cpp -o build/pgs_service.o

echo "[6/15] Linking pgs_service.exe..."
"$GXX" -std=c++17 -Wall -Wextra -O2 \
  build/PGLogger.o build/PGS.o build/PGSProtocol.o build/ModuleManager.o build/pgs_service.o \
  -o build/pgs_service.exe \
  -lws2_32 -ladvapi32 -lwtsapi32 -luserenv -lbcrypt -lwintrust -lole32 -lshell32

echo "[7/15] Building guard_example.exe..."
"$GXX" $CXXFLAGS examples/guard_example.cpp -o build/guard_example.exe -lws2_32 -ladvapi32 -lbcrypt

echo "[8/15] Building quick_start.exe..."
"$GXX" $CXXFLAGS examples/quick_start.cpp -o build/quick_start.exe -lws2_32 -ladvapi32 -lbcrypt

echo "[9/15] Building smoke_worker.exe..."
"$GXX" $CXXFLAGS examples/smoke_worker.cpp -o build/smoke_worker.exe -lws2_32

echo "[10/15] Building pgs_bless.exe..."
"$GXX" $CXXFLAGS -c src/common/PGSClient.cpp -o build/PGSClient.o
"$GXX" $CXXFLAGS tools/pgs_bless.cpp build/PGSClient.o build/ModuleManager.o build/PGLogger.o -o build/pgs_bless.exe \
  -lws2_32 -ladvapi32 -lbcrypt -lwintrust -lole32

# Schedule module: cron/once/interval scheduler (ABI v2).
echo "[11/15] Building pgs_sched_module.dll..."
mkdir -p build/modules/sched
"$GXX" -std=c++17 -Wall -Wextra -O2 -shared -o build/modules/sched/pgs_sched_module.dll modules/sched/SchedCron.cpp modules/sched/pgs_sched_module.cpp -Iinclude
cp -f "$MINGW_ROOT/bin/libstdc++-6.dll" build/modules/sched/ 2>/dev/null || true
cp -f "$MINGW_ROOT/bin/libgcc_s_seh-1.dll" build/modules/sched/ 2>/dev/null || true
cp -f "$MINGW_ROOT/bin/libwinpthread-1.dll" build/modules/sched/ 2>/dev/null || true
cp -f modules/sched/module.html build/modules/sched/module.html
cp -f modules/sched/module.manifest build/modules/sched/module.manifest
cp -f modules/sched/module.manifest.json build/modules/sched/module.manifest.json

# Health module: lightweight service status wrapper around stats/list/events.
echo "[12/15] Building pgs_health_module.dll..."
mkdir -p build/modules/health
"$GXX" -std=c++17 -Wall -Wextra -O2 -shared -o build/modules/health/pgs_health_module.dll modules/health/pgs_health_module.cpp -Iinclude
cp -f "$MINGW_ROOT/bin/libstdc++-6.dll" build/modules/health/ 2>/dev/null || true
cp -f "$MINGW_ROOT/bin/libgcc_s_seh-1.dll" build/modules/health/ 2>/dev/null || true
cp -f "$MINGW_ROOT/bin/libwinpthread-1.dll" build/modules/health/ 2>/dev/null || true
cp -f modules/health/module.html build/modules/health/module.html
cp -f modules/health/module.manifest build/modules/health/module.manifest
cp -f modules/health/module.manifest.json build/modules/health/module.manifest.json

# Profile module: named restart-policy profiles, persisted beside the module.
echo "[13/15] Building pgs_profile_module.dll..."
mkdir -p build/modules/profile
"$GXX" -std=c++17 -Wall -Wextra -O2 -shared -o build/modules/profile/pgs_profile_module.dll modules/profile/pgs_profile_module.cpp -Iinclude
cp -f "$MINGW_ROOT/bin/libstdc++-6.dll" build/modules/profile/ 2>/dev/null || true
cp -f "$MINGW_ROOT/bin/libgcc_s_seh-1.dll" build/modules/profile/ 2>/dev/null || true
cp -f "$MINGW_ROOT/bin/libwinpthread-1.dll" build/modules/profile/ 2>/dev/null || true
cp -f modules/profile/module.html build/modules/profile/module.html
cp -f modules/profile/module.manifest build/modules/profile/module.manifest
cp -f modules/profile/module.manifest.json build/modules/profile/module.manifest.json

# Report module: base64 snapshots/backup exports from stats/list/events.
echo "[14/15] Building pgs_report_module.dll..."
mkdir -p build/modules/report
"$GXX" -std=c++17 -Wall -Wextra -O2 -shared -o build/modules/report/pgs_report_module.dll modules/report/pgs_report_module.cpp -Iinclude
cp -f "$MINGW_ROOT/bin/libstdc++-6.dll" build/modules/report/ 2>/dev/null || true
cp -f "$MINGW_ROOT/bin/libgcc_s_seh-1.dll" build/modules/report/ 2>/dev/null || true
cp -f "$MINGW_ROOT/bin/libwinpthread-1.dll" build/modules/report/ 2>/dev/null || true
cp -f modules/report/module.html build/modules/report/module.html
cp -f modules/report/module.manifest build/modules/report/module.manifest
cp -f modules/report/module.manifest.json build/modules/report/module.manifest.json

# Default module allowlist: approve the bundled modules.
mkdir -p build/modules
printf "ppl\nsched\nhealth\nprofile\nreport\n" > build/modules/modules.allow

# PPL module: built as a separate shared DLL. Per-folder layout
# build/modules/<name>/<name>.dll + module.html + assets. The folder name MUST
# match the module PG_GetName() return value so the Qt UI and
# `module call --name <folder>` resolve correctly.
echo "[15/15] Building pgs_ppl_module.dll..."
mkdir -p build/modules/ppl
"$GXX" -std=c++17 -Wall -Wextra -O2 -shared -o build/modules/ppl/pgs_ppl_module.dll modules/ppl/pgs_ppl_module.cpp -Iinclude -ladvapi32
cp -f modules/ppl/Sirius.sys build/modules/ppl/Sirius.sys
cp -f modules/ppl/module.html build/modules/ppl/module.html
cp -f modules/ppl/module.manifest build/modules/ppl/module.manifest
cp -f modules/ppl/module.manifest.json build/modules/ppl/module.manifest.json
# MinGW runtime DLLs: copy into build/ (process dir) and build/modules/ppl/
# (module folder, self-contained) so binaries run without MSYS2 in PATH. The
# module DLL inherits libstdc++/libgcc from the already-loaded pgs_service.exe,
# but we copy them for standalone use too.
cp -f "$MINGW_ROOT/bin/libstdc++-6.dll" build/ 2>/dev/null || true
cp -f "$MINGW_ROOT/bin/libgcc_s_seh-1.dll" build/ 2>/dev/null || true
cp -f "$MINGW_ROOT/bin/libwinpthread-1.dll" build/ 2>/dev/null || true
cp -f "$MINGW_ROOT/bin/libstdc++-6.dll" build/modules/ppl/ 2>/dev/null || true
cp -f "$MINGW_ROOT/bin/libgcc_s_seh-1.dll" build/modules/ppl/ 2>/dev/null || true
cp -f "$MINGW_ROOT/bin/libwinpthread-1.dll" build/modules/ppl/ 2>/dev/null || true

{
  echo '{"version":1,"generated_at":"build","modules":['
  first=1
  for name in sched health profile report ppl; do
    dll="build/modules/$name/pgs_${name}_module.dll"
    hash="$(sha256sum "$dll" | awk '{print $1}')"
    [ $first -eq 1 ] || echo ','
    first=0
    risk="low"; [ "$name" = "ppl" ] && risk="critical"; [ "$name" = "sched" ] && risk="medium"; [ "$name" = "profile" ] && risk="medium"
    caps='[]'
    case "$name" in
      sched) caps='["sched.add","sched.list","sched.remove","sched.enable","sched.disable","guard.register","guard.unregister","guard.intentional","guard.policy","guard.list"]' ;;
      health) caps='["health.summary","health.stats","guard.list","event.read"]' ;;
      profile) caps='["profile.set","profile.list","profile.apply","guard.policy"]' ;;
      report) caps='["report.snapshot","report.backup","event.read","guard.list","health.stats"]' ;;
      ppl) caps='["driver.kernel","driver.sirius.load","process.ppl.set","process.ppl.clear","ppl.set","ppl.get","ppl.clear"]' ;;
    esac
    printf '{"name":"%s","version":"1.0.0","sha256":"%s","publisher":"PGS bundled","source":"bundled","capabilities":%s,"risk":"%s","trustedAt":"build","signature_policy":"hash","require_signed":false}' "$name" "$hash" "$caps" "$risk"
  done
  echo ']}'
} > build/modules/modules.lock

echo
echo "Build completed:"
echo "- build/pgs_service.exe"
echo "- build/guard_example.exe"
echo "- build/quick_start.exe"
echo "- build/smoke_worker.exe"
echo "- build/pgs_bless.exe"
echo "- build/modules/sched/pgs_sched_module.dll"
echo "- build/modules/health/pgs_health_module.dll"
echo "- build/modules/profile/pgs_profile_module.dll"
echo "- build/modules/report/pgs_report_module.dll"
echo "- build/modules/ppl/pgs_ppl_module.dll"
echo "- build/modules/ppl/Sirius.sys"
echo "- build/modules/ppl/module.html"
