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

echo "[1/12] Compiling logger..."
"$GXX" $CXXFLAGS -c src/common/PGLogger.cpp -o build/PGLogger.o

echo "[2/12] Compiling PGS core..."
"$GXX" $CXXFLAGS -c src/service/PGS.cpp -o build/PGS.o

# Module system: ModuleManager is linked into pgs_service.exe.
echo "[3/12] Compiling module manager..."
"$GXX" $CXXFLAGS -c src/modules/ModuleManager.cpp -o build/ModuleManager.o

echo "[4/12] Compiling PGS protocol layer..."
"$GXX" $CXXFLAGS -c src/service/PGSProtocol.cpp -o build/PGSProtocol.o

echo "[5/12] Compiling service host..."
"$GXX" $CXXFLAGS -c src/service/pgs_service.cpp -o build/pgs_service.o

echo "[6/12] Linking pgs_service.exe..."
"$GXX" -std=c++17 -Wall -Wextra -O2 \
  build/PGLogger.o build/PGS.o build/PGSProtocol.o build/ModuleManager.o build/pgs_service.o \
  -o build/pgs_service.exe \
  -lws2_32 -ladvapi32 -lwtsapi32 -luserenv -lbcrypt -lwintrust -lole32 -lshell32

echo "[7/12] Building guard_example.exe..."
"$GXX" $CXXFLAGS examples/guard_example.cpp -o build/guard_example.exe -lws2_32 -ladvapi32 -lbcrypt

echo "[8/12] Building quick_start.exe..."
"$GXX" $CXXFLAGS examples/quick_start.cpp -o build/quick_start.exe -lws2_32 -ladvapi32 -lbcrypt

echo "[9/12] Building smoke_worker.exe..."
"$GXX" $CXXFLAGS examples/smoke_worker.cpp -o build/smoke_worker.exe -lws2_32

echo "[10/12] Building pgs_bless.exe..."
"$GXX" $CXXFLAGS -c src/common/PGSClient.cpp -o build/PGSClient.o
"$GXX" $CXXFLAGS tools/pgs_bless.cpp build/PGSClient.o -o build/pgs_bless.exe -lws2_32 -ladvapi32 -lbcrypt

# Schedule module: cron/once/interval scheduler (ABI v2).
echo "[11/12] Building pgs_sched_module.dll..."
mkdir -p build/modules/sched
"$GXX" -std=c++17 -Wall -Wextra -O2 -shared -o build/modules/sched/pgs_sched_module.dll modules/sched/SchedCron.cpp modules/sched/pgs_sched_module.cpp -Iinclude
cp -f "$MINGW_ROOT/bin/libstdc++-6.dll" build/modules/sched/ 2>/dev/null || true
cp -f "$MINGW_ROOT/bin/libgcc_s_seh-1.dll" build/modules/sched/ 2>/dev/null || true
cp -f "$MINGW_ROOT/bin/libwinpthread-1.dll" build/modules/sched/ 2>/dev/null || true
cp -f modules/sched/module.html build/modules/sched/module.html

# Default module allowlist: approve the bundled ppl + sched modules.
mkdir -p build/modules
printf "ppl\nsched\n" > build/modules/modules.allow

# PPL module: built as a separate shared DLL. Per-folder layout
# build/modules/<name>/<name>.dll + module.html + assets. The folder name MUST
# match the module PG_GetName() return value so the Qt UI and
# `module call --name <folder>` resolve correctly.
echo "[12/12] Building pgs_ppl_module.dll..."
mkdir -p build/modules/ppl
"$GXX" -std=c++17 -Wall -Wextra -O2 -shared -o build/modules/ppl/pgs_ppl_module.dll modules/ppl/pgs_ppl_module.cpp -Iinclude -ladvapi32
cp -f modules/ppl/Sirius.sys build/modules/ppl/Sirius.sys
cp -f modules/ppl/module.html build/modules/ppl/module.html
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

echo
echo "Build completed:"
echo "- build/pgs_service.exe"
echo "- build/guard_example.exe"
echo "- build/quick_start.exe"
echo "- build/smoke_worker.exe"
echo "- build/pgs_bless.exe"
echo "- build/modules/sched/pgs_sched_module.dll"
echo "- build/modules/ppl/pgs_ppl_module.dll"
echo "- build/modules/ppl/Sirius.sys"
echo "- build/modules/ppl/module.html"
