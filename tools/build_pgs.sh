#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$repo_root"

export PATH="/mingw64/bin:/usr/bin"

# v3: NTDDI_VERSION >= Win8 enables MinGW's IApplicationActivationManager
# (used by restartAppGuard for WindowsApps activation), no WinRT headers needed.
CXXFLAGS="-std=c++17 -Wall -Wextra -O2 -Iinclude -DNTDDI_VERSION=0x06020000"
mkdir -p build

# Keep this script close to the manual build instructions in README so local
# debugging and scripted verification use the same MinGW64 toolchain path.

echo "[1/7] Compiling logger..."
g++ $CXXFLAGS -c src/common/PGLogger.cpp -o build/PGLogger.o

echo "[2/7] Compiling PGS core..."
g++ $CXXFLAGS -c src/service/PGS.cpp -o build/PGS.o
# Module system: ModuleManager is linked into pgs_service.exe.
echo "[2.5/9] Compiling module manager..."
g++ $CXXFLAGS -c src/modules/ModuleManager.cpp -o build/ModuleManager.o
g++ $CXXFLAGS -c src/service/PGSProtocol.cpp -o build/PGSProtocol.o

echo "[3/7] Compiling service host..."
g++ $CXXFLAGS -c src/service/pgs_service.cpp -o build/pgs_service.o

echo "[4/7] Linking pgs_service.exe..."
g++ -std=c++17 -Wall -Wextra -O2 \
  build/PGLogger.o build/PGS.o build/PGSProtocol.o build/ModuleManager.o build/pgs_service.o \
  -o build/pgs_service.exe \
  -lws2_32 -ladvapi32 -lwtsapi32 -luserenv -lbcrypt -lwintrust -lole32 -lshell32

echo "[5/7] Building guard_example.exe..."
g++ $CXXFLAGS examples/guard_example.cpp -o build/guard_example.exe -lws2_32 -ladvapi32 -lbcrypt

echo "[6/7] Building quick_start.exe..."
g++ $CXXFLAGS examples/quick_start.cpp -o build/quick_start.exe -lws2_32 -ladvapi32 -lbcrypt

echo "[7/8] Building smoke_worker.exe..."
g++ $CXXFLAGS examples/smoke_worker.cpp -o build/smoke_worker.exe -lws2_32

echo "[8/8] Building pgs_bless.exe..."
g++ $CXXFLAGS -c src/common/PGSClient.cpp -o build/PGSClient.o
g++ $CXXFLAGS tools/pgs_bless.cpp build/PGSClient.o -o build/pgs_bless.exe -lws2_32 -ladvapi32 -lbcrypt

# PPL module: built as a separate shared DLL. Per-folder layout
# build/modules/<name>/<name>.dll + module.html + assets. The folder name MUST
# match the module PG_GetName() return value so the Qt UI and
# `module call --name <folder>` resolve correctly.
echo "[9/9] Building pgs_ppl_module.dll..."
mkdir -p build/modules/ppl
g++ -std=c++17 -Wall -Wextra -O2 -shared -o build/modules/ppl/pgs_ppl_module.dll modules/ppl/pgs_ppl_module.cpp -Iinclude -ladvapi32
cp -f modules/ppl/Sirius.sys build/modules/ppl/Sirius.sys
cp -f modules/ppl/module.html build/modules/ppl/module.html
# MinGW runtime DLLs: copy into build/ (process dir) and build/modules/ppl/
# (module folder, self-contained) so binaries run without MSYS2 in PATH. The
# module DLL inherits libstdc++/libgcc from the already-loaded pgs_service.exe,
# but we copy them for standalone use too.
cp -f /mingw64/bin/libstdc++-6.dll build/ 2>/dev/null || true
cp -f /mingw64/bin/libgcc_s_seh-1.dll build/ 2>/dev/null || true
cp -f /mingw64/bin/libwinpthread-1.dll build/ 2>/dev/null || true
cp -f /mingw64/bin/libstdc++-6.dll build/modules/ppl/ 2>/dev/null || true
cp -f /mingw64/bin/libgcc_s_seh-1.dll build/modules/ppl/ 2>/dev/null || true
cp -f /mingw64/bin/libwinpthread-1.dll build/modules/ppl/ 2>/dev/null || true

echo
echo "Build completed:"
echo "- build/pgs_service.exe"
echo "- build/guard_example.exe"
echo "- build/quick_start.exe"
echo "- build/smoke_worker.exe"
echo "- build/pgs_bless.exe"
echo "- build/modules/ppl/pgs_ppl_module.dll"
echo "- build/modules/ppl/Sirius.sys"
echo "- build/modules/ppl/module.html"