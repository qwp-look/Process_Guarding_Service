#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$repo_root"

export PATH="/mingw64/bin:/usr/bin"
mkdir -p build

# Keep this script close to the manual build instructions in README so local
# debugging and scripted verification use the same MinGW64 toolchain path.

echo "[1/7] Compiling logger..."
g++ -std=c++17 -Wall -Wextra -O2 -Iinclude -c src/common/PGLogger.cpp -o build/PGLogger.o

echo "[2/7] Compiling PGS core..."
g++ -std=c++17 -Wall -Wextra -O2 -Iinclude -c src/service/PGS.cpp -o build/PGS.o

echo "[3/7] Compiling service host..."
g++ -std=c++17 -Wall -Wextra -O2 -Iinclude -c src/service/pgs_service.cpp -o build/pgs_service.o

echo "[4/7] Linking pgs_service.exe..."
g++ -std=c++17 -Wall -Wextra -O2 \
  build/PGLogger.o build/PGS.o build/pgs_service.o \
  -o build/pgs_service.exe \
  -lws2_32 -ladvapi32 -lwtsapi32 -luserenv

echo "[5/7] Building guard_example.exe..."
g++ -std=c++17 -Wall -Wextra -O2 -Iinclude examples/guard_example.cpp -o build/guard_example.exe -lws2_32

echo "[6/7] Building quick_start.exe..."
g++ -std=c++17 -Wall -Wextra -O2 -Iinclude examples/quick_start.cpp -o build/quick_start.exe -lws2_32

echo "[7/8] Building smoke_worker.exe..."
g++ -std=c++17 -Wall -Wextra -O2 -Iinclude examples/smoke_worker.cpp -o build/smoke_worker.exe -lws2_32

echo "[8/8] Building pgs_bless.exe..."
g++ -std=c++17 -Wall -Wextra -O2 -Iinclude tools/pgs_bless.cpp -o build/pgs_bless.exe -lws2_32

cp -f /mingw64/bin/libstdc++-6.dll build/
cp -f /mingw64/bin/libgcc_s_seh-1.dll build/
cp -f /mingw64/bin/libwinpthread-1.dll build/

echo
echo "Build completed:"
echo "- build/pgs_service.exe"
echo "- build/guard_example.exe"
echo "- build/quick_start.exe"
echo "- build/smoke_worker.exe"
echo "- build/pgs_bless.exe"
