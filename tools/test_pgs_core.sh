#!/usr/bin/env bash
# MSYS2 MinGW64 entry point: build and run the pgs_core unit tests.
set -euo pipefail
export PATH="/mingw64/bin:/usr/bin:$PATH"
hash -r
mkdir -p build
g++ -std=c++17 -Wall -Wextra -O2 -Iinclude tests/test_pgs_core.cpp -o build/test_pgs_core.exe -lbcrypt
./build/test_pgs_core.exe