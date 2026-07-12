@echo off
setlocal
chcp 65001 >nul 2>&1
pushd "%~dp0.."

if not defined MINGW_ROOT set "MINGW_ROOT=C:\msys64\mingw64"
if not defined MINGW_BIN set "MINGW_BIN=%MINGW_ROOT%\bin"
if not defined CXX set "CXX=%MINGW_BIN%\g++.exe"
set "PATH=%MINGW_BIN%;%PATH%"

if not exist "build" mkdir "build"

echo [unit:core] Compiling tests\test_pgs_core.cpp...
"%CXX%" -std=c++17 -Wall -Wextra -O2 -DPGS_ENABLE_TEST_HOOKS -Iinclude tests\test_pgs_core.cpp modules\sched\pgs_sched_module.cpp modules\ppl\pgs_ppl_module.cpp -o build\test_pgs_core.exe -lbcrypt
if errorlevel 1 (
    echo Failed to compile core unit tests
    popd
    exit /b 1
)

echo [unit:core] Running...
build\test_pgs_core.exe
set "RC=%errorlevel%"
popd
exit /b %RC%
