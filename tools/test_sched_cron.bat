@echo off
setlocal
chcp 65001 >nul 2>&1
pushd "%~dp0.."

if not defined MINGW_ROOT set "MINGW_ROOT=C:\msys64\mingw64"
if not defined MINGW_BIN set "MINGW_BIN=%MINGW_ROOT%\bin"
if not defined CXX set "CXX=%MINGW_BIN%\g++.exe"
set "PATH=%MINGW_BIN%;%PATH%"

if not exist "build" mkdir "build"

echo [unit:sched] Compiling tests\test_sched_cron.cpp...
"%CXX%" -std=c++17 -Wall -Wextra -O2 -Iinclude -Imodules\sched tests\test_sched_cron.cpp modules\sched\SchedCron.cpp -o build\test_sched_cron.exe
if errorlevel 1 (
    echo Failed to compile sched cron tests
    popd
    exit /b 1
)

echo [unit:sched] Running...
build\test_sched_cron.exe
set "RC=%errorlevel%"
popd
exit /b %RC%
