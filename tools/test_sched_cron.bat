@echo off
setlocal
chcp 65001 >nul 2>&1
pushd "%~dp0.."

set "COMPILER=C:\msys64\mingw64\bin\g++.exe"
set "PATH=C:\msys64\mingw64\bin;%PATH%"

if not exist "build" mkdir "build"

echo [unit:sched] Compiling tests\test_sched_cron.cpp...
%COMPILER% -std=c++17 -Wall -Wextra -O2 -Iinclude -Imodules\sched tests\test_sched_cron.cpp modules\sched\SchedCron.cpp -o build\test_sched_cron.exe
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
