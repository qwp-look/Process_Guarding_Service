@echo off
setlocal
chcp 65001 >nul 2>&1
pushd "%~dp0.."

set "COMPILER=C:\msys64\mingw64\bin\g++.exe"
set "PATH=C:\msys64\mingw64\bin;%PATH%"

if not exist "build" mkdir "build"

echo [unit:core] Compiling tests\test_pgs_core.cpp...
%COMPILER% -std=c++17 -Wall -Wextra -O2 -Iinclude tests\test_pgs_core.cpp -o build\test_pgs_core.exe -lbcrypt
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
