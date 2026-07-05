@echo off
setlocal
chcp 65001 >nul 2>&1
pushd "%~dp0.."

set "COMPILER=C:\msys64\mingw64\bin\g++.exe"
set "PATH=C:\msys64\mingw64\bin;%PATH%"

if not exist "build" mkdir "build"

echo [test] Compiling pgs_core unit tests...
%COMPILER% -std=c++17 -Wall -Wextra -O2 -Iinclude tests\test_pgs_core.cpp -o build\test_pgs_core.exe -lbcrypt
if errorlevel 1 (
    echo Failed to compile tests
    popd
    exit /b 1
)

echo [test] Running pgs_core unit tests...
build\test_pgs_core.exe
set "RC=%errorlevel%"
popd
exit /b %RC%