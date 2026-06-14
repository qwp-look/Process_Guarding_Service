@echo off
setlocal enabledelayedexpansion

chcp 65001 >nul 2>&1
pushd "%~dp0.."

set "COMPILER=C:\msys64\mingw64\bin\g++.exe"
set "INCLUDE_DIR=include"
set "BUILD_DIR=build"
set "CXXFLAGS=-std=c++17 -Wall -Wextra -O2"

if not exist "%COMPILER%" (
    echo Compiler not found: %COMPILER%
    exit /b 1
)

if not exist "%BUILD_DIR%" mkdir "%BUILD_DIR%"
set "TMP=!CD!\%BUILD_DIR%"
set "TEMP=!CD!\%BUILD_DIR%"

echo [1/7] Compiling logger...
%COMPILER% %CXXFLAGS% -c src\common\PGLogger.cpp -I %INCLUDE_DIR% -o %BUILD_DIR%\PGLogger.o
if errorlevel 1 (
    echo Failed: src\common\PGLogger.cpp
    exit /b 1
)

echo [2/7] Compiling PGS core...
%COMPILER% %CXXFLAGS% -c src\service\PGS.cpp -I %INCLUDE_DIR% -o %BUILD_DIR%\PGS.o
if errorlevel 1 (
    echo Failed: src\service\PGS.cpp
    exit /b 1
)

echo [3/7] Compiling service host...
%COMPILER% %CXXFLAGS% -c src\service\pgs_service.cpp -I %INCLUDE_DIR% -o %BUILD_DIR%\pgs_service.o
if errorlevel 1 (
    echo Failed: src\service\pgs_service.cpp
    exit /b 1
)

echo [4/7] Linking pgs_service.exe...
%COMPILER% -o %BUILD_DIR%\pgs_service.exe %BUILD_DIR%\PGLogger.o %BUILD_DIR%\PGS.o %BUILD_DIR%\pgs_service.o -lws2_32 -ladvapi32 -lwtsapi32 -luserenv
if errorlevel 1 (
    echo Failed: link pgs_service.exe
    exit /b 1
)

echo [5/7] Building guard_example.exe...
%COMPILER% %CXXFLAGS% -o %BUILD_DIR%\guard_example.exe examples\guard_example.cpp -I %INCLUDE_DIR% -lws2_32
if errorlevel 1 (
    echo Failed: examples\guard_example.cpp
    exit /b 1
)

echo [6/7] Building quick_start.exe...
%COMPILER% %CXXFLAGS% -o %BUILD_DIR%\quick_start.exe examples\quick_start.cpp -I %INCLUDE_DIR% -lws2_32
if errorlevel 1 (
    echo Failed: examples\quick_start.cpp
    exit /b 1
)

echo [7/8] Building smoke_worker.exe...
%COMPILER% %CXXFLAGS% -o %BUILD_DIR%\smoke_worker.exe examples\smoke_worker.cpp -I %INCLUDE_DIR% -lws2_32
if errorlevel 1 (
    echo Failed: examples\smoke_worker.cpp
    exit /b 1
)

echo [8/8] Building pgs_bless.exe...
%COMPILER% %CXXFLAGS% -o %BUILD_DIR%\pgs_bless.exe tools\pgs_bless.cpp -I %INCLUDE_DIR% -lws2_32
if errorlevel 1 (
    echo Failed: tools\pgs_bless.cpp
    exit /b 1
)

echo.
echo Build completed:
echo - %BUILD_DIR%\pgs_service.exe
echo - %BUILD_DIR%\guard_example.exe
echo - %BUILD_DIR%\quick_start.exe
echo - %BUILD_DIR%\smoke_worker.exe
echo - %BUILD_DIR%\pgs_bless.exe

popd
exit /b 0
