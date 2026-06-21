@echo off
setlocal enabledelayedexpansion

chcp 65001 >nul 2>&1
pushd "%~dp0.."

set "COMPILER=C:\msys64\mingw64\bin\g++.exe"
set "PATH=C:\msys64\mingw64\bin;%PATH%"
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
REM Module system: ModuleManager is linked into pgs_service.exe.
echo [2.5/9] Compiling module manager...
%COMPILER% %CXXFLAGS% -c src\modules\ModuleManager.cpp -I %INCLUDE_DIR% -o %BUILD_DIR%\ModuleManager.o
if errorlevel 1 (
    echo Failed: src\modules\ModuleManager.cpp
    exit /b 1
)

echo [3/7] Compiling service host...
%COMPILER% %CXXFLAGS% -c src\service\pgs_service.cpp -I %INCLUDE_DIR% -o %BUILD_DIR%\pgs_service.o
if errorlevel 1 (
    echo Failed: src\service\pgs_service.cpp
    exit /b 1
)

echo [4/7] Linking pgs_service.exe...
%COMPILER% -o %BUILD_DIR%\pgs_service.exe %BUILD_DIR%\PGLogger.o %BUILD_DIR%\PGS.o %BUILD_DIR%\ModuleManager.o %BUILD_DIR%\pgs_service.o -lws2_32 -ladvapi32 -lwtsapi32 -luserenv -lbcrypt
if errorlevel 1 (
    echo Failed: link pgs_service.exe
    exit /b 1
)

echo [5/7] Building guard_example.exe...
%COMPILER% %CXXFLAGS% -o %BUILD_DIR%\guard_example.exe examples\guard_example.cpp -I %INCLUDE_DIR% -lws2_32 -ladvapi32 -lbcrypt
if errorlevel 1 (
    echo Failed: examples\guard_example.cpp
    exit /b 1
)

echo [6/7] Building quick_start.exe...
%COMPILER% %CXXFLAGS% -o %BUILD_DIR%\quick_start.exe examples\quick_start.cpp -I %INCLUDE_DIR% -lws2_32 -ladvapi32 -lbcrypt
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
%COMPILER% %CXXFLAGS% -o %BUILD_DIR%\pgs_bless.exe tools\pgs_bless.cpp -I %INCLUDE_DIR% -lws2_32 -ladvapi32 -lbcrypt
if errorlevel 1 (
    echo Failed: tools\pgs_bless.cpp
    exit /b 1
)

REM PPL module: built as a separate DLL (-shared) into build\modules, then
REM Sirius.sys and the MinGW runtime DLLs are copied next to it so PGS can
REM auto-load the module and the module can load the driver at runtime.
echo [9/9] Building pgs_ppl_module.dll...
REM Per-folder module layout: build\modules\<name>\<name>.dll + module.html + assets.
REM The folder name MUST match the module PG_GetName() return value so the
REM Qt UI and `module call --name <folder>` resolve correctly.
if not exist "%BUILD_DIR%\modules\ppl" mkdir "%BUILD_DIR%\modules\ppl"
%COMPILER% %CXXFLAGS% -shared -o "%BUILD_DIR%\modules\ppl\pgs_ppl_module.dll" modules\ppl\pgs_ppl_module.cpp -I %INCLUDE_DIR% -ladvapi32
if errorlevel 1 (
    echo Failed: modules\ppl\pgs_ppl_module.cpp
    exit /b 1
)
copy /Y modules\ppl\Sirius.sys "%BUILD_DIR%\modules\ppl\Sirius.sys" >nul
copy /Y modules\ppl\module.html "%BUILD_DIR%\modules\ppl\module.html" >nul
REM MinGW runtime DLLs: copy into build\ and build\modules\ so the .exe and the
REM pgs_ppl_module.dll can run without MSYS2 in PATH.
copy /Y "C:\msys64\mingw64\bin\libstdc++-6.dll" "%BUILD_DIR%\libstdc++-6.dll" >nul 2>&1
copy /Y "C:\msys64\mingw64\bin\libgcc_s_seh-1.dll" "%BUILD_DIR%\libgcc_s_seh-1.dll" >nul 2>&1
copy /Y "C:\msys64\mingw64\bin\libwinpthread-1.dll" "%BUILD_DIR%\libwinpthread-1.dll" >nul 2>&1
copy /Y "%BUILD_DIR%\libstdc++-6.dll" "%BUILD_DIR%\modules\ppl\libstdc++-6.dll" >nul 2>&1
copy /Y "%BUILD_DIR%\libgcc_s_seh-1.dll" "%BUILD_DIR%\modules\ppl\libgcc_s_seh-1.dll" >nul 2>&1
copy /Y "%BUILD_DIR%\libwinpthread-1.dll" "%BUILD_DIR%\modules\ppl\libwinpthread-1.dll" >nul 2>&1

echo.
echo Build completed:
echo - %BUILD_DIR%\pgs_service.exe
echo - %BUILD_DIR%\guard_example.exe
echo - %BUILD_DIR%\quick_start.exe
echo - %BUILD_DIR%\smoke_worker.exe
echo - %BUILD_DIR%\pgs_bless.exe
echo - %BUILD_DIR%\modules\ppl\pgs_ppl_module.dll
echo - %BUILD_DIR%\modules\ppl\Sirius.sys
echo - %BUILD_DIR%\modules\ppl\module.html

popd
exit /b 0
