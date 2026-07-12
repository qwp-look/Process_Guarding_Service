@echo off
setlocal enabledelayedexpansion

chcp 65001 >nul 2>&1
pushd "%~dp0.."

if not defined MINGW_ROOT set "MINGW_ROOT=C:\msys64\mingw64"
if not defined MINGW_BIN set "MINGW_BIN=%MINGW_ROOT%\bin"
if not defined CXX set "CXX=%MINGW_BIN%\g++.exe"
set "COMPILER=%CXX%"
set "PATH=%MINGW_BIN%;%PATH%"
set "INCLUDE_DIR=include"
set "BUILD_DIR=build"
set "CXXFLAGS=-std=c++17 -Wall -Wextra -O2 -DNTDDI_VERSION=0x06020000"

if not exist "%COMPILER%" (
    echo Compiler not found: %COMPILER%
    echo Set MINGW_ROOT, MINGW_BIN, or CXX to your MSYS2 MinGW toolchain path.
    popd
    exit /b 1
)

if not exist "%BUILD_DIR%" mkdir "%BUILD_DIR%"
if not exist "%BUILD_DIR%\tmp" mkdir "%BUILD_DIR%\tmp"
set "TMP=!CD!\%BUILD_DIR%\tmp"
set "TEMP=!TMP!"
set "TMPDIR=!TMP!"

echo [1/12] Compiling logger...
"%COMPILER%" %CXXFLAGS% -c src\common\PGLogger.cpp -I %INCLUDE_DIR% -o %BUILD_DIR%\PGLogger.o
if errorlevel 1 (
    echo Failed: src\common\PGLogger.cpp
    popd
    exit /b 1
)

echo [2/12] Compiling PGS core...
"%COMPILER%" %CXXFLAGS% -c src\service\PGS.cpp -I %INCLUDE_DIR% -o %BUILD_DIR%\PGS.o
if errorlevel 1 (
    echo Failed: src\service\PGS.cpp
    popd
    exit /b 1
)

REM Module system: ModuleManager is linked into pgs_service.exe.
echo [3/12] Compiling module manager...
"%COMPILER%" %CXXFLAGS% -c src\modules\ModuleManager.cpp -I %INCLUDE_DIR% -o %BUILD_DIR%\ModuleManager.o
if errorlevel 1 (
    echo Failed: src\modules\ModuleManager.cpp
    popd
    exit /b 1
)

echo [4/12] Compiling PGS protocol layer...
"%COMPILER%" %CXXFLAGS% -c src\service\PGSProtocol.cpp -I %INCLUDE_DIR% -o %BUILD_DIR%\PGSProtocol.o
if errorlevel 1 (
    echo Failed: src\service\PGSProtocol.cpp
    popd
    exit /b 1
)

echo [5/12] Compiling service host...
"%COMPILER%" %CXXFLAGS% -c src\service\pgs_service.cpp -I %INCLUDE_DIR% -o %BUILD_DIR%\pgs_service.o
if errorlevel 1 (
    echo Failed: src\service\pgs_service.cpp
    popd
    exit /b 1
)

echo [6/12] Linking pgs_service.exe...
"%COMPILER%" -o %BUILD_DIR%\pgs_service.exe %BUILD_DIR%\PGLogger.o %BUILD_DIR%\PGS.o %BUILD_DIR%\PGSProtocol.o %BUILD_DIR%\ModuleManager.o %BUILD_DIR%\pgs_service.o -lws2_32 -ladvapi32 -lwtsapi32 -luserenv -lbcrypt -lwintrust -lole32 -lshell32
if errorlevel 1 (
    echo Failed: link pgs_service.exe
    popd
    exit /b 1
)

echo [7/12] Building guard_example.exe...
"%COMPILER%" %CXXFLAGS% -o %BUILD_DIR%\guard_example.exe examples\guard_example.cpp -I %INCLUDE_DIR% -lws2_32 -ladvapi32 -lbcrypt
if errorlevel 1 (
    echo Failed: examples\guard_example.cpp
    popd
    exit /b 1
)

echo [8/12] Building quick_start.exe...
"%COMPILER%" %CXXFLAGS% -o %BUILD_DIR%\quick_start.exe examples\quick_start.cpp -I %INCLUDE_DIR% -lws2_32 -ladvapi32 -lbcrypt
if errorlevel 1 (
    echo Failed: examples\quick_start.cpp
    popd
    exit /b 1
)

echo [9/12] Building smoke_worker.exe...
"%COMPILER%" %CXXFLAGS% -o %BUILD_DIR%\smoke_worker.exe examples\smoke_worker.cpp -I %INCLUDE_DIR% -lws2_32
if errorlevel 1 (
    echo Failed: examples\smoke_worker.cpp
    popd
    exit /b 1
)

echo [10/12] Building pgs_bless.exe (links shared PGSClient)...
"%COMPILER%" %CXXFLAGS% -c src\common\PGSClient.cpp -I %INCLUDE_DIR% -o %BUILD_DIR%\PGSClient.o
if errorlevel 1 (
    echo Failed: src\common\PGSClient.cpp
    popd
    exit /b 1
)
"%COMPILER%" %CXXFLAGS% -o %BUILD_DIR%\pgs_bless.exe tools\pgs_bless.cpp %BUILD_DIR%\PGSClient.o -I %INCLUDE_DIR% -lws2_32 -ladvapi32 -lbcrypt
if errorlevel 1 (
    echo Failed: tools\pgs_bless.cpp
    popd
    exit /b 1
)

REM Schedule module: cron/once/interval scheduler (ABI v2, calls back into PGS).
echo [11/12] Building pgs_sched_module.dll...
if not exist "%BUILD_DIR%\modules\sched" mkdir "%BUILD_DIR%\modules\sched"
"%COMPILER%" %CXXFLAGS% -shared -o "%BUILD_DIR%\modules\sched\pgs_sched_module.dll" modules\sched\SchedCron.cpp modules\sched\pgs_sched_module.cpp -I %INCLUDE_DIR%
if errorlevel 1 (
    echo Failed: modules\sched\pgs_sched_module.cpp
    popd
    exit /b 1
)
copy /Y "%MINGW_BIN%\libstdc++-6.dll" "%BUILD_DIR%\modules\sched\libstdc++-6.dll" >nul 2>&1
copy /Y "%MINGW_BIN%\libgcc_s_seh-1.dll" "%BUILD_DIR%\modules\sched\libgcc_s_seh-1.dll" >nul 2>&1
copy /Y "%MINGW_BIN%\libwinpthread-1.dll" "%BUILD_DIR%\modules\sched\libwinpthread-1.dll" >nul 2>&1
copy /Y modules\sched\module.html "%BUILD_DIR%\modules\sched\module.html" >nul

REM PPL module: built as a separate DLL (-shared) into build\modules, then
REM Sirius.sys and the MinGW runtime DLLs are copied next to it so PGS can
REM auto-load the module and the module can load the driver at runtime.
echo [12/12] Building pgs_ppl_module.dll...
REM v3: ship a default allowlist that permits the bundled PPL and sched modules.
REM Operators add lines "name[|sha256|signed]" to <exe>\modules\modules.allow to approve more.
echo ppl> "%BUILD_DIR%\modules\modules.allow"
echo sched>> "%BUILD_DIR%\modules\modules.allow"
REM Per-folder module layout: build\modules\<name>\<name>.dll + module.html + assets.
REM The folder name MUST match the module PG_GetName() return value so the
REM Qt UI and `module call --name <folder>` resolve correctly.
if not exist "%BUILD_DIR%\modules\ppl" mkdir "%BUILD_DIR%\modules\ppl"
"%COMPILER%" %CXXFLAGS% -shared -o "%BUILD_DIR%\modules\ppl\pgs_ppl_module.dll" modules\ppl\pgs_ppl_module.cpp -I %INCLUDE_DIR% -ladvapi32
if errorlevel 1 (
    echo Failed: modules\ppl\pgs_ppl_module.cpp
    popd
    exit /b 1
)
copy /Y modules\ppl\Sirius.sys "%BUILD_DIR%\modules\ppl\Sirius.sys" >nul
copy /Y modules\ppl\module.html "%BUILD_DIR%\modules\ppl\module.html" >nul
REM MinGW runtime DLLs: copy into build\ and build\modules\ so the .exe and the
REM pgs_ppl_module.dll can run without MSYS2 in PATH.
copy /Y "%MINGW_BIN%\libstdc++-6.dll" "%BUILD_DIR%\libstdc++-6.dll" >nul 2>&1
copy /Y "%MINGW_BIN%\libgcc_s_seh-1.dll" "%BUILD_DIR%\libgcc_s_seh-1.dll" >nul 2>&1
copy /Y "%MINGW_BIN%\libwinpthread-1.dll" "%BUILD_DIR%\libwinpthread-1.dll" >nul 2>&1
copy /Y "%MINGW_BIN%\libstdc++-6.dll" "%BUILD_DIR%\modules\ppl\libstdc++-6.dll" >nul 2>&1
copy /Y "%MINGW_BIN%\libgcc_s_seh-1.dll" "%BUILD_DIR%\modules\ppl\libgcc_s_seh-1.dll" >nul 2>&1
copy /Y "%MINGW_BIN%\libwinpthread-1.dll" "%BUILD_DIR%\modules\ppl\libwinpthread-1.dll" >nul 2>&1

echo.
echo Build completed:
echo - %BUILD_DIR%\pgs_service.exe
echo - %BUILD_DIR%\guard_example.exe
echo - %BUILD_DIR%\quick_start.exe
echo - %BUILD_DIR%\smoke_worker.exe
echo - %BUILD_DIR%\pgs_bless.exe
echo - %BUILD_DIR%\modules\sched\pgs_sched_module.dll
echo - %BUILD_DIR%\modules\ppl\pgs_ppl_module.dll
echo - %BUILD_DIR%\modules\ppl\Sirius.sys
echo - %BUILD_DIR%\modules\ppl\module.html

popd
exit /b 0
