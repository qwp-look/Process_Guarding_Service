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
if not defined PGS_BUILD_DIR set "PGS_BUILD_DIR=build"
set "BUILD_DIR=%PGS_BUILD_DIR%"
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

echo [1/22] Compiling logger...
"%COMPILER%" %CXXFLAGS% -c src\common\PGLogger.cpp -I %INCLUDE_DIR% -o %BUILD_DIR%\PGLogger.o
if errorlevel 1 (
    echo Failed: src\common\PGLogger.cpp
    popd
    exit /b 1
)

echo [2/22] Compiling PGS core...
"%COMPILER%" %CXXFLAGS% -c src\service\PGS.cpp -I %INCLUDE_DIR% -o %BUILD_DIR%\PGS.o
if errorlevel 1 (
    echo Failed: src\service\PGS.cpp
    popd
    exit /b 1
)

REM Module system: ModuleManager is linked into pgs_service.exe.
echo [3/22] Compiling module manager...
"%COMPILER%" %CXXFLAGS% -c src\modules\ModuleManager.cpp -I %INCLUDE_DIR% -o %BUILD_DIR%\ModuleManager.o
if errorlevel 1 (
    echo Failed: src\modules\ModuleManager.cpp
    popd
    exit /b 1
)

echo [4/22] Compiling PGS protocol and module install handlers...
"%COMPILER%" %CXXFLAGS% -c src\service\PGSProtocol.cpp -I %INCLUDE_DIR% -o %BUILD_DIR%\PGSProtocol.o
if errorlevel 1 (
    echo Failed: src\service\PGSProtocol.cpp
    popd
    exit /b 1
)
"%COMPILER%" %CXXFLAGS% -c src\service\PGSModuleInstall.cpp -I %INCLUDE_DIR% -o %BUILD_DIR%\PGSModuleInstall.o
if errorlevel 1 (
    echo Failed: src\service\PGSModuleInstall.cpp
    popd
    exit /b 1
)

echo [5/22] Compiling service host...
"%COMPILER%" %CXXFLAGS% -c src\service\pgs_service.cpp -I %INCLUDE_DIR% -o %BUILD_DIR%\pgs_service.o
if errorlevel 1 (
    echo Failed: src\service\pgs_service.cpp
    popd
    exit /b 1
)

echo [6/22] Linking pgs_service.exe...
"%COMPILER%" -o %BUILD_DIR%\pgs_service.exe %BUILD_DIR%\PGLogger.o %BUILD_DIR%\PGS.o %BUILD_DIR%\PGSProtocol.o %BUILD_DIR%\PGSModuleInstall.o %BUILD_DIR%\ModuleManager.o %BUILD_DIR%\pgs_service.o -lws2_32 -lwinhttp -ladvapi32 -lwtsapi32 -luserenv -lbcrypt -lwintrust -lole32 -lshell32
if errorlevel 1 (
    echo Failed: link pgs_service.exe
    popd
    exit /b 1
)

echo [7/22] Building guard_example.exe...
"%COMPILER%" %CXXFLAGS% -o %BUILD_DIR%\guard_example.exe examples\guard_example.cpp -I %INCLUDE_DIR% -lws2_32 -ladvapi32 -lbcrypt
if errorlevel 1 (
    echo Failed: examples\guard_example.cpp
    popd
    exit /b 1
)

echo [8/22] Building quick_start.exe...
"%COMPILER%" %CXXFLAGS% -o %BUILD_DIR%\quick_start.exe examples\quick_start.cpp -I %INCLUDE_DIR% -lws2_32 -ladvapi32 -lbcrypt
if errorlevel 1 (
    echo Failed: examples\quick_start.cpp
    popd
    exit /b 1
)

echo [9/22] Building smoke_worker.exe...
"%COMPILER%" %CXXFLAGS% -o %BUILD_DIR%\smoke_worker.exe examples\smoke_worker.cpp -I %INCLUDE_DIR% -lws2_32
if errorlevel 1 (
    echo Failed: examples\smoke_worker.cpp
    popd
    exit /b 1
)

echo [10/22] Building pgs_bless.exe (links shared PGSClient)...
"%COMPILER%" %CXXFLAGS% -c src\common\PGSClient.cpp -I %INCLUDE_DIR% -o %BUILD_DIR%\PGSClient.o
if errorlevel 1 (
    echo Failed: src\common\PGSClient.cpp
    popd
    exit /b 1
)
"%COMPILER%" %CXXFLAGS% -c tools\PGSRegistryInstall.cpp -I %INCLUDE_DIR% -o %BUILD_DIR%\PGSRegistryInstall.o
if errorlevel 1 (
    echo Failed: tools\PGSRegistryInstall.cpp
    popd
    exit /b 1
)
"%COMPILER%" %CXXFLAGS% -o %BUILD_DIR%\pgs_bless.exe tools\pgs_bless.cpp %BUILD_DIR%\PGSRegistryInstall.o %BUILD_DIR%\PGSClient.o %BUILD_DIR%\ModuleManager.o %BUILD_DIR%\PGLogger.o -I %INCLUDE_DIR% -lws2_32 -lwinhttp -ladvapi32 -lbcrypt -lwintrust -lole32 -lshell32
if errorlevel 1 (
    echo Failed: tools\pgs_bless.cpp
    popd
    exit /b 1
)

REM Schedule module: cron/once/interval scheduler (ABI v2, calls back into PGS).
echo [11/22] Building pgs_sched_module.dll...
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
copy /Y modules\sched\module.manifest "%BUILD_DIR%\modules\sched\module.manifest" >nul
copy /Y modules\sched\module.manifest.json "%BUILD_DIR%\modules\sched\module.manifest.json" >nul

REM Health module: lightweight service status wrapper around stats/list/events.
echo [12/22] Building pgs_health_module.dll...
if not exist "%BUILD_DIR%\modules\health" mkdir "%BUILD_DIR%\modules\health"
"%COMPILER%" %CXXFLAGS% -shared -o "%BUILD_DIR%\modules\health\pgs_health_module.dll" modules\health\pgs_health_module.cpp -I %INCLUDE_DIR%
if errorlevel 1 (
    echo Failed: modules\health\pgs_health_module.cpp
    popd
    exit /b 1
)
copy /Y "%MINGW_BIN%\libstdc++-6.dll" "%BUILD_DIR%\modules\health\libstdc++-6.dll" >nul 2>&1
copy /Y "%MINGW_BIN%\libgcc_s_seh-1.dll" "%BUILD_DIR%\modules\health\libgcc_s_seh-1.dll" >nul 2>&1
copy /Y "%MINGW_BIN%\libwinpthread-1.dll" "%BUILD_DIR%\modules\health\libwinpthread-1.dll" >nul 2>&1
copy /Y modules\health\module.html "%BUILD_DIR%\modules\health\module.html" >nul
copy /Y modules\health\module.manifest "%BUILD_DIR%\modules\health\module.manifest" >nul
copy /Y modules\health\module.manifest.json "%BUILD_DIR%\modules\health\module.manifest.json" >nul

REM Profile module: named restart-policy profiles, persisted beside the module.
echo [13/22] Building pgs_profile_module.dll...
if not exist "%BUILD_DIR%\modules\profile" mkdir "%BUILD_DIR%\modules\profile"
"%COMPILER%" %CXXFLAGS% -shared -o "%BUILD_DIR%\modules\profile\pgs_profile_module.dll" modules\profile\pgs_profile_module.cpp -I %INCLUDE_DIR%
if errorlevel 1 (
    echo Failed: modules\profile\pgs_profile_module.cpp
    popd
    exit /b 1
)
copy /Y "%MINGW_BIN%\libstdc++-6.dll" "%BUILD_DIR%\modules\profile\libstdc++-6.dll" >nul 2>&1
copy /Y "%MINGW_BIN%\libgcc_s_seh-1.dll" "%BUILD_DIR%\modules\profile\libgcc_s_seh-1.dll" >nul 2>&1
copy /Y "%MINGW_BIN%\libwinpthread-1.dll" "%BUILD_DIR%\modules\profile\libwinpthread-1.dll" >nul 2>&1
copy /Y modules\profile\module.html "%BUILD_DIR%\modules\profile\module.html" >nul
copy /Y modules\profile\module.manifest "%BUILD_DIR%\modules\profile\module.manifest" >nul
copy /Y modules\profile\module.manifest.json "%BUILD_DIR%\modules\profile\module.manifest.json" >nul

REM Report module: base64 snapshots/backup exports from stats/list/events.
echo [14/22] Building pgs_report_module.dll...
if not exist "%BUILD_DIR%\modules\report" mkdir "%BUILD_DIR%\modules\report"
"%COMPILER%" %CXXFLAGS% -shared -o "%BUILD_DIR%\modules\report\pgs_report_module.dll" modules\report\pgs_report_module.cpp -I %INCLUDE_DIR%
if errorlevel 1 (
    echo Failed: modules\report\pgs_report_module.cpp
    popd
    exit /b 1
)
copy /Y "%MINGW_BIN%\libstdc++-6.dll" "%BUILD_DIR%\modules\report\libstdc++-6.dll" >nul 2>&1
copy /Y "%MINGW_BIN%\libgcc_s_seh-1.dll" "%BUILD_DIR%\modules\report\libgcc_s_seh-1.dll" >nul 2>&1
copy /Y "%MINGW_BIN%\libwinpthread-1.dll" "%BUILD_DIR%\modules\report\libwinpthread-1.dll" >nul 2>&1
copy /Y modules\report\module.html "%BUILD_DIR%\modules\report\module.html" >nul
copy /Y modules\report\module.manifest "%BUILD_DIR%\modules\report\module.manifest" >nul
copy /Y modules\report\module.manifest.json "%BUILD_DIR%\modules\report\module.manifest.json" >nul

REM Notify module: Windows-native Event Log and optional local popup notifications.
echo [15/22] Building pgs_notify_module.dll...
if not exist "%BUILD_DIR%\modules\notify" mkdir "%BUILD_DIR%\modules\notify"
"%COMPILER%" %CXXFLAGS% -shared -o "%BUILD_DIR%\modules\notify\pgs_notify_module.dll" modules\notify\pgs_notify_module.cpp -I %INCLUDE_DIR% -ladvapi32 -luser32
if errorlevel 1 (
    echo Failed: modules\notify\pgs_notify_module.cpp
    popd
    exit /b 1
)
copy /Y "%MINGW_BIN%\libstdc++-6.dll" "%BUILD_DIR%\modules\notify\libstdc++-6.dll" >nul 2>&1
copy /Y "%MINGW_BIN%\libgcc_s_seh-1.dll" "%BUILD_DIR%\modules\notify\libgcc_s_seh-1.dll" >nul 2>&1
copy /Y "%MINGW_BIN%\libwinpthread-1.dll" "%BUILD_DIR%\modules\notify\libwinpthread-1.dll" >nul 2>&1
copy /Y modules\notify\module.html "%BUILD_DIR%\modules\notify\module.html" >nul
copy /Y modules\notify\module.manifest "%BUILD_DIR%\modules\notify\module.manifest" >nul
copy /Y modules\notify\module.manifest.json "%BUILD_DIR%\modules\notify\module.manifest.json" >nul

REM Metrics module: local guard/service metrics in KV, JSON, and Prometheus text.
echo [16/22] Building pgs_metrics_module.dll...
if not exist "%BUILD_DIR%\modules\metrics" mkdir "%BUILD_DIR%\modules\metrics"
"%COMPILER%" %CXXFLAGS% -shared -o "%BUILD_DIR%\modules\metrics\pgs_metrics_module.dll" modules\metrics\pgs_metrics_module.cpp -I %INCLUDE_DIR%
if errorlevel 1 (
    echo Failed: modules\metrics\pgs_metrics_module.cpp
    popd
    exit /b 1
)
copy /Y "%MINGW_BIN%\libstdc++-6.dll" "%BUILD_DIR%\modules\metrics\libstdc++-6.dll" >nul 2>&1
copy /Y "%MINGW_BIN%\libgcc_s_seh-1.dll" "%BUILD_DIR%\modules\metrics\libgcc_s_seh-1.dll" >nul 2>&1
copy /Y "%MINGW_BIN%\libwinpthread-1.dll" "%BUILD_DIR%\modules\metrics\libwinpthread-1.dll" >nul 2>&1
copy /Y modules\metrics\module.html "%BUILD_DIR%\modules\metrics\module.html" >nul
copy /Y modules\metrics\module.manifest "%BUILD_DIR%\modules\metrics\module.manifest" >nul
copy /Y modules\metrics\module.manifest.json "%BUILD_DIR%\modules\metrics\module.manifest.json" >nul

REM Backup module: local ProgramData state snapshot and optional ArtifactStore output.
echo [17/22] Building pgs_backup_module.dll...
if not exist "%BUILD_DIR%\modules\backup" mkdir "%BUILD_DIR%\modules\backup"
"%COMPILER%" %CXXFLAGS% -shared -o "%BUILD_DIR%\modules\backup\pgs_backup_module.dll" modules\backup\pgs_backup_module.cpp -I %INCLUDE_DIR%
if errorlevel 1 (
    echo Failed: modules\backup\pgs_backup_module.cpp
    popd
    exit /b 1
)
copy /Y "%MINGW_BIN%\libstdc++-6.dll" "%BUILD_DIR%\modules\backup\libstdc++-6.dll" >nul 2>&1
copy /Y "%MINGW_BIN%\libgcc_s_seh-1.dll" "%BUILD_DIR%\modules\backup\libgcc_s_seh-1.dll" >nul 2>&1
copy /Y "%MINGW_BIN%\libwinpthread-1.dll" "%BUILD_DIR%\modules\backup\libwinpthread-1.dll" >nul 2>&1
copy /Y modules\backup\module.html "%BUILD_DIR%\modules\backup\module.html" >nul
copy /Y modules\backup\module.manifest "%BUILD_DIR%\modules\backup\module.manifest" >nul
copy /Y modules\backup\module.manifest.json "%BUILD_DIR%\modules\backup\module.manifest.json" >nul

REM Eventlog module: read-only local Windows Application Event Log queries.
echo [18/22] Building pgs_eventlog_module.dll...
if not exist "%BUILD_DIR%\modules\eventlog" mkdir "%BUILD_DIR%\modules\eventlog"
"%COMPILER%" %CXXFLAGS% -shared -o "%BUILD_DIR%\modules\eventlog\pgs_eventlog_module.dll" modules\eventlog\pgs_eventlog_module.cpp -I %INCLUDE_DIR% -ladvapi32
if errorlevel 1 (
    echo Failed: modules\eventlog\pgs_eventlog_module.cpp
    popd
    exit /b 1
)
copy /Y "%MINGW_BIN%\libstdc++-6.dll" "%BUILD_DIR%\modules\eventlog\libstdc++-6.dll" >nul 2>&1
copy /Y "%MINGW_BIN%\libgcc_s_seh-1.dll" "%BUILD_DIR%\modules\eventlog\libgcc_s_seh-1.dll" >nul 2>&1
copy /Y "%MINGW_BIN%\libwinpthread-1.dll" "%BUILD_DIR%\modules\eventlog\libwinpthread-1.dll" >nul 2>&1
copy /Y modules\eventlog\module.html "%BUILD_DIR%\modules\eventlog\module.html" >nul
copy /Y modules\eventlog\module.manifest "%BUILD_DIR%\modules\eventlog\module.manifest" >nul
copy /Y modules\eventlog\module.manifest.json "%BUILD_DIR%\modules\eventlog\module.manifest.json" >nul

REM Dump module: explicit local minidump collection into ArtifactStore.
echo [19/22] Building pgs_dump_module.dll...
if not exist "%BUILD_DIR%\modules\dump" mkdir "%BUILD_DIR%\modules\dump"
"%COMPILER%" %CXXFLAGS% -shared -o "%BUILD_DIR%\modules\dump\pgs_dump_module.dll" modules\dump\pgs_dump_module.cpp -I %INCLUDE_DIR% -ldbghelp
if errorlevel 1 (
    echo Failed: modules\dump\pgs_dump_module.cpp
    popd
    exit /b 1
)
copy /Y "%MINGW_BIN%\libstdc++-6.dll" "%BUILD_DIR%\modules\dump\libstdc++-6.dll" >nul 2>&1
copy /Y "%MINGW_BIN%\libgcc_s_seh-1.dll" "%BUILD_DIR%\modules\dump\libgcc_s_seh-1.dll" >nul 2>&1
copy /Y "%MINGW_BIN%\libwinpthread-1.dll" "%BUILD_DIR%\modules\dump\libwinpthread-1.dll" >nul 2>&1
copy /Y modules\dump\module.html "%BUILD_DIR%\modules\dump\module.html" >nul
copy /Y modules\dump\module.manifest "%BUILD_DIR%\modules\dump\module.manifest" >nul
copy /Y modules\dump\module.manifest.json "%BUILD_DIR%\modules\dump\module.manifest.json" >nul

REM Service guard module: local Windows SCM query/start/stop helper.
echo [20/22] Building pgs_service_guard_module.dll...
if not exist "%BUILD_DIR%\modules\service_guard" mkdir "%BUILD_DIR%\modules\service_guard"
"%COMPILER%" %CXXFLAGS% -shared -o "%BUILD_DIR%\modules\service_guard\pgs_service_guard_module.dll" modules\service_guard\pgs_service_guard_module.cpp -I %INCLUDE_DIR% -ladvapi32
if errorlevel 1 (
    echo Failed: modules\service_guard\pgs_service_guard_module.cpp
    popd
    exit /b 1
)
copy /Y "%MINGW_BIN%\libstdc++-6.dll" "%BUILD_DIR%\modules\service_guard\libstdc++-6.dll" >nul 2>&1
copy /Y "%MINGW_BIN%\libgcc_s_seh-1.dll" "%BUILD_DIR%\modules\service_guard\libgcc_s_seh-1.dll" >nul 2>&1
copy /Y "%MINGW_BIN%\libwinpthread-1.dll" "%BUILD_DIR%\modules\service_guard\libwinpthread-1.dll" >nul 2>&1
copy /Y modules\service_guard\module.html "%BUILD_DIR%\modules\service_guard\module.html" >nul
copy /Y modules\service_guard\module.manifest "%BUILD_DIR%\modules\service_guard\module.manifest" >nul
copy /Y modules\service_guard\module.manifest.json "%BUILD_DIR%\modules\service_guard\module.manifest.json" >nul

REM File watch module: demand-driven local file change detector.
echo [21/22] Building pgs_file_watch_module.dll...
if not exist "%BUILD_DIR%\modules\file_watch" mkdir "%BUILD_DIR%\modules\file_watch"
"%COMPILER%" %CXXFLAGS% -shared -o "%BUILD_DIR%\modules\file_watch\pgs_file_watch_module.dll" modules\file_watch\pgs_file_watch_module.cpp -I %INCLUDE_DIR% -lbcrypt
if errorlevel 1 (
    echo Failed: modules\file_watch\pgs_file_watch_module.cpp
    popd
    exit /b 1
)
copy /Y "%MINGW_BIN%\libstdc++-6.dll" "%BUILD_DIR%\modules\file_watch\libstdc++-6.dll" >nul 2>&1
copy /Y "%MINGW_BIN%\libgcc_s_seh-1.dll" "%BUILD_DIR%\modules\file_watch\libgcc_s_seh-1.dll" >nul 2>&1
copy /Y "%MINGW_BIN%\libwinpthread-1.dll" "%BUILD_DIR%\modules\file_watch\libwinpthread-1.dll" >nul 2>&1
copy /Y modules\file_watch\module.html "%BUILD_DIR%\modules\file_watch\module.html" >nul
copy /Y modules\file_watch\module.manifest "%BUILD_DIR%\modules\file_watch\module.manifest" >nul
copy /Y modules\file_watch\module.manifest.json "%BUILD_DIR%\modules\file_watch\module.manifest.json" >nul

REM Policy module: named guard-policy templates.
echo [22/22] Building pgs_policy_module.dll...
if not exist "%BUILD_DIR%\modules\policy" mkdir "%BUILD_DIR%\modules\policy"
"%COMPILER%" %CXXFLAGS% -shared -o "%BUILD_DIR%\modules\policy\pgs_policy_module.dll" modules\policy\pgs_policy_module.cpp -I %INCLUDE_DIR%
if errorlevel 1 (
    echo Failed: modules\policy\pgs_policy_module.cpp
    popd
    exit /b 1
)
copy /Y "%MINGW_BIN%\libstdc++-6.dll" "%BUILD_DIR%\modules\policy\libstdc++-6.dll" >nul 2>&1
copy /Y "%MINGW_BIN%\libgcc_s_seh-1.dll" "%BUILD_DIR%\modules\policy\libgcc_s_seh-1.dll" >nul 2>&1
copy /Y "%MINGW_BIN%\libwinpthread-1.dll" "%BUILD_DIR%\modules\policy\libwinpthread-1.dll" >nul 2>&1
copy /Y modules\policy\module.html "%BUILD_DIR%\modules\policy\module.html" >nul
copy /Y modules\policy\module.manifest "%BUILD_DIR%\modules\policy\module.manifest" >nul
copy /Y modules\policy\module.manifest.json "%BUILD_DIR%\modules\policy\module.manifest.json" >nul

powershell -NoProfile -ExecutionPolicy Bypass -File tools\write_modules_lock.ps1 -ModulesRoot "%BUILD_DIR%\modules" -Output "%BUILD_DIR%\modules\modules.lock" -GeneratedAt build
if errorlevel 1 (
    echo Failed: write modules.lock
    popd
    exit /b 1
)

echo.
echo Build completed:
echo - %BUILD_DIR%\pgs_service.exe
echo - %BUILD_DIR%\guard_example.exe
echo - %BUILD_DIR%\quick_start.exe
echo - %BUILD_DIR%\smoke_worker.exe
echo - %BUILD_DIR%\pgs_bless.exe
echo - %BUILD_DIR%\modules\sched\pgs_sched_module.dll
echo - %BUILD_DIR%\modules\health\pgs_health_module.dll
echo - %BUILD_DIR%\modules\profile\pgs_profile_module.dll
echo - %BUILD_DIR%\modules\report\pgs_report_module.dll
echo - %BUILD_DIR%\modules\notify\pgs_notify_module.dll
echo - %BUILD_DIR%\modules\metrics\pgs_metrics_module.dll
echo - %BUILD_DIR%\modules\backup\pgs_backup_module.dll
echo - %BUILD_DIR%\modules\eventlog\pgs_eventlog_module.dll
echo - %BUILD_DIR%\modules\dump\pgs_dump_module.dll
echo - %BUILD_DIR%\modules\service_guard\pgs_service_guard_module.dll
echo - %BUILD_DIR%\modules\file_watch\pgs_file_watch_module.dll
echo - %BUILD_DIR%\modules\policy\pgs_policy_module.dll

popd
exit /b 0
