@echo off
setlocal enabledelayedexpansion
chcp 65001 >nul 2>&1
pushd "%~dp0.."

REM ===========================================================================
REM  package_release.bat - One-shot, self-contained release packaging for PGS.
REM
REM  Builds the PGS core+CLI+modules, the Qt admin GUI, then assembles a
REM  freshly deleted release/ folder that runs on a CLEAN machine (no MSYS2 in
REM  PATH). Do not publish an existing release/ tree without rerunning this
REM  script; it is rebuilt from current build outputs each time:
REM    - pgs_service.exe / pgs_bless.exe / pgs_admin_qt.exe + examples
REM    - pgs_admin_web.exe + pgs_cluster_web.exe (browser consoles)
REM    - modules/{sched,health,report,notify,metrics,backup,eventlog,dump,service_guard,file_watch,policy}/ payloads
REM    - Qt6 DLLs + plugins via windeployqt6
REM    - MinGW third-party runtime DLLs that Qt6Core/Qt6Gui transitively depend
REM      on (windeployqt does NOT deploy these MSYS2 libs; without them the Qt
REM      app fails with 0xC0000135 STATUS_DLL_NOT_FOUND on a clean box).
REM
REM  Prerequisite: MSYS2 MinGW64 toolchain + Qt6. Override with MINGW_ROOT,
REM  MINGW_BIN, CMAKE, or CXX when the toolchain is not under C:\msys64.
REM ===========================================================================

if not defined MINGW_ROOT set "MINGW_ROOT=C:\msys64\mingw64"
if not defined MINGW_BIN set "MINGW_BIN=%MINGW_ROOT%\bin"
if not defined CMAKE set "CMAKE=%MINGW_BIN%\cmake.exe"
if not defined CXX set "CXX=%MINGW_BIN%\g++.exe"
set "MINGW=%MINGW_BIN%"
set "PATH=%MINGW_BIN%;%PATH%"
if not defined PGS_RELEASE_BUILD_DIR set "PGS_RELEASE_BUILD_DIR=build_release"
set "BUILD=%PGS_RELEASE_BUILD_DIR%"
set "PGS_BUILD_DIR=%BUILD%"
set "RELEASE=release"

if not exist "%CXX%" ( echo MinGW g++ not found: %CXX% & popd & exit /b 1 )
if not exist "%CMAKE%" ( echo CMake not found: %CMAKE% & popd & exit /b 1 )
if not exist "%MINGW%\windeployqt6.exe" ( echo windeployqt6 not found: %MINGW%\windeployqt6.exe & popd & exit /b 1 )

echo [1/6] Build PGS core + CLI + modules (build_pgs.bat)...
call tools\build_pgs.bat
if errorlevel 1 ( echo ERROR: build_pgs.bat failed & popd & exit /b 1 )

echo [2/6] Configure+build Qt admin app + web consoles...
REM     Builds the Qt GUI (pgs_admin_qt), admin web console, and cluster web console.
if not exist "%BUILD%\pgs_admin_qt\CMakeCache.txt" (
    "%CMAKE%" -S qt\pgs_admin_qt -B "%BUILD%\pgs_admin_qt" -G "MinGW Makefiles" -DCMAKE_BUILD_TYPE=Release -DCMAKE_PREFIX_PATH="%MINGW_ROOT%" -DCMAKE_CXX_COMPILER="%CXX%"
    if errorlevel 1 ( echo ERROR: cmake configure failed & popd & exit /b 1 )
)
"%CMAKE%" --build "%BUILD%\pgs_admin_qt" --config Release
if errorlevel 1 ( echo ERROR: Qt build failed & popd & exit /b 1 )

REM --- Web console (pgs_admin_web): Qt6 Core/Network + lightweight HTTP shim ---
"%CMAKE%" -S qt\pgs_admin_web -B "%BUILD%\pgs_admin_web" -G "MinGW Makefiles" -DCMAKE_BUILD_TYPE=Release -DCMAKE_PREFIX_PATH="%MINGW_ROOT%" -DCMAKE_CXX_COMPILER="%CXX%"
if errorlevel 1 ( echo ERROR: cmake configure web failed & popd & exit /b 1 )
if exist "%BUILD%\pgs_admin_web\CMakeFiles\pgs_admin_web.dir\objects.a" del /f /q "%BUILD%\pgs_admin_web\CMakeFiles\pgs_admin_web.dir\objects.a" >nul 2>&1
"%CMAKE%" --build "%BUILD%\pgs_admin_web" --config Release --clean-first
if errorlevel 1 ( echo ERROR: Qt web build failed & popd & exit /b 1 )

REM --- Cluster web dashboard (pgs_cluster_web): Qt6 Core/Network + lightweight HTTP shim ---
"%CMAKE%" -S qt\pgs_cluster_web -B "%BUILD%\pgs_cluster_web" -G "MinGW Makefiles" -DCMAKE_BUILD_TYPE=Release -DCMAKE_PREFIX_PATH="%MINGW_ROOT%" -DCMAKE_CXX_COMPILER="%CXX%"
if errorlevel 1 ( echo ERROR: cmake configure cluster web failed & popd & exit /b 1 )
if exist "%BUILD%\pgs_cluster_web\CMakeFiles\pgs_cluster_web.dir\objects.a" del /f /q "%BUILD%\pgs_cluster_web\CMakeFiles\pgs_cluster_web.dir\objects.a" >nul 2>&1
"%CMAKE%" --build "%BUILD%\pgs_cluster_web" --config Release --clean-first
if errorlevel 1 ( echo ERROR: Qt cluster web build failed & popd & exit /b 1 )

echo [3/6] Assemble release tree...
REM Always start from a clean release tree so installer and zip artifacts cannot
REM accidentally include stale binaries from a previous packaging run.
if exist "%RELEASE%" (
    rmdir /s /q "%RELEASE%"
    if exist "%RELEASE%" (
        echo ERROR: failed to remove existing release tree: %RELEASE%
        echo        Fix ACL/locks under %RELEASE% and rerun tools\package_release.bat.
        popd
        exit /b 1
    )
)
mkdir "%RELEASE%" "%RELEASE%\modules\sched" "%RELEASE%\modules\health" "%RELEASE%\modules\report" "%RELEASE%\modules\notify" "%RELEASE%\modules\metrics" "%RELEASE%\modules\backup" "%RELEASE%\modules\eventlog" "%RELEASE%\modules\dump" "%RELEASE%\modules\service_guard" "%RELEASE%\modules\file_watch" "%RELEASE%\modules\policy" "%RELEASE%\modules\winapp" "%RELEASE%\module_managers\official" "%RELEASE%\modules_staging" "%RELEASE%\examples" "%RELEASE%\docs" >nul 2>&1
copy /Y "%BUILD%\pgs_service.exe"     "%RELEASE%\" >nul
copy /Y "%BUILD%\pgs_bless.exe"       "%RELEASE%\" >nul
copy /Y "%BUILD%\pgs_admin_qt\pgs_admin_qt.exe" "%RELEASE%\" >nul
copy /Y "%BUILD%\pgs_admin_web\pgs_admin_web.exe" "%RELEASE%\" >nul
copy /Y "%BUILD%\pgs_cluster_web\pgs_cluster_web.exe" "%RELEASE%\" >nul
copy /Y "%BUILD%\guard_example.exe"   "%RELEASE%\examples\" >nul
copy /Y "%BUILD%\quick_start.exe"     "%RELEASE%\examples\" >nul
copy /Y "%BUILD%\smoke_worker.exe"    "%RELEASE%\examples\" >nul
REM MinGW runtime DLLs the example exes link (they live in examples\, not the release root, so windeployqt/closure above does not cover them).
copy /Y "%MINGW%\libgcc_s_seh-1.dll" "%RELEASE%\examples\" >nul
copy /Y "%MINGW%\libstdc++-6.dll"   "%RELEASE%\examples\" >nul
copy /Y "%MINGW%\libwinpthread-1.dll" "%RELEASE%\examples\" >nul
copy /Y "%BUILD%\modules\sched\pgs_sched_module.dll" "%RELEASE%\modules\sched\" >nul
copy /Y "%BUILD%\modules\sched\module.html"          "%RELEASE%\modules\sched\" >nul
copy /Y "%BUILD%\modules\sched\module.manifest.json" "%RELEASE%\modules\sched\" >nul
copy /Y "%BUILD%\modules\health\pgs_health_module.dll" "%RELEASE%\modules\health\" >nul
copy /Y "%BUILD%\modules\health\module.html"           "%RELEASE%\modules\health\" >nul
copy /Y "%BUILD%\modules\health\module.manifest.json" "%RELEASE%\modules\health\" >nul
copy /Y "%BUILD%\modules\report\pgs_report_module.dll" "%RELEASE%\modules\report\" >nul
copy /Y "%BUILD%\modules\report\module.html"           "%RELEASE%\modules\report\" >nul
copy /Y "%BUILD%\modules\report\module.manifest.json" "%RELEASE%\modules\report\" >nul
copy /Y "%BUILD%\modules\notify\pgs_notify_module.dll" "%RELEASE%\modules\notify\" >nul
copy /Y "%BUILD%\modules\notify\module.html"           "%RELEASE%\modules\notify\" >nul
copy /Y "%BUILD%\modules\notify\module.manifest.json" "%RELEASE%\modules\notify\" >nul
copy /Y "%BUILD%\modules\metrics\pgs_metrics_module.dll" "%RELEASE%\modules\metrics\" >nul
copy /Y "%BUILD%\modules\metrics\module.html"           "%RELEASE%\modules\metrics\" >nul
copy /Y "%BUILD%\modules\metrics\module.manifest.json" "%RELEASE%\modules\metrics\" >nul
copy /Y "%BUILD%\modules\backup\pgs_backup_module.dll" "%RELEASE%\modules\backup\" >nul
copy /Y "%BUILD%\modules\backup\module.html"           "%RELEASE%\modules\backup\" >nul
copy /Y "%BUILD%\modules\backup\module.manifest.json" "%RELEASE%\modules\backup\" >nul
copy /Y "%BUILD%\modules\eventlog\pgs_eventlog_module.dll" "%RELEASE%\modules\eventlog\" >nul
copy /Y "%BUILD%\modules\eventlog\module.html"           "%RELEASE%\modules\eventlog\" >nul
copy /Y "%BUILD%\modules\eventlog\module.manifest.json" "%RELEASE%\modules\eventlog\" >nul
for %%M in (dump service_guard file_watch policy winapp) do (
  copy /Y "%BUILD%\modules\%%M\pgs_%%M_module.dll" "%RELEASE%\modules\%%M\" >nul
  copy /Y "%BUILD%\modules\%%M\module.html" "%RELEASE%\modules\%%M\" >nul
  copy /Y "%BUILD%\modules\%%M\module.manifest.json" "%RELEASE%\modules\%%M\" >nul
)
copy /Y "%BUILD%\modules\modules.allow"        "%RELEASE%\modules\" >nul
copy /Y "%BUILD%\modules\modules.lock"         "%RELEASE%\modules\" >nul
copy /Y "module_managers\official\manager.manifest.json" "%RELEASE%\module_managers\official\" >nul
copy /Y "modules_staging\README.md" "%RELEASE%\modules_staging\" >nul
copy /Y "docs\INDEX.md"              "%RELEASE%\docs\" >nul
copy /Y "docs\MODULE_SYSTEM.md"       "%RELEASE%\docs\" >nul
copy /Y "docs\MODULE_ECOSYSTEM.md"    "%RELEASE%\docs\" >nul
copy /Y "docs\REMAINING_UPGRADE_PLAN.md" "%RELEASE%\docs\" >nul
copy /Y "docs\SERVICE_MODE_GUIDE.md"  "%RELEASE%\docs\" >nul
copy /Y "docs\TECHNICAL_ARCHITECTURE.md" "%RELEASE%\docs\" >nul
copy /Y "docs\ROBUSTNESS_AND_TESTING.md" "%RELEASE%\docs\" >nul
copy /Y "docs\SCHEDULER_MODULE.md"     "%RELEASE%\docs\" >nul
copy /Y "docs\REMOTE_GATEWAY.md"       "%RELEASE%\docs\" >nul
copy /Y "docs\CLUSTER_DASHBOARD.md"    "%RELEASE%\docs\" >nul
copy /Y "docs\GUARD_POLICIES.md"       "%RELEASE%\docs\" >nul
copy /Y "docs\SECURITY_HARDENING_BACKLOG.md" "%RELEASE%\docs\" >nul
copy /Y "docs\UNFINISHED_FEATURES_BACKLOG.md" "%RELEASE%\docs\" >nul
xcopy /E /I /Y "docs\user" "%RELEASE%\docs\user" >nul
xcopy /E /I /Y "docs\operator" "%RELEASE%\docs\operator" >nul
xcopy /E /I /Y "docs\developer" "%RELEASE%\docs\developer" >nul
if not exist "%RELEASE%\docs\schemas" mkdir "%RELEASE%\docs\schemas" >nul 2>&1
copy /Y "docs\schemas\*.json"          "%RELEASE%\docs\schemas\" >nul
copy /Y "LICENSE"                     "%RELEASE%\" >nul
copy /Y "NOTICE"                      "%RELEASE%\" >nul
copy /Y "README.md"                   "%RELEASE%\" >nul

echo [4/6] Deploy Qt6 DLLs + plugins (windeployqt6)...
"%MINGW%\windeployqt6.exe" --release --no-translations --no-system-d3d-compiler --no-opengl-sw "%RELEASE%\pgs_admin_qt.exe" >nul 2>&1
if errorlevel 1 ( echo ERROR: windeployqt6 failed for pgs_admin_qt.exe & popd & exit /b 1 )
REM pgs_admin_web still links Qt6HttpServer for response/header helpers; HTTP I/O is handled by the local QTcpServer shim.
"%MINGW%\windeployqt6.exe" --release --no-translations --no-system-d3d-compiler --no-opengl-sw "%RELEASE%\pgs_admin_web.exe" >nul 2>&1
if errorlevel 1 ( echo ERROR: windeployqt6 failed for pgs_admin_web.exe & popd & exit /b 1 )
REM pgs_cluster_web shares the same Qt runtime closure but has its own executable.
"%MINGW%\windeployqt6.exe" --release --no-translations --no-system-d3d-compiler --no-opengl-sw "%RELEASE%\pgs_cluster_web.exe" >nul 2>&1
if errorlevel 1 ( echo ERROR: windeployqt6 failed for pgs_cluster_web.exe & popd & exit /b 1 )

echo [5/6] Copy MinGW third-party runtime DLLs (Qt6Core/Gui/TLS transitive deps)...
REM windeployqt does not deploy these MSYS2 libs. This verified closure is what
REM makes pgs_admin_qt.exe run on a machine without mingw64/bin in PATH. The
REM ICU version (78) tracks the MSYS2 Qt6 build; bump if Qt is upgraded.
set "QT_MINGW_DEPS=libb2-1.dll libbrotlicommon.dll libbrotlidec.dll libbz2-1.dll libcrypto-3-x64.dll libdouble-conversion.dll libfreetype-6.dll libgcc_s_seh-1.dll libglib-2.0-0.dll libgraphite2.dll libharfbuzz-0.dll libiconv-2.dll libicudt78.dll libicuin78.dll libicuuc78.dll libintl-8.dll libmd4c.dll libpcre2-16-0.dll libpcre2-8-0.dll libpng16-16.dll libssl-3-x64.dll libstdc++-6.dll libwinpthread-1.dll libzstd.dll zlib1.dll"
for %%D in (%QT_MINGW_DEPS%) do copy /Y "%MINGW%\%%D" "%RELEASE%\%%D" >nul 2>&1
if not exist "%RELEASE%\tls" mkdir "%RELEASE%\tls" >nul 2>&1
copy /Y "%MINGW_ROOT%\share\qt6\plugins\tls\qopensslbackend.dll" "%RELEASE%\tls\" >nul 2>&1

echo [6/7] Validate required release artifacts...
dir "%RELEASE%\modules" >nul 2>&1
if errorlevel 1 ( echo ERROR: release\modules is missing or unreadable & popd & exit /b 1 )
for %%F in (
  pgs_service.exe
  pgs_bless.exe
  pgs_admin_qt.exe
  pgs_admin_web.exe
  pgs_cluster_web.exe
  modules\modules.allow
  modules\modules.lock
  modules\sched\pgs_sched_module.dll
  modules\sched\module.html
  modules\sched\module.manifest
  modules\sched\module.manifest.json
  modules\health\pgs_health_module.dll
  modules\health\module.html
  modules\health\module.manifest
  modules\health\module.manifest.json
  modules\report\pgs_report_module.dll
  modules\report\module.html
  modules\report\module.manifest
  modules\report\module.manifest.json
  modules\notify\pgs_notify_module.dll
  modules\notify\module.html
  modules\notify\module.manifest
  modules\notify\module.manifest.json
  modules\metrics\pgs_metrics_module.dll
  modules\metrics\module.html
  modules\metrics\module.manifest
  modules\metrics\module.manifest.json
  modules\backup\pgs_backup_module.dll
  modules\backup\module.html
  modules\backup\module.manifest
  modules\backup\module.manifest.json
  modules\eventlog\pgs_eventlog_module.dll
  modules\eventlog\module.html
  modules\eventlog\module.manifest
  modules\eventlog\module.manifest.json
  modules\dump\pgs_dump_module.dll
  modules\dump\module.html
  modules\dump\module.manifest
  modules\dump\module.manifest.json
  modules\service_guard\pgs_service_guard_module.dll
  modules\service_guard\module.html
  modules\service_guard\module.manifest
  modules\service_guard\module.manifest.json
  modules\file_watch\pgs_file_watch_module.dll
  modules\file_watch\module.html
  modules\file_watch\module.manifest
  modules\file_watch\module.manifest.json
  modules\policy\pgs_policy_module.dll
  modules\policy\module.html
  modules\policy\module.manifest.json
  modules\winapp\pgs_winapp_module.dll
  modules\winapp\module.html
  modules\winapp\module.manifest.json
  module_managers\official\manager.manifest.json
  modules_staging\README.md
  examples\smoke_worker.exe
  docs\INDEX.md
  docs\MODULE_SYSTEM.md
  docs\MODULE_ECOSYSTEM.md
  docs\REMAINING_UPGRADE_PLAN.md
  docs\SERVICE_MODE_GUIDE.md
  docs\TECHNICAL_ARCHITECTURE.md
  docs\ROBUSTNESS_AND_TESTING.md
  docs\SCHEDULER_MODULE.md
  docs\REMOTE_GATEWAY.md
  docs\CLUSTER_DASHBOARD.md
  docs\GUARD_POLICIES.md
  docs\SECURITY_HARDENING_BACKLOG.md
  docs\UNFINISHED_FEATURES_BACKLOG.md
  docs\user\QUICK_START.md
  docs\user\USER_GUIDE.md
  docs\user\FEATURES.md
  docs\user\FEATURE_GUARD.md
  docs\user\FEATURE_UI.md
  docs\user\FEATURE_SCHEDULER.md
  docs\user\FAQ.md
  docs\operator\OPERATOR_GUIDE.md
  docs\operator\RELEASE_GUIDE.md
  docs\operator\TROUBLESHOOTING.md
  docs\developer\ARCHITECTURE.md
  docs\developer\BUILD.md
  docs\developer\MODULE_SYSTEM.md
  docs\developer\PROTOCOL.md
  docs\developer\TESTING.md
  docs\schemas\manager.manifest.schema.json
  docs\schemas\module.manifest.schema.json
  docs\schemas\modules.lock.schema.json
  README.md
) do (
  if not exist "%RELEASE%\%%F" (
    echo ERROR: required release artifact missing: %RELEASE%\%%F
    popd
    exit /b 1
  )
)

echo [7/7] Done. Release layout:
echo   %RELEASE%\pgs_service.exe / pgs_bless.exe / pgs_admin_qt.exe / pgs_admin_web.exe / pgs_cluster_web.exe
echo   %RELEASE%\modules\sched\{pgs_sched_module.dll, module.html, module.manifest}
echo   %RELEASE%\modules\{health,report,notify,metrics,backup,eventlog,dump,service_guard,file_watch,policy,winapp}\{module dll, module.html, module.manifest}
echo   Qt6 + MinGW runtime DLLs (self-contained)

popd
exit /b 0
