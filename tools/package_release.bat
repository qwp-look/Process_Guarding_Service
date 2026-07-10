@echo off
setlocal enabledelayedexpansion
chcp 65001 >nul 2>&1
pushd "%~dp0.."

REM ===========================================================================
REM  package_release.bat - One-shot, self-contained release packaging for PGS.
REM
REM  Builds the PGS core+CLI+PPL module, the Qt admin GUI, then assembles a
REM  release/ folder that runs on a CLEAN machine (no MSYS2 in PATH):
REM    - pgs_service.exe / pgs_bless.exe / pgs_admin_qt.exe + examples
REM    - pgs_admin_web.exe (web console, shares Qt runtime with pgs_admin_qt)
REM    - modules/ppl/{pgs_ppl_module.dll, Sirius.sys, module.html}  (per-folder)
REM    - Qt6 DLLs + plugins via windeployqt6
REM    - MinGW third-party runtime DLLs that Qt6Core/Qt6Gui transitively depend
REM      on (windeployqt does NOT deploy these MSYS2 libs; without them the Qt
REM      app fails with 0xC0000135 STATUS_DLL_NOT_FOUND on a clean box).
REM
REM  Prerequisite: MSYS2 MinGW64 toolchain + Qt6 at C:\msys64\mingw64.
REM ===========================================================================

set "MINGW=C:\msys64\mingw64\bin"
set "PATH=%MINGW%;%PATH%"
set "BUILD=build"
set "RELEASE=release"

if not exist "%MINGW%\g++.exe" ( echo MinGW g++ not found: %MINGW% & popd & exit /b 1 )

echo [1/6] Build PGS core + CLI + PPL module (build_pgs.bat)...
call tools\build_pgs.bat
if errorlevel 1 ( echo ERROR: build_pgs.bat failed & popd & exit /b 1 )

echo [2/6] Configure+build Qt admin app...
REM     Builds both the Qt GUI (pgs_admin_qt) and the web console (pgs_admin_web).
if not exist "%BUILD%\pgs_admin_qt\CMakeCache.txt" (
    cmake -S qt\pgs_admin_qt -B "%BUILD%\pgs_admin_qt" -G Ninja -DCMAKE_BUILD_TYPE=Release
    if errorlevel 1 ( echo ERROR: cmake configure failed & popd & exit /b 1 )
)
cmake --build "%BUILD%\pgs_admin_qt" --config Release
if errorlevel 1 ( echo ERROR: Qt build failed & popd & exit /b 1 )

REM --- Web console (pgs_admin_web): Qt6 Core/Network/HttpServer ---
if not exist "%BUILD%\pgs_admin_web\CMakeCache.txt" (
    cmake -S qt\pgs_admin_web -B "%BUILD%\pgs_admin_web" -G Ninja -DCMAKE_BUILD_TYPE=Release
    if errorlevel 1 ( echo ERROR: cmake configure web failed & popd & exit /b 1 )
)
cmake --build "%BUILD%\pgs_admin_web" --config Release
if errorlevel 1 ( echo ERROR: Qt web build failed & popd & exit /b 1 )

echo [3/6] Assemble release tree...
if exist "%RELEASE%" rmdir /s /q "%RELEASE%"
mkdir "%RELEASE%" "%RELEASE%\modules\ppl" "%RELEASE%\modules\sched" "%RELEASE%\examples" "%RELEASE%\docs" >nul 2>&1
copy /Y "%BUILD%\pgs_service.exe"     "%RELEASE%\" >nul
copy /Y "%BUILD%\pgs_bless.exe"       "%RELEASE%\" >nul
copy /Y "%BUILD%\pgs_admin_qt\pgs_admin_qt.exe" "%RELEASE%\" >nul
copy /Y "%BUILD%\pgs_admin_web\pgs_admin_web.exe" "%RELEASE%\" >nul
copy /Y "%BUILD%\guard_example.exe"   "%RELEASE%\examples\" >nul
copy /Y "%BUILD%\quick_start.exe"     "%RELEASE%\examples\" >nul
copy /Y "%BUILD%\smoke_worker.exe"    "%RELEASE%\examples\" >nul
REM MinGW runtime DLLs the example exes link (they live in examples\, not the release root, so windeployqt/closure above does not cover them).
copy /Y "%MINGW%\libgcc_s_seh-1.dll" "%RELEASE%\examples\" >nul
copy /Y "%MINGW%\libstdc++-6.dll"   "%RELEASE%\examples\" >nul
copy /Y "%MINGW%\libwinpthread-1.dll" "%RELEASE%\examples\" >nul
copy /Y "%BUILD%\modules\ppl\pgs_ppl_module.dll" "%RELEASE%\modules\ppl\" >nul
copy /Y "%BUILD%\modules\ppl\Sirius.sys"         "%RELEASE%\modules\ppl\" >nul
copy /Y "%BUILD%\modules\ppl\module.html"        "%RELEASE%\modules\ppl\" >nul
copy /Y "%BUILD%\modules\sched\pgs_sched_module.dll" "%RELEASE%\modules\sched\" >nul
copy /Y "%BUILD%\modules\sched\module.html"          "%RELEASE%\modules\sched\" >nul
copy /Y "%BUILD%\modules\modules.allow"        "%RELEASE%\modules\" >nul
copy /Y "docs\MODULE_SYSTEM.md"       "%RELEASE%\docs\" >nul
copy /Y "docs\TECHNICAL_ARCHITECTURE.md" "%RELEASE%\docs\" >nul
copy /Y "docs\SCHEDULER_MODULE.md"     "%RELEASE%\docs\" >nul
copy /Y "docs\REMOTE_GATEWAY.md"       "%RELEASE%\docs\" >nul
copy /Y "docs\CLUSTER_DASHBOARD.md"    "%RELEASE%\docs\" >nul
copy /Y "LICENSE"                     "%RELEASE%\" >nul
copy /Y "LICENSE.ThirdParty.StarlightGUI.txt" "%RELEASE%\" >nul
copy /Y "NOTICE"                      "%RELEASE%\" >nul
copy /Y "README.md"                   "%RELEASE%\" >nul

echo [4/6] Deploy Qt6 DLLs + plugins (windeployqt6)...
"%MINGW%\windeployqt6.exe" --release --no-translations --no-system-d3d-compiler --no-opengl-sw "%RELEASE%\pgs_admin_qt.exe" >nul 2>&1
REM pgs_admin_web pulls Qt6HttpServer (+transitive Qt6WebSockets) into the shared release tree.
"%MINGW%\windeployqt6.exe" --release --no-translations --no-system-d3d-compiler --no-opengl-sw "%RELEASE%\pgs_admin_web.exe" >nul 2>&1
if errorlevel 1 ( echo WARNING: windeployqt6 reported errors )

echo [5/6] Copy MinGW third-party runtime DLLs (Qt6Core/Gui transitive deps)...
REM windeployqt does not deploy these MSYS2 libs. This verified closure is what
REM makes pgs_admin_qt.exe run on a machine without mingw64/bin in PATH. The
REM ICU version (78) tracks the MSYS2 Qt6 build; bump if Qt is upgraded.
set "QT_MINGW_DEPS=libb2-1.dll libbrotlicommon.dll libbrotlidec.dll libbz2-1.dll libdouble-conversion.dll libfreetype-6.dll libgcc_s_seh-1.dll libglib-2.0-0.dll libgraphite2.dll libharfbuzz-0.dll libiconv-2.dll libicudt78.dll libicuin78.dll libicuuc78.dll libintl-8.dll libmd4c.dll libpcre2-16-0.dll libpcre2-8-0.dll libpng16-16.dll libstdc++-6.dll libwinpthread-1.dll libzstd.dll zlib1.dll"
for %%D in (%QT_MINGW_DEPS%) do copy /Y "%MINGW%\%%D" "%RELEASE%\%%D" >nul 2>&1

echo [6/6] Done. Release layout:
echo   %RELEASE%\pgs_service.exe / pgs_bless.exe / pgs_admin_qt.exe / pgs_admin_web.exe
echo   %RELEASE%\modules\ppl\{pgs_ppl_module.dll, Sirius.sys, module.html}
echo   %RELEASE%\modules\sched\{pgs_sched_module.dll, module.html}
echo   Qt6 + MinGW runtime DLLs (self-contained)

popd
exit /b 0
