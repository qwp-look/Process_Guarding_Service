@echo off
setlocal enabledelayedexpansion

chcp 65001 >nul 2>&1
pushd "%~dp0"

echo [1/2] Building PGS service and CLI tools...
call build_pgs.bat
if errorlevel 1 (
    echo Build failed in build_pgs.bat
    popd
    exit /b 1
)

echo [2/2] Qt GUI source is available under ..\qt\pgs_admin_qt
echo Build it manually with Qt/CMake environment:
echo   cmake -S ..\qt\pgs_admin_qt -B ..\build\pgs_admin_qt
echo   cmake --build ..\build\pgs_admin_qt --config Release

popd
exit /b 0
