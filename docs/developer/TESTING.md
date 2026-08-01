# 测试与验证

## 基本原则

PGS 的默认开发环境是 MSYS2/MinGW64。任何构建、测试、smoke、Qt/Web/Cluster 验证命令，只要依赖 MinGW、CMake、bash、Qt runtime 或 MSYS2 工具，都必须在命令前显式设置环境变量。不要依赖当前终端已经把 `C:\msys64\mingw64\bin` 放进 `PATH`。

功能修改和文档修改要同步进行：

- 新增或改变命令、协议字段、模块能力、UI 入口时，同一轮更新用户/维护者/开发者文档中对应段落。
- 改变安全边界、默认开关、确认门槛、ACL、token、模块 trust/install 行为时，同步更新 `docs/SECURITY_HARDENING_BACKLOG.md` 和相关操作指南。
- 改变未完成项状态时，同步更新 `docs/UNFINISHED_FEATURES_BACKLOG.md` 或 `docs/REMAINING_UPGRADE_PLAN.md`，避免交接文档变成旧地图。
- 验证记录里写完整命令和环境变量前缀，尤其是 MSYS2/MinGW、Qt、PowerShell 脚本和 VM acceptance。

## 环境前缀

Windows `cmd` / `.bat`：

```bat
set MINGW_ROOT=C:\msys64\mingw64
set MINGW_BIN=%MINGW_ROOT%\bin
set MSYSTEM=MINGW64
set CHERE_INVOKING=1
set CXX=%MINGW_ROOT%\bin\g++.exe
set CMAKE=%MINGW_ROOT%\bin\cmake.exe
set MSYS2_BASH=C:\msys64\usr\bin\bash.exe
set PATH=%MINGW_BIN%;%PATH%
```

PowerShell：

```powershell
$env:MINGW_ROOT='C:\msys64\mingw64'
$env:MINGW_BIN="$env:MINGW_ROOT\bin"
$env:MSYSTEM='MINGW64'
$env:CHERE_INVOKING='1'
$env:CXX="$env:MINGW_BIN\g++.exe"
$env:CMAKE="$env:MINGW_BIN\cmake.exe"
$env:MSYS2_BASH='C:\msys64\usr\bin\bash.exe'
$env:PATH="$env:MINGW_BIN;$env:PATH"
```

MSYS2 bash：

```bash
export MINGW_ROOT=/mingw64
export MSYSTEM=MINGW64
export CHERE_INVOKING=1
export GXX=$MINGW_ROOT/bin/g++.exe
export CMAKE=$MINGW_ROOT/bin/cmake.exe
export PATH=$MINGW_ROOT/bin:$PATH
```

Qt/CMake 配置如果出现 `Cannot create temporary file` 或 `can't open ?cc*.s`，把 `TMP`、`TEMP`、`TMPDIR` 显式设到 Windows 用户临时目录再重跑，例如 PowerShell 中设为 `C:\Users\<user>\AppData\Local\Temp`，MSYS2 bash 中设为 `/c/Users/<user>/AppData/Local/Temp`。

## 日常验证

```bat
set MINGW_ROOT=C:\msys64\mingw64
set MINGW_BIN=%MINGW_ROOT%\bin
set CXX=%MINGW_ROOT%\bin\g++.exe
set CMAKE=%MINGW_ROOT%\bin\cmake.exe
set MSYS2_BASH=C:\msys64\usr\bin\bash.exe
set PATH=%MINGW_BIN%;%PATH%
tools\verify.bat
```

覆盖：

- 文件存在性检查。
- core / CLI / examples / bundled modules 构建。
- core、ModuleManager、Scheduler unit tests。
- console smoke。
- Qt 管理端构建。
- Web 管理端和 Cluster 面板构建。

## 单项测试

```bash
export MINGW_ROOT=/mingw64
export GXX=$MINGW_ROOT/bin/g++.exe
export CMAKE=$MINGW_ROOT/bin/cmake.exe
export PATH=$MINGW_ROOT/bin:$PATH
./tools/run_unit_tests.sh
./tools/test_core_units.sh
./tools/test_module_manager.sh
./tools/test_sched_cron.sh
```

## 协议契约

```powershell
$env:MINGW_ROOT='C:\msys64\mingw64'
$env:MINGW_BIN="$env:MINGW_ROOT\bin"
$env:CXX="$env:MINGW_BIN\g++.exe"
$env:CMAKE="$env:MINGW_BIN\cmake.exe"
$env:MSYS2_BASH='C:\msys64\usr\bin\bash.exe'
$env:PATH="$env:MINGW_BIN;$env:PATH"
powershell -NoProfile -ExecutionPolicy Bypass -File tools\protocol_contract.ps1 -Release build_verify
```

当前固定 `ping`、`version`、`stats`、`list --json` 的基础契约。更多命令契约可以继续扩展。

## Release smoke

```powershell
$env:MINGW_ROOT='C:\msys64\mingw64'
$env:MINGW_BIN="$env:MINGW_ROOT\bin"
$env:CXX="$env:MINGW_BIN\g++.exe"
$env:CMAKE="$env:MINGW_BIN\cmake.exe"
$env:PATH="$env:MINGW_BIN;$env:PATH"
powershell -NoProfile -ExecutionPolicy Bypass -File tools\release_smoke.ps1 -Release release -Fresh
```

验证便携 release 的核心 happy path，包含模块加载、PPL gate 和 guard 生命周期。

## 压力与长稳

```powershell
$env:MINGW_ROOT='C:\msys64\mingw64'
$env:MINGW_BIN="$env:MINGW_ROOT\bin"
$env:CXX="$env:MINGW_BIN\g++.exe"
$env:CMAKE="$env:MINGW_BIN\cmake.exe"
$env:PATH="$env:MINGW_BIN;$env:PATH"
powershell -NoProfile -ExecutionPolicy Bypass -File tools\pressure_pgs.ps1 -Release build_verify -Iterations 50
powershell -NoProfile -ExecutionPolicy Bypass -File tools\long_stability.ps1 -Release build_verify -Minutes 30
```

本轮已跑过短压测和 1 分钟长稳 smoke。正式 release 基线仍需在固定环境中沉淀。

## VM acceptance

```powershell
$env:MINGW_ROOT='C:\msys64\mingw64'
$env:MINGW_BIN="$env:MINGW_ROOT\bin"
$env:CXX="$env:MINGW_BIN\g++.exe"
$env:CMAKE="$env:MINGW_BIN\cmake.exe"
$env:PATH="$env:MINGW_BIN;$env:PATH"
powershell -NoProfile -ExecutionPolicy Bypass -File tools\vm_acceptance.ps1 -EnablePpl -RunWinApp
```

需要管理员 VM、安装器、真实服务权限和可选 WindowsApps 环境。该项没有纳入普通 verify。
