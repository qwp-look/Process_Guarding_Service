# 构建指南

PGS 推荐使用 MSYS2 MinGW64 工具链。Windows `.bat` 和 MSYS2 `.sh` 脚本都保留，但变量名略有差异。

## 工具链

默认路径：

```text
C:\msys64\mingw64
C:\msys64\usr\bin\bash.exe
```

Windows `.bat` 使用：

- `MINGW_ROOT`
- `MINGW_BIN`
- `CXX`
- `CMAKE`
- `MSYS2_BASH`

MSYS2 `.sh` 使用：

- `MINGW_ROOT`
- `GXX`
- `CMAKE`

## MSYS2 环境约定

本项目后续默认按 MSYS2/MinGW64 环境执行构建、测试和本地验证。调用任何依赖 MinGW、CMake、bash、Qt runtime 或 MSYS2 shell 的程序时，都必须显式携带环境变量，不依赖当前终端 `PATH` 的偶然状态。

Windows `cmd` / `.bat` 入口推荐先设置：

```bat
set MINGW_ROOT=C:\msys64\mingw64
set MINGW_BIN=%MINGW_ROOT%\bin
set CXX=%MINGW_ROOT%\bin\g++.exe
set CMAKE=%MINGW_ROOT%\bin\cmake.exe
set MSYS2_BASH=C:\msys64\usr\bin\bash.exe
set PATH=%MINGW_BIN%;%PATH%
```

PowerShell 入口推荐在同一命令中设置环境并调用脚本，避免跨终端丢失：

```powershell
$env:MINGW_ROOT='C:\msys64\mingw64'
$env:MINGW_BIN="$env:MINGW_ROOT\bin"
$env:CXX="$env:MINGW_BIN\g++.exe"
$env:CMAKE="$env:MINGW_BIN\cmake.exe"
$env:MSYS2_BASH='C:\msys64\usr\bin\bash.exe'
$env:PATH="$env:MINGW_BIN;$env:PATH"
```

MSYS2 bash 入口推荐：

```bash
export MINGW_ROOT=/mingw64
export GXX=$MINGW_ROOT/bin/g++.exe
export CMAKE=$MINGW_ROOT/bin/cmake.exe
export PATH=$MINGW_ROOT/bin:$PATH
```

新增脚本、CI 步骤、文档示例和人工验证记录都应保留这些显式环境变量。后续修改功能时，如果验证命令依赖 MSYS2，也要在提交说明或交接文档中写出完整环境前缀。

## 完整验证构建

```bat
set MINGW_ROOT=C:\msys64\mingw64
set MINGW_BIN=%MINGW_ROOT%\bin
set CXX=%MINGW_ROOT%\bin\g++.exe
set CMAKE=%MINGW_ROOT%\bin\cmake.exe
set MSYS2_BASH=C:\msys64\usr\bin\bash.exe
set PATH=%MINGW_BIN%;%PATH%
tools\verify.bat
```

`tools\verify.bat` 默认使用 `build_verify\`，避免污染普通 `build\` 或被旧生成物 ACL 影响。

MSYS2 入口：

```bash
export MINGW_ROOT=/mingw64
export GXX=$MINGW_ROOT/bin/g++.exe
export CMAKE=$MINGW_ROOT/bin/cmake.exe
export PATH=$MINGW_ROOT/bin:$PATH
./tools/verify_pgs.sh
```

## Core/CLI/modules

```bat
set MINGW_ROOT=C:\msys64\mingw64
set MINGW_BIN=%MINGW_ROOT%\bin
set CXX=%MINGW_ROOT%\bin\g++.exe
set CMAKE=%MINGW_ROOT%\bin\cmake.exe
set PATH=%MINGW_BIN%;%PATH%
tools\build_pgs.bat
```

```bash
export MINGW_ROOT=/mingw64
export GXX=$MINGW_ROOT/bin/g++.exe
export CMAKE=$MINGW_ROOT/bin/cmake.exe
export PATH=$MINGW_ROOT/bin:$PATH
./tools/build_pgs.sh
```

可用 `PGS_BUILD_DIR` 指定输出目录：

```bat
set MINGW_ROOT=C:\msys64\mingw64
set MINGW_BIN=%MINGW_ROOT%\bin
set CXX=%MINGW_ROOT%\bin\g++.exe
set CMAKE=%MINGW_ROOT%\bin\cmake.exe
set PATH=%MINGW_BIN%;%PATH%
set PGS_BUILD_DIR=build_custom
tools\build_pgs.bat
```

## Qt/Web/Cluster

Web/Cluster：

```bash
export MINGW_ROOT=/mingw64
export GXX=$MINGW_ROOT/bin/g++.exe
export CMAKE=$MINGW_ROOT/bin/cmake.exe
export PATH=$MINGW_ROOT/bin:$PATH
./tools/build_qt_web.sh
```

Qt 桌面端可用：

```bash
export MINGW_ROOT=/mingw64
export GXX=$MINGW_ROOT/bin/g++.exe
export CMAKE=$MINGW_ROOT/bin/cmake.exe
export PATH=$MINGW_ROOT/bin:$PATH
./tools/build_qt_admin.sh
```

完整 release 打包见 [发布与打包指南](../operator/RELEASE_GUIDE.md)。
