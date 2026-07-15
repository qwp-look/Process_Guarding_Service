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

MSYS2 `.sh` 使用：

- `MINGW_ROOT`
- `GXX`
- `CMAKE`

## 完整验证构建

```bat
set MINGW_ROOT=C:\msys64\mingw64
set CXX=%MINGW_ROOT%\bin\g++.exe
set CMAKE=%MINGW_ROOT%\bin\cmake.exe
set MSYS2_BASH=C:\msys64\usr\bin\bash.exe
tools\verify.bat
```

`tools\verify.bat` 默认使用 `build_verify\`，避免污染普通 `build\` 或被旧生成物 ACL 影响。

MSYS2 入口：

```bash
export MINGW_ROOT=/mingw64
export GXX=$MINGW_ROOT/bin/g++.exe
export CMAKE=$MINGW_ROOT/bin/cmake.exe
./tools/verify_pgs.sh
```

## Core/CLI/modules

```bat
tools\build_pgs.bat
```

```bash
./tools/build_pgs.sh
```

可用 `PGS_BUILD_DIR` 指定输出目录：

```bat
set PGS_BUILD_DIR=build_custom
tools\build_pgs.bat
```

## Qt/Web/Cluster

Web/Cluster：

```bash
./tools/build_qt_web.sh
```

Qt 桌面端可用：

```bash
./tools/build_qt_admin.sh
```

完整 release 打包见 [发布与打包指南](../operator/RELEASE_GUIDE.md)。
