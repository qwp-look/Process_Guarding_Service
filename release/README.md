# Process_Guarding_Service

Process_Guarding_Service (PGS) 是一个 Windows 进程守护工具，用来把重要程序交给后台服务持续看护：目标进程异常退出时自动拉起，达到重启上限时停止重启，服务自身重启后还能恢复之前的守护列表。

这个项目由 qwp-look 和 AI 一起开发。它适合需要长期运行小工具、后台程序、业务客户端、监控脚本，或者需要一个本机/局域网可管理的 Windows 守护服务的场景。

## 它解决什么问题

- 程序崩溃后无人值守恢复。
- Windows 服务重启后恢复守护目标和 token。
- 通过 Qt 图形界面、命令行或 Web 页面查看和管理守护对象。
- 为高级场景提供重启窗口、延迟、退避、假活检测、进程族清理等策略。
- 通过模块扩展 Scheduler、Health、Profile、Report、PPL 等能力。
- 为远程管理和集群查看提供 Web gateway / cluster dashboard。

## 普通用户怎么开始

推荐使用安装包：

1. 以管理员身份运行 `pgs_setup_3.1.0.exe`。
2. 在向导里安装并启动 PGS 服务。
3. 打开 **PGS 管理端（Qt）**，按提示填入首次 token，然后添加要守护的程序。

便携版用户可以解压后在管理员终端运行：

```bat
pgs_service.exe install
pgs_service.exe start
pgs_admin_qt.exe
```

普通用户建议先读：

- [快速开始](docs/user/QUICK_START.md)
- [普通用户操作指南](docs/user/USER_GUIDE.md)
- [功能概览](docs/user/FEATURES.md)
- [常见问题](docs/user/FAQ.md)

## 文档目录

完整文档入口在 [docs/INDEX.md](docs/INDEX.md)。

按读者分组：

- 普通用户：安装、启动、守护程序、Qt/Web 使用、功能说明。
- 高级用户/维护者：服务 token、端口、远程管理、release、VM 验收、排障。
- 开发者：架构、协议、模块系统、构建、测试。
- 交接文档：后续安全专项和未完成/未验证功能清单。

## 当前边界

- WindowsApps / Store 应用当前支持“先启动，再按 PID 使用 `--winapp --aumid` attach”；自动 AUMID 推导和 `bless-start --winapp` 尚未完成。
- PPL 模块默认不启用；只有显式 opt-in 才会加载相关模块和驱动。
- 完整安全收口仍是后续专项，详见 [安全收口交接](docs/SECURITY_HARDENING_BACKLOG.md)。
- 未完成或未验证的功能集中记录在 [未完成功能交接](docs/UNFINISHED_FEATURES_BACKLOG.md)。

## 开发者快速入口

开发环境推荐 MSYS2 MinGW64：

```bat
set MINGW_ROOT=C:\msys64\mingw64
set CXX=%MINGW_ROOT%\bin\g++.exe
set CMAKE=%MINGW_ROOT%\bin\cmake.exe
set MSYS2_BASH=C:\msys64\usr\bin\bash.exe
tools\verify.bat
```

更多构建、测试、打包细节见：

- [开发者构建指南](docs/developer/BUILD.md)
- [测试与验证](docs/developer/TESTING.md)
- [技术架构](docs/developer/ARCHITECTURE.md)
