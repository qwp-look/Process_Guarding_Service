# 守护功能

守护功能是 PGS 的核心：把一个程序注册给 PGS，PGS 会观察它的退出状态，并按策略决定是否重启。

## 基础行为

- 正常取消守护或标记 intentional 后，PGS 不会再拉起目标。
- 异常退出时，PGS 按最大重启次数决定是否重启。
- 服务重启后，PGS 会读取归档并恢复仍应守护的对象。
- `bless-start` 会先启动程序再注册守护，适合普通 Win32 程序。

## 常用策略

- 最大重启次数：限制崩溃循环。
- 重启窗口：只统计一段时间内的重启次数。
- 重启延迟：异常退出后等一会儿再拉起。
- 指数退避：连续失败时逐步拉长等待时间。
- 假活检测：对有窗口的程序做简单 hang 探测。
- 退出连杀：PGS 退出时是否一并结束目标进程族。

普通用户可以先只设置最大重启次数。其它策略适合服务端程序、容易崩溃的程序或需要严格恢复节奏的场景。

## WindowsApps 当前用法

WindowsApps / Store / UWP 应用的启动方式和普通 exe 不一样。当前版本支持两种流程：

1. 已运行应用：先启动 Store 应用，找到对应 PID，然后使用 `pgs_bless bless --pid <pid> --winapp --aumid <id>` 注册。
2. 直接启动注册：使用 `pgs_bless bless-start --winapp --aumid <id>`，CLI 会通过 Windows AUMID activation 激活应用并注册返回的 PID。

如果传入的是 WindowsApps 目录内的 exe 路径，CLI 会尝试读取上层 `AppxManifest.xml` 并推导 AUMID；也可以显式传 `--aumid`。这条路径已实现 manifest fixture 单元测试，真实 Store/UWP 环境仍需要用 `tools/verify_winapp.ps1` 做管理员/交互会话 E2E 验证。

## 进一步阅读

- 命令行用法见 [普通用户操作指南](USER_GUIDE.md)。
- 策略字段和协议细节见 [协议与契约](../developer/PROTOCOL.md)。
