# 技术架构

本文面向开发者，解释 PGS 的实现边界和主要组件。操作命令请看 [普通用户操作指南](../user/USER_GUIDE.md) 或 [维护者操作指南](../operator/OPERATOR_GUIDE.md)。

## 组件

- `PGS`：服务核心，负责认证、协议、守护状态、监控、重启、模块调用。
- `pgs_service`：Windows 服务宿主，负责 install/start/stop/uninstall/run。
- `pgs_bless`：CLI 运维入口。
- `pgs_admin_qt`：Qt 桌面管理端。
- `pgs_admin_web`：Web 管理端。
- `pgs_cluster_web`：Cluster dashboard。
- `ModuleManager`：加载和调用 ABI 模块。

## 状态模型

PGS 把守护对象当成“逻辑 guard”，而不是单个 PID。进程重启后 PID 会变，但 guardId 和策略继续存在。

持久化状态包含：

- guard desired-state。
- token hash。
- 重启计数和窗口时间戳。
- 高级策略字段。
- 模块 permissive 状态。

归档存储为 SQLite 数据库（2026-10-31 起，阶段 E）：事务化快照写入、类型化列（guards/groups/restart_policy/meta 四张表），schema 版本由 meta.state_version 标记（当前 5，与旧文本格式版本对齐）。首次加载遇到旧 tab 分隔文本归档时会自动迁移到 SQLite 并把旧文件改名 `.text-imported`；v1/v2/v3/v4 文本版本沿用历史迁移规则（v1 丢弃 FNV-1a token hash）。

默认持久化文件位于：

```text
C:\ProgramData\ProcessGuard\state\pgs_guard_state.db
```

实现位于 `src/service/PGSSqliteStore.{h,cpp}`（快照结构与旧文本互转的 `parseLegacyStateText` 也在其中，供迁移和单测使用）；`loadPersistedState`/`persistState` 的快照编排在 `PGSGuardStore.cpp`。MinGW 构建链接 `sqlite3`，发布树附带 `libsqlite3-0.dll`。

## 监控和重启

PGS 使用 Job Object 管理进程族，并通过 IOCP 接收退出通知。IOCP 是快速唤醒路径，句柄轮询仍作为兜底。

`kill-on-exit` 默认关闭，保证 PGS 自身崩溃或被 SCM 重启时，守护进程可以继续存活并被复接管。用户显式开启时，PGS 退出会连同守护进程族一起结束。

重启流程按 guardId 维护窗口计数。`restart-delay` 会延迟拉起；`restart-backoff` 基于该延迟做指数退避；超过 `restart-window` 内的上限、restore 重启失败或重启异常失败时，guard 会进入持久 `quarantined` 状态并保留失败原因，等待 `guard retry` 或 `guard clear-quarantine`。

## 启动路径

普通 Win32 程序：

- `bless-start` 使用 CLI 启动后注册。
- 服务端异常恢复时按保存的 path/args 在目标 session 中拉起。

WindowsApps：

- 支持显式 AUMID attach，也支持从 WindowsApps exe 上层 `AppxManifest.xml` 推导 AUMID。
- `bless-start --winapp --aumid ...` 走 Windows AUMID activation 并注册返回 PID。
- 服务端异常恢复/重启同样走 AUMID activation；真实 Store/UWP 环境仍需要 `tools/verify_winapp.ps1` 验证。

## UI 边界

Qt 管理端偏本机普通用户。Web 管理端偏浏览器和远程维护。Cluster dashboard 只做多节点查看与节点管理，不替代单机守护核心。

Web remote 必须 TLS + users file + audit log。Cluster 非回环监听必须 TLS + dashboard API token。

## 模块边界

模块是 Windows DLL，导出 C ABI，随目录携带 manifest v2（`module.manifest.json`，`class` 区分 command/provider/companion）。PGS 通过 `LoadLibrary` 和 `PG_Invoke` 调用。命令模块按需加载；provider 类模块（如 winapp launcher）需要 `--enable-launchers` opt-in。JSON-RPC 调用面按 manifest capability/methods 强制校验。

模块目录受 allowlist 和路径限制保护。完整模块开发细节见 [模块系统](MODULE_SYSTEM.md)。

## 协议边界

协议是文本行协议，不是 protobuf/grpc。当前通过契约测试固定核心响应；protobuf 迁移不是本轮目标，后续视复杂度再评估。

协议细节见 [协议与契约](PROTOCOL.md)。
