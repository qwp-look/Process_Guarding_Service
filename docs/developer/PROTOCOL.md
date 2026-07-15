# 协议与契约

PGS 管理协议是轻量文本行协议。客户端通过 TCP 连接发送一行命令，服务端返回 `OK ...` 或 `ERR ...`。

## 认证信封

TCP 客户端命令会包在 token 信封里：

```text
token <base64-token> <command>
```

CLI 的 `--token` 输入仍是普通 token 字符串，由客户端编码成 wire envelope。服务端只保存 token hash，不保存 token 明文。空 token 不被接受。

没有信封的命令会被拒绝，少数测试或模块 callback 路径是在服务进程内直接调用协议处理函数，不经过 TCP auth envelope。

## 常用命令

CLI 用户通常通过 `pgs_bless.exe` 间接调用协议：

- `ping`
- `version`
- `stats`
- `list`
- `get`
- `bless`
- `bless-start`
- `unbless`
- `policy`
- `token-set`
- `module list/load/unload/call`
- `sched ...`
- `health ...`
- `profile ...`
- `report ...`

`bless` / `unbless` 是协议层别名，兼容旧 `register` / `unregister` 语义。

核心 wire 形态：

```text
register <pid>|<pathB64>|<max>|<restartArgsB64>|<sha256-or-empty>|<restartWindow>|<restartDelay>|<backoff>|<hangTimeout>|<killOnExit>|<appKind>|<aumidB64>
unregister <pid>
intentional <pid>
set-policy <pid>|<max>|<restartArgsB64>|<restartWindow>|<restartDelay>|<backoff>|<hangTimeout>|<killOnExit>|<appKind>|<aumidB64>
set-token <oldTokenB64>|<newTokenB64>
module call <name> <request>
events list [limit]
```

CLI 的 `bless`、`bless-start`、`policy` 会负责生成这些 wire payload。`bless-start` 还会先创建本地进程，待服务注册成功后再恢复主线程。

## 高级策略字段

高级 guard policy 包含：

- `restart-window`
- `restart-delay`
- `restart-backoff`
- `hang-timeout`
- `kill-on-exit`
- `appKind`
- `aumid`

`set-policy` 的 `pid` 和 `max` 必填；`restartArgs` 和高级策略字段支持只更新显式传入项。Scheduler 文档和 CLI 示例应统一使用 `set-policy`，旧 `policy` 作为兼容别名。

字段默认值：

- `restart-window=0`：不按滑动窗口裁剪，沿用生命周期计数。
- `restart-delay=0`：立即重启。
- `restart-backoff=0`：不退避。
- `hang-timeout=0`：不做 GUI hang 探测。
- `kill-on-exit=0`：PGS 退出时不连杀进程族。
- `appKind=win32`：普通 Win32 程序。

## JSON 输出

`list --json` 和 `get --json` 面向 UI/脚本，包含 v3 字段：

- `app_kind`
- `aumid`
- `restart_window`
- `restart_delay`
- `backoff`
- `hang_timeout`
- `kill_on_exit`

新增字段时要同步 `tools/protocol_contract.ps1` 和 UI 解析。

## WindowsApps 当前协议边界

`--winapp` 必须携带显式 AUMID。`bless-start --winapp` 当前由 CLI 拒绝。自动 AUMID 推导是未完成项。

## 模块 action

模块通过：

```text
module call <name> <request>
```

高层 CLI 会提供便利命令，如 `sched`、`health`、`profile`、`report`。模块 capability 目前主要用于展示和后续策略规划，尚未作为完整运行时授权边界。

Scheduler 的 action 是服务端 wire command，不是 CLI 命令。允许的首词当前包括 `bless`/`register`、`unbless`/`unregister`、`policy`/`set-policy`、`intentional`、`list`、`get`、`ping`；`token-set`、服务安装卸载、模块 load/unload、模块 call、PPL 等不会被 Scheduler 执行。
