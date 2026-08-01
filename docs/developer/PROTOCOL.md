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
- `guard retry --id <guard-id>`
- `guard clear-quarantine --id <guard-id>`
- `notify status|config`
- `metrics summary|json|prometheus`
- `backup status|snapshot [--artifact] [--max-bytes N]`
- `eventlog status|recent [--limit N] [--source <name>]`
- `dump status|collect --pid <pid> [--type normal|with-data] [--confirm]`
- `service-guard status|query|start|stop|ensure --name <service> [--state running|stopped] [--confirm]`
- `service-guard policy [--allow <svc1,svc2>] [--allow-protected|--no-allow-protected] [--confirm]`
- `service-guard policy-clear --confirm`
- `file-watch status|add|list|check|remove --path <file> [--id <id>] [--action event|none]`
- `policy-template status|set|list|remove|apply --name <template> [--pid <pid>]`
- `remote-agent status|heartbeat|guards`
- `update status|verify --path <release-manifest.json>`
- `script-runner status|config|add|list|run [--id <id>] [--path <script>] [--start-args "..."] [--enable|--disable] [--confirm]`
- `module op-status <operation-id>`
- `module artifact get <artifact-id> [--json|--out <path>]`
- `module artifact cleanup [--expired|--all] [--verify]`
- `module artifact status [--verify] [--json]`
- `module artifact policy [--ttl-ms N] [--max-artifact-bytes N] [--max-total-bytes N] [--auto-cleanup|--no-auto-cleanup] [--verify-on-status|--no-verify-on-status] [--json]`

`bless` / `unbless` 是协议层别名，兼容旧 `register` / `unregister` 语义。

核心 wire 形态：

```text
register <pid>|<pathB64>|<max>|<restartArgsB64>|<sha256-or-empty>|<restartWindow>|<restartDelay>|<backoff>|<hangTimeout>|<killOnExit>|<appKind>|<aumidB64>
unregister <pid>
intentional <pid>
set-policy <pid>|<max>|<restartArgsB64>|<restartWindow>|<restartDelay>|<backoff>|<hangTimeout>|<killOnExit>|<appKind>|<aumidB64>
set-token <oldTokenB64>|<newTokenB64>
module call <name> <request>
guard retry <guard-id>
guard clear-quarantine <guard-id>
events list [limit]
```

CLI 的 `bless`、`bless-start`、`policy` 会负责生成这些 wire payload。普通 Win32 的 `bless-start` 会先创建本地进程，待服务注册成功后再恢复主线程；WindowsApps 的 `bless-start --winapp` 不走 `CreateProcessW`，而是通过 AUMID activation 拿到 PID 后注册。

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

## Health Check

`health-check set|get|clear --pid <pid> [--config-json <json>]` 现在由核心执行，不只是存储。支持的最小 schema 示例：

```json
{"type":"process","interval_ms":30000,"timeout_ms":2000,"failures":3,"action":"event"}
{"type":"tcp","host":"127.0.0.1","port":8080,"interval_sec":10,"timeout_ms":1000,"failures":2,"action":"restart"}
{"type":"http","url":"http://127.0.0.1:8080/health","min_status":200,"max_status":399,"action":"quarantine"}
```

`action` 可为 `event`、`none`、`restart`、`quarantine`。`alert`/`notify` 会归一为 `event`，由 Windows 本机通知模块消费事件，不在 health-check 内直接接远程通知渠道。探针在独立 health worker 线程执行，超时上限由配置裁剪到安全范围内。

## JSON 输出

`list --json` 和 `get --json` 面向 UI/脚本，包含 v3 字段：

- `app_kind`
- `aumid`
- `restart_window`
- `restart_delay`
- `backoff`
- `hang_timeout`
- `kill_on_exit`
- `health_status`
- `health_last_message`
- `health_last_check`
- `health_last_ok`
- `health_last_failure`
- `health_next_check`
- `health_failure_count`
- `guard_id`
- `status` (`active` / `paused` / `missing` / `quarantined`)
- `quarantined`
- `last_failure`
- `last_failure_code`
- `next_retry_ms`
- `failure_count`

新增字段时要同步 `tools/protocol_contract.ps1`、`tools/smoke_test_pgs.sh` 和 UI 解析。

## Guard 隔离态

当自动重启失败、延迟重启失败、restore 重启失败或重启窗口耗尽时，服务会把持久 guard 标为 `quarantined`，而不是直接从归档删除。`list` 会继续返回这类记录，通常 `PID=0`、`STATUS=quarantined`、`QUARANTINED=1`，并带失败原因和失败次数。

人工处理入口：

```text
guard retry <guard-id>
guard clear-quarantine <guard-id>
```

CLI 对应：`pgs_bless.exe guard retry --id <guard-id>` 和 `pgs_bless.exe guard clear-quarantine --id <guard-id>`。`retry` 成功后清除失败状态并恢复 active guard；失败会更新隔离失败次数。`clear-quarantine` 表示管理员确认退休该归档。主动 `intentional` 退出仍然清理 guard，不进入隔离。

## WindowsApps 当前协议边界

`--winapp` 必须最终得到 AUMID。CLI 支持显式 `--aumid`，也会在给出 WindowsApps exe 路径时尝试从上层 `AppxManifest.xml` 推导 AUMID。`bless-start --winapp --aumid <id>` 会通过 Windows AUMID activation 启动应用并注册返回的 PID；若 activation 失败、无法查询进程路径，或激活出的进程与请求 AUMID 不匹配，会拒绝注册。真实 Store/UWP 环境仍需 `tools/verify_winapp.ps1` 做 E2E 验证。

## 模块 action

模块通过：

```text
module call <name> <request>
```

OperationStore / ArtifactStore 已由服务端提供：模块可通过 ABI v3 `call_json` 调 `pgs.operation.create/get/update/finish/fail` 和 `pgs.artifact.put/get_meta`；模块也可通过 `emit_event` 发送 JSON 事件，若 JSON 内 `type` 是安全事件名，核心会在 `events list` 中直接记录该 `TYPE`，并把原始 JSON 放到 base64 detail，缺失或不安全时回退为 `module.event`。CLI 可用 `module op-status <op_id> --json` 查询操作，用 `module artifact get <art_id> --json` 查元数据，用 `module artifact get <art_id> --out <path>` 分块下载。下载完成后 CLI 会按元数据核对 size 和 SHA-256；服务端 chunk 返回前也会重新计算落盘 size/SHA-256，不匹配时返回 `ERR artifact content hash mismatch`。`module artifact cleanup [--expired|--all] [--verify]` 可清理过期/全部 artifact，并可校验后移除损坏内容；`module artifact status [--verify] --json` 返回 store health、敏感 artifact 数量和有效策略；`module artifact policy --ttl-ms N --max-artifact-bytes N --max-total-bytes N --auto-cleanup --verify-on-status --json` 读取或写入保留策略。`max_artifact_bytes` 受限为 64KB 到 64MB，`max_total_bytes` 受限为 1MB 到 1GB，且总量不能小于单个 artifact 上限。Artifact metadata 包含 `sensitive` / `sensitivity`，高敏 artifact TTL 会被裁剪；artifact chunk 下载会记录开始/完成/过期/非法事件。`pgs_bless doctor --json` 也包含 `artifact_store` 检查。

高层 CLI 会提供便利命令，如 `sched`、`health`、`profile`、`report`。模块 capability 目前主要用于展示和后续策略规划，尚未作为完整运行时授权边界。

当前 bundled 模块便利命令还包括 `notify`、`metrics`、`backup`、`eventlog`、`dump`、`service-guard`、`file-watch`、`policy-template`、`remote-agent`、`update`、`script-runner`。其中 `notify` 只使用 Windows 本机 Event Log/可选弹窗；`metrics json/prometheus` 和 `backup snapshot` 会在 CLI 端解码 base64 文本，便于脚本直接消费；`eventlog --source` 会拒绝分号、控制字符和超长值。`service-guard status` 返回 `mutation_policy/allowlist_mode/allow_count/allow_protected/protected_services`；mutation 需要 `--confirm`，默认拒绝受保护 SCM 服务，可用 `service-guard policy --allow <svc1,svc2> --confirm` 持久化白名单，受保护服务还需要额外 `--allow-protected`。mutation/policy 会记录 `service_guard.*` 审计事件。`file-watch status` 返回 `rules/max_rules/mode/actions/path_policy`，`add` 最多保留 64 条规则，只接受本机绝对盘符路径，并拒绝 UNC/device/ADS/Windows 系统目录/System Volume Information/Recycle Bin 路径。`script-runner status` 返回 `path_policy=final-path-under-data-scripts/hash_on_run/audit`；`add` 会记录脚本 SHA-256，`run` 前重验 hash，不一致返回 `ERR script hash mismatch`，并记录 `script_runner.*` 事件。`dump collect`、服务 mutation、`script-runner run` 需要 `--confirm`；`script-runner` 默认禁用；`update` 只校验本地 release manifest，不下载或安装。`module permissive status|on|off` 可显示、确认开启或关闭开发用 permissive 模式，`on` 需要 `--confirm` 并记录审计事件。

Scheduler 的 action 是服务端 wire command，不是 CLI 命令。允许的首词当前包括 `bless`/`register`、`unbless`/`unregister`、`policy`/`set-policy`、`intentional`、`list`、`get`、`ping`；`token-set`、服务安装卸载、模块 load/unload、模块 call、PPL 等不会被 Scheduler 执行。
