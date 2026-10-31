# 模块系统

模块系统让 PGS 可以按需扩展能力。模块是 Windows DLL，放在 `<exe>\modules\<name>\` 下，每个目录带一份 `module.manifest.json`（manifest v2，含 `class` 字段）。通过 `module load` 显式加载，或在 opt-in 场景中扫描加载。

更底层的生态设计、`modules.lock`、manager extension 和 JSON-RPC 风格调用，见 [模块生态基础](../MODULE_ECOSYSTEM.md)。本文只保留开发者日常实现和调试时最常用的模块接口说明。

## 模块类别（manifest v2 `class`）

- `command`：命令扩展插件，经 `module call` / `module invoke` 调用。绝大多数 bundled 模块属于此类。
- `provider`：核心控制流提供者。首个消费者是 `winapp` launcher provider（WindowsApps AUMID 激活机制），服务重启 `appKind=winapp` 的 guard 时会把激活步骤委托给它。provider 类默认不启用。
- `companion`：发行级组件（如 `companions/` 下的 Web 管理端与 Cluster 面板）。独立进程，声明入口 exe，不加载进服务进程。

## ABI

模块导出：

- `PG_GetName`
- `PG_GetVersion`
- `PG_GetAbiVersion`
- `PG_GetManifest`
- `PG_Init`
- `PG_Shutdown`
- `PG_Invoke`

ABI v2 的 `PG_Init` 会收到 `PGS_Services`，模块可通过 callback 调回 PGS。

## Bundled modules（11 个 command + 1 个 provider）

- `sched`：定时任务，现有 Qt/Web 还提供专用便捷控件。
- `health`：状态摘要与健康探针配置/执行。
- `report`：snapshot/backup 文本报告与 artifact 输出。
- `notify`：Windows 本机通知模块，默认 Event Log，弹窗为显式 opt-in。
- `metrics`：guard/service/event 指标摘要、JSON 和 Prometheus 文本输出。
- `backup`：服务数据目录本地状态快照，可输出到 ArtifactStore；不会导出明文 token、artifact payload 或临时文件。
- `eventlog`：读取本机 Windows Application Event Log，支持 source 过滤。
- `dump`：显式确认后采集本机 minidump 到 ArtifactStore，不暴露临时路径。
- `service_guard`：本机 Windows SCM 查询/start/stop/ensure，mutation 需要 confirm，默认拒绝受保护 SCM 服务，可配置持久化 allowlist，并记录 mutation/policy 审计事件。
- `file_watch`：按需检测本地文件变化并发本机 PGS event；最多 64 条规则，只接受本机绝对盘符路径，并拒绝 UNC/device/ADS/Windows 系统目录/System Volume Information/Recycle Bin 路径。
- `policy`（v1.1.0）：命名 guard policy 模板 + 重启 profile（原 profile 模块已并入；`op=profile-*` 为兼容面，旧 `pgs_profiles.db` 会一次性导入）。
- `winapp`（provider）：WindowsApps AUMID launcher provider，默认不启用。

常用调用示例：

```bat
pgs_bless.exe health summary --token your-token
pgs_bless.exe profile set --name conservative --max-restarts 3 --token your-token
pgs_bless.exe profile apply --name conservative --pid 1234 --token your-token
pgs_bless.exe report snapshot --limit 20 --token your-token
pgs_bless.exe metrics prometheus --token your-token
pgs_bless.exe backup snapshot --artifact --token your-token
pgs_bless.exe module artifact status --json --token your-token
pgs_bless.exe module artifact policy --ttl-ms 86400000 --max-artifact-bytes 16777216 --max-total-bytes 268435456 --auto-cleanup --token your-token
pgs_bless.exe eventlog recent --limit 20 --source ProcessGuardService --token your-token
pgs_bless.exe dump status --token your-token
pgs_bless.exe service-guard query --name EventLog --token your-token
pgs_bless.exe service-guard policy --allow Spooler --confirm --token your-token
pgs_bless.exe file-watch status --token your-token
pgs_bless.exe policy-template list --token your-token
pgs_bless.exe schedule list --token your-token
```

## 加载规则

默认启动不自动扫描全部模块。推荐：

```bat
pgs_bless.exe module load --path "C:\Program Files\Process_Guarding_Service\modules\sched\pgs_sched_module.dll" --token your-token
```

服务模式下使用绝对 DLL 路径。相对路径只适合 `pgs_service.exe run` 从 release 目录启动的调试场景；服务端最终会确认 DLL 位于 `pgs_service.exe` 旁的 `modules` 目录内。

provider 类模块需要显式 opt-in：

```bat
pgs_service.exe install --enable-launchers
REM 或 run 模式：
pgs_service.exe run --enable-launchers
```

`--enable-launchers` 隐含 `--enable-modules`；未 opt-in 时 startup 扫描跳过 `winapp`，依赖它的 winapp guard 重启会进入隔离态并给出 `winapp.launcher_unavailable` 失败码。

## capability 强制（P2-12）

`module invoke` / `module invoke-json`（JSON-RPC 面）会在分发前校验 method 是否在目标模块 manifest 的 `methods` 声明内；manifest 未声明 methods 时退化为 capability 前缀匹配；两者都没有时保持放行（遗留插件）。拒绝会记录 `module.invoke-denied` / `module.invoke-json-denied` 审计事件。

KV 面的 `module call` 仍由模块自身校验 op 参数，模块回调 PGS 的命令受 ModuleManager 的 capability 门控（`commandAllowedForCapabilities`）。

## allowlist

`modules.allow` 支持：

```text
name
name|sha256
name|sha256|signed
```

bundled `modules.lock` 由各模块的 `module.manifest.json` + DLL hash 派生（构建时自动生成，不再维护手工清单）；当 release 树随包携带 `modules.lock` 时，加载会按 hash-pinned 条目 fail-closed。`modules.allow` 是操作者的信任管理面；发布签名强制和代码签名仍属于后续安全专项。

非 permissive 模式下，空 allowlist 会 fail-closed。`module trust` 可离线生成带 hash 或签名要求的条目。

## module info / trust

`module info` 和 `module trust` 是本地离线工具，不连接服务，不需要 token。

```bat
pgs_bless.exe module info --path modules\winapp\pgs_winapp_module.dll --json
pgs_bless.exe module trust --path modules\winapp\pgs_winapp_module.dll --hash auto
```

## 运行态状态

ArtifactStore 写入服务 state 目录下的 `artifacts` 子目录，默认 TTL 为 24 小时、单 artifact 16MB、总量 256MB，可通过 `module artifact policy` 调整；TTL 范围是 60 秒到 7 天，`max_artifact_bytes` 范围是 64KB 到 64MB，`max_total_bytes` 范围是 1MB 到 1GB，且总量不能小于单 artifact 上限。`auto_cleanup=1` 时新 artifact 写入前和后台 health loop 会清理过期项，`verify_on_status=1` 时 status 查询会做 hash 校验。metadata id 与文件名不一致会按损坏处理。metadata 包含 `sensitive` / `sensitivity`；dump/minidump 默认高敏并限制到 6 小时 TTL，backup 类默认中敏并限制到 24 小时 TTL；status/doctor 会显示敏感 artifact 数量和有效配额策略。

`service_guard` policy 写入服务 state 目录下的 `modules\service_guard\service_guard_policy.cfg`。空 allowlist 表示兼容模式：仍需 `confirm=1`，并默认拒绝受保护服务；配置 allowlist 后，mutation 还必须命中 allowlist。`allow_protected=1` 只在 allowlist 非空时允许设置，并且只解除显式 allowlist 内受保护服务的默认拒绝。

`policy` / `sched` 按服务数据目录写运行态 DB，默认落到 `C:\ProgramData\ProcessGuard\state\modules\<name>\` 或等价受保护目录。`policy` 首次访问会把旧 `modules\profile\pgs_profiles.db` 一次性导入模板库并改名 `.imported`。

## ABI 调用顺序

1. 服务端读取 `<modules-dir>\modules.allow`。
2. `module load` 解析 DLL 路径并确认它位于模块目录内。
3. `LoadLibrary` 后解析 `PG_GetName`、`PG_Invoke`，再读取 `module.manifest.json`（与导出函数的 name/abi 交叉校验）。
4. 宿主调用 `PG_Init`。ABI v2 模块会通过 `reserved` 收到 `PGS_Services`。
5. 客户端 `module call` / `module invoke`（capability 校验后）或便利命令触发 `PG_Invoke`。
6. `module unload` 或服务关闭时调用 `PG_Shutdown`。

`PG_Invoke` 必须线程安全；PGS 可能并发调用同一个模块。

## 安全边界

- `--allow-all-modules` 只用于开发和应急调试；运行中可用 `pgs_bless.exe module permissive status|on|off` 查看、确认开启或关闭，`on` 必须带 `--confirm`。
- 模块 load 路径必须位于模块目录内。
- provider 类模块默认关闭，需 `--enable-launchers`。
- JSON-RPC 面按 manifest capability/methods 强制校验（见上文 capability 强制一节）。
