# 模块系统

模块系统让 PGS 可以按需扩展能力。模块是 Windows DLL，放在 `<exe>\modules\<name>\` 下，通过 `module load` 显式加载或在 opt-in 场景中扫描加载。

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

## Bundled modules

- `sched`：定时任务。
- `health`：状态摘要。
- `profile`：命名重启策略 profile。
- `report`：snapshot/backup 文本报告。
- `ppl`：PPL opt-in 模块，复用 Sirius 驱动。

常用调用示例：

```bat
pgs_bless.exe health summary --token your-token
pgs_bless.exe profile set --name conservative --max-restarts 3 --token your-token
pgs_bless.exe profile apply --name conservative --pid 1234 --token your-token
pgs_bless.exe report snapshot --limit 20 --token your-token
pgs_bless.exe schedule list --token your-token
```

## 加载规则

默认启动不自动扫描全部模块。推荐：

```bat
pgs_bless.exe module load --path "C:\Program Files\Process_Guarding_Service\modules\sched\pgs_sched_module.dll" --token your-token
```

服务模式下使用绝对 DLL 路径。相对路径只适合 `pgs_service.exe run` 从 release 目录启动的调试场景；服务端最终会确认 DLL 位于 `pgs_service.exe` 旁的 `modules` 目录内。

PPL 需要额外 opt-in：

```bat
set PGS_ENABLE_PPL=1
pgs_service.exe run --enable-ppl
```

## allowlist

`modules.allow` 支持：

```text
name
name|sha256
name|sha256|signed
```

功能完成版 bundled allowlist 仍以名称为主。发布哈希钉扎、签名和 SBOM 属于后续安全专项。

非 permissive 模式下，空 allowlist 会 fail-closed。`module trust` 可离线生成带 hash 或签名要求的条目，但本轮 release 未自动把 bundled module 哈希钉进 allowlist。

## module info / trust

`module info` 和 `module trust` 是本地离线工具，不连接服务，不需要 token。

```bat
pgs_bless.exe module info --path modules\ppl\pgs_ppl_module.dll --json
pgs_bless.exe module trust --path modules\ppl\pgs_ppl_module.dll --hash auto
```

## 运行态状态

当前 `profile` / `sched` 仍按模块目录设计运行态 DB。release smoke 和 installer 已防止运行态 DB 泄漏进发布包；长期应迁移到 ProgramData，详见交接文档。

## ABI 调用顺序

1. 服务端读取 `<modules-dir>\modules.allow`。
2. `module load` 解析 DLL 路径并确认它位于模块目录内。
3. `LoadLibrary` 后解析 `PG_GetName`、`PG_Invoke`，再读取可选 version/ABI/manifest。
4. 如果 manifest 里声明了 name 或 abi，宿主会和导出函数结果交叉校验。
5. 宿主调用 `PG_Init`。ABI v2 模块会通过 `reserved` 收到 `PGS_Services`。
6. 客户端 `module call` 或便利命令触发 `PG_Invoke`。
7. `module unload` 或服务关闭时调用 `PG_Shutdown`。

`PG_Invoke` 必须线程安全；PGS 可能并发调用同一个模块。

## 安全边界

- `--allow-all-modules` 只用于开发和应急调试。
- 模块 load 路径必须位于模块目录内。
- PPL 默认关闭。
- capability 目前是展示/规划字段，尚未作为完整授权系统。
