# PGS 模块系统与 PPL 模块说明

本文档是当前模块系统的权威说明。PGS 的主线已经从“守护服务里内建若干扩展能力”调整为“稳定核心 + 受信任模块生态”：核心服务负责守护、认证、协议、持久化、Job Object/IOCP、目录 ACL 和最终安全 loader；PPL、调度、健康、profile、report 以及未来社区插件都作为模块存在。

## 1. 架构边界

PGS 核心保留最终拒绝权。任何模块或模块管理器扩展都不能绕过以下检查：真实 DLL 路径必须位于 `<service-dir>/modules/` 内，模块名必须与目录/manifest 匹配，ABI 必须受支持，`modules.lock` 或兼容 `modules.allow` 必须授信，通过 hash/signature/risk/capability 检查后才允许 `LoadLibrary`。

普通模块和模块管理器扩展分开：

- 普通模块：`modules/<name>/pgs_<name>_module.dll`
- 模块 manifest：`modules/<name>/module.manifest.json`，旧 `module.manifest` 继续兼容
- 主信任文件：`modules/modules.lock`，旧 `modules.allow` 继续兼容
- staging 安装区：`modules_staging/`
- manager 扩展：`module_managers/<name>/manager.dll` + `manager.manifest.json`

Manager 扩展只做仓库索引、manifest 解析、安装计划、版本兼容和信任建议；它不直接加载普通模块，也没有执行 PGS 管理命令的 callback。核心 loader 始终不可插件化。

## 2. 模块 ABI v2/v3

模块 DLL 使用 `include/Process_Guard/PGModule.h` 的 C ABI。ABI v2 继续支持历史 KV 调用，ABI v3 增加 JSON-RPC 风格入口。

必需/推荐导出：

| 导出 | 说明 |
|------|------|
| `PG_GetName()` | 必需。返回稳定短名，如 `ppl`、`sched`。 |
| `PG_GetVersion()` | 推荐。返回版本字符串。 |
| `PG_GetAbiVersion()` | 推荐。当前基础 ABI 为 v2；带 JSON 入口的模块可声明/使用 v3 能力。 |
| `PG_GetManifest()` | 兼容 KV manifest。新模块推荐同时提供 `module.manifest.json`。 |
| `PG_Init(void*)` | 可选。PGS 传入 `PGS_ServicesV3*`，旧模块按 v2 前缀读取即可。 |
| `PG_Shutdown()` | 可选。卸载前释放资源。 |
| `PG_Invoke(const char*, char*, size_t)` | ABI v2 KV 调用入口。 |
| `PG_InvokeJson(const char*, char*, size_t)` | ABI v3 JSON-RPC 调用入口，动态探测，未导出时走 KV shim。 |

`PGS_ServicesV3` 提供：`call`、`now_ms`、`call_json`、`emit_event`、`get_data_dir`、`log`。模块通过 `call`/`call_json` 回调核心命令时，核心会按模块 capability 拦截危险操作，例如 `guard.register`、`guard.group`、`guard.hook`、`driver.kernel`。

## 3. JSON-RPC 模块协议

新主线命令是：

```bash
pgs_bless module invoke --name <name> --method <namespace.method> --params-json <json>
```

服务端 wire 命令为：

```text
module invoke <name> <method> <params-json-b64>
```

PGS 构造的请求 envelope：

```json
{
  "jsonrpc": "2.0",
  "id": "uuid-or-number",
  "module": "profile",
  "method": "profile.apply",
  "params": {},
  "context": {
    "trace_id": "...",
    "caller": "tcp|scheduler|web|qt",
    "deadline_ms": 5000
  }
}
```

响应：

```json
{"jsonrpc":"2.0","id":"...","result":{}}
```

或：

```json
{"jsonrpc":"2.0","id":"...","error":{"code":"ERR_CODE","message":"..."}}
```

约束：方法必须命名空间化，如 `profile.apply`、`ppl.set`、`health.summary`。默认请求/响应上限 64 KB；默认 deadline 5s，最大 60s。长任务应返回 `{ "accepted": true, "operation_id": "..." }`，后续用 `module op-status` 语义查询；大结果应返回 artifact id。当前服务端已经保留 `module artifact get` 命令位，但 artifact store 还未启用，会返回明确错误。

旧命令保留：

```bash
pgs_bless module call --name <name> --request "op=...;key=value"
```

## 4. Trust：modules.lock 与 modules.allow

`modules.lock` 是主信任文件，记录模块名、版本、sha256、publisher、source、capabilities、risk、trustedAt、signature policy 和 require_signed。构建脚本会为 bundled 模块生成默认 lock。

示例结构：

```json
{
  "version": 1,
  "generated_at": "build",
  "modules": [
    {
      "name": "ppl",
      "version": "1.0.0",
      "sha256": "...",
      "publisher": "PGS bundled",
      "source": "bundled",
      "capabilities": ["driver.kernel", "process.ppl.set", "process.ppl.clear"],
      "risk": "critical",
      "trustedAt": "build",
      "signature_policy": "hash",
      "require_signed": false
    }
  ]
}
```

`modules.allow` 继续兼容，逐行格式：

```text
<name>[|<sha256Hex>][|signed]
```

加载链路：预探测导出，不运行模块；解析 manifest；计算 sha256；检查路径、名称、ABI、lock/allow、签名策略、risk 开关和 capability；全部通过后才真正 `LoadLibrary` + `PG_Init`。`--allow-all-modules` 仍是开发逃生阀，等价于降低模块边界，生产环境不要使用。

`--hash none` 的语义已收紧：信任工具只有在选择 `auto` 或显式 HEX 时写入 hash；`none` 不会持久化 hash，后续重启不会做 hash 拦截。

## 5. 启用策略与 PPL 解耦

默认启动不自动扫描模块。常用开关：

```bash
pgs_service.exe run --enable-modules
pgs_service.exe run --enable-kernel-modules
pgs_service.exe run --enable-risk critical
pgs_service.exe run --enable-ppl   # 兼容别名
```

`--enable-modules` 用于普通模块。PPL 属于高危普通模块，需要 `--enable-kernel-modules`、`--enable-risk critical`、`PGS_ENABLE_KERNEL_MODULES=1` 或兼容 `--enable-ppl` 才能安装/加载。

`pgs_bless ppl set|get|clear` 仍保留为用户友好的便捷语法，但内部路由到：

```text
module invoke ppl ppl.set/get/clear <params-json-b64>
```

PPL 模块 manifest 标注 `driver.kernel`、`driver.sirius.load`、`process.ppl.set`、`process.ppl.clear` 等 capability。`Sirius.sys` 不在模块加载时初始化，只有显式 trust + load + invoke 后才尝试打开/加载驱动。

## 6. 模块安装、回滚与管理

当前 CLI：

```bash
pgs_bless module verify
pgs_bless module install --path <dll>
pgs_bless module reload --name <name>
pgs_bless module disable --name <name>
pgs_bless module rollback --name <name>
pgs_bless module artifact get <id>
```

`module install` 使用 staging 流程：先复制到 `modules_staging/<name>-stage-*`，验证 manifest/name/hash，再把旧版本移动到 `modules_staging/rollback/`，最后提升到 `modules/<name>/` 并更新 `modules.lock`。`rollback` 会从最近的 rollback payload 恢复。

`module verify` 会返回 modules 目录、`modules.allow`、`modules.lock`、`modules_staging`、`module_managers`、permissive 和 kernel enable 状态，适合 UI 和自动化健康检查。

## 7. Bundled 模块

| 模块 | 风险 | 作用 |
|------|------|------|
| `sched` | medium | 定时触发受限 PGS 命令。 |
| `health` | low | 汇总 stats/list/events。 |
| `profile` | medium | 保存并应用命名重启策略。 |
| `report` | low | 导出 stats/guards/events 快照。 |
| `ppl` | critical | 通过 Sirius.sys 设置/查询/清除 PPL。 |

PPL 的 signer 取值：`None`、`Authenticode`、`CodeGen`、`Antimalware`、`Lsa`、`Windows`、`WinTcb`、`WinSystem`、`App`。裸数字 signer 被拒绝，避免打开未文档化 enum 面。

## 8. UI 与 doctor

Qt 模块页保持现有风格，增强显示已安装、已信任、未信任、高风险、加载状态、回滚入口和 JSON invoke。PPL/driver/kernel 类模块显示普通用户可理解的风险确认。

Web/Qt 已加入 doctor 结果展示。CLI 命令：

```bash
pgs_bless doctor [--json]
```

doctor 默认只诊断不修改系统状态，覆盖 PGS 连通、token、服务状态、管理员权限、ProgramData ACL、state/log 可写、modules ACL、`modules.allow/modules.lock`、Qt/OpenSSL DLL、PPL 测试签名、`Sirius.sys`、Job Object attach 能力。

## 9. 编写新模块建议

最小步骤：

1. 新建 `modules/<name>/`。
2. 实现 `PG_GetName`、`PG_GetVersion`、`PG_GetAbiVersion`、`PG_Invoke`，新模块推荐实现 `PG_InvokeJson`。
3. 添加 `module.manifest.json`，声明 methods、params/result schema、required capabilities、risk、sync/async。
4. 构建到 `modules/<name>/pgs_<name>_module.dll`。
5. 使用 `module info/trust` 或 `module install` 进入 `modules.lock` 信任链。
6. 通过 `module invoke` 调用。

原则：模块名小写稳定；目录名、manifest name、`PG_GetName()` 保持一致；`PG_Invoke`/`PG_InvokeJson` 必须线程安全；不要在 `PG_Init` 做高风险或易失败初始化；大数据走 artifact，长任务走 operation id。

## 10. 社区生态规划

主仓库先提供协议、ABI、schema、信任和加载基础。后续建议拆两个仓库：

- `pgs-module-sdk`：ABI 头、CMake 模板、示例模块、schema、编写指南。
- `pgs-modules-registry`：registry index、插件元数据、publisher、release hash、审核记录。

Registry 只作为元数据来源，不信任 DLL 本身。社区模块默认只下载到 staging，必须显式 verify/trust/load 后才可执行。

## 11. 安全提醒

模块是在 PGS 服务进程内执行的 DLL，服务常见部署身份是 LocalSystem。只加载可信来源模块，保护 `modules/`、`modules_staging/`、`module_managers/` 的 ACL，不要在不可信主机启用 PPL。`Sirius.sys` 一旦加载，具备内核级能力；任何能打开其设备的本地主体都可能获得完整内核能力。

发布来源请只信任 CI artifact 或 GitHub Release。发布脚本会从源码重新构建 release，避免误发旧二进制；不要手工发布仓库里残留的旧 `release/` 或 `installer/Output/` 文件。
