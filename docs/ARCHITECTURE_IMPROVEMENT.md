# 当前架构的改进与升级思路

> 文档版本：2026-07-27  
> 适用版本：PGS 0.1.0-beta.1  
> 阅读对象：项目维护者、后续开发者

---

## 一、背景

PGS（Process Guarding Service）是一个 Windows 进程守护工具，以 Windows 服务形态运行，核心语言为 C++17，使用 CMake + MSYS2/MinGW64 工具链构建，管理界面分为 Qt 桌面端、Web 管理端和 CLI 三层。项目当前处于 0.1.0-beta.1 阶段，核心守护功能已完整，具备 16 个 bundled 模块，适合进入下一轮架构强化。

本文基于对源码、文档和构建系统的系统评审，识别当前架构的优点、不足和潜在瓶颈，并提出分阶段、可落地的演进方案。

---

## 二、现状分析

### 2.1 核心组件划分

| 组件 | 职责 | 实现方式 |
|------|------|---------|
| `PGS`（核心类） | 认证、协议、守护状态、监控、重启、模块调用、ArtifactStore、HealthLoop、NotifyLoop | 单一大类，`PGS.cpp` |
| `pgs_service` | Windows 服务宿主（install/start/stop/run） | 薄壳，委托 `PGS` |
| `pgs_bless` | CLI 运维工具 | 单文件，含 registry install 逻辑 |
| `ModuleManager` | DLL 加载、allowlist、hash 校验 | 独立静态库 |
| `PGSClient` | TCP 客户端（CLI/Qt/Web 使用） | 独立静态库 |
| `PGLogger` | 日志 | 独立静态库 |
| Qt 管理端 × 3 | 桌面/Web/Cluster 管理界面 | 独立 CMake 子项目 |
| 16 个 bundled 模块 | 功能扩展（调度/健康/备份/通知等） | C ABI DLL |

### 2.2 架构亮点

1. **Guard ID 抽象**：以逻辑 `guardId` 而非 PID 追踪守护对象，进程重启后策略和计数器不丢失，多实例同路径场景下行为正确。
2. **IOCP + 句柄轮询双路径**：IOCP 作为快速通知路径，句柄轮询作为兜底，监控可靠性高。
3. **模块 C ABI**：DLL 导出 C 接口，ABI 稳定，不受编译器版本影响，支持热加载/卸载。
4. **Quarantine 隔离态**：重启失败后不丢弃守护对象，保留失败码、失败次数，支持人工恢复。
5. **分层文档体系**：交接文档、安全 Backlog、未完成 Backlog 结构清晰。
6. **`pgs_service` 作为薄壳**：所有守护逻辑封装在 `PGS` 类，Console 模式和 SCM 模式共享同一套逻辑。

### 2.3 主要不足与潜在瓶颈

#### 不足一：PGS 类职责过重（最突出问题）

`PGS.cpp` 是单一文件，集中承载了以下互不相关的子系统：

- TCP 服务器（监听 + Worker Pool + 协议解析）
- 守护生命周期管理（注册/注销/隔离/恢复）
- 持久化归档（状态文件读写）
- ArtifactStore（artifact 元数据、分块下载、过期清理）
- OperationStore（异步操作追踪）
- HealthLoop（探针执行引擎）
- NotifyLoop（事件分发）
- 模块调用路由

随着功能增长，这个文件必然变得难以阅读、难以单元测试，修改任一子系统都需要理解整个文件的上下文。

#### 不足二：状态文件是手工序列化的 tab 分隔文本

`pgs_guard_state.db`（v5）有约 25 个字段，序列化/反序列化逻辑散落在 `loadPersistedState()` 和 `persistState()` 中，手工维护版本兼容代码（v2→v3→v4→v5 升级路径）。随着字段继续增加，这里是未来的 bug 高发区。

#### 不足三：管理协议是裸文本行协议

`token <base64-token> <command>` 的信封设计功能上可用，但：
- 没有结构化 schema，新命令需要手工解析参数字符串
- 没有版本协商，客户端无法探测服务端能力边界
- 没有连接复用，每个命令独立 TCP 连接

#### 不足四：测试覆盖不均匀

单元测试只覆盖 `SchedCron`、部分 `ModuleManager` 逻辑和通过 `PGS_ENABLE_TEST_HOOKS` 宏暴露的少量核心行为；守护流程（注册→监控→退出检测→重启→隔离）主要依赖集成 smoke 脚本覆盖，粒度粗。

#### 不足五：pgs_bless.cpp 体量膨胀

CLI 入口是单个 `pgs_bless.cpp`，含 16 个模块的 CLI wrapper 代码、registry install 逻辑、doctor 命令等，文件结构趋向难以维护。

#### 不足六：依赖管理无锁定机制

`nlohmann/json.hpp` 是直接放入仓库的单头文件（vendor）；Qt 和 MinGW 通过 MSYS2 pacman 安装，版本没有 lockfile 约束，CI 缓存 key 靠 `v5` 手工版本控制。

---

## 三、分阶段改进方案

### 第一阶段：内部重构（低风险，不改对外接口）

**目标**：在不改变协议、不破坏现有用户的前提下，提升内部可维护性和可测试性。

#### 3.1 拆分 PGS 核心类

将 `PGS` 类中各子系统抽出为独立类，通过接口或直接持有引用连接：

```
PGS（协调器）
├── GuardEngine         守护生命周期（注册/注销/重启/隔离）
├── PersistenceStore    状态文件读写
├── ArtifactStore       artifact 元数据/分块/清理
├── OperationStore      异步操作追踪
├── HealthEngine        探针执行（process/tcp/http）
├── NotifyEngine        事件队列分发
├── TcpServer           监听 + Worker Pool
└── ProtocolHandler     命令解析与路由
```

每个子系统有独立头文件，可以独立单元测试。`PGS` 本身只做组装和生命周期协调，不包含业务逻辑。

优先级最高的两个拆分：
- **ArtifactStore**：已有清晰的 `ArtifactRecord`、`ArtifactCleanupResult` 等 struct，边界清楚，拆出成本低。
- **HealthEngine**：`healthLoop()` 已是独立线程，将探针配置解析、执行、结果回调抽出即可。

#### 3.2 状态文件迁移到 SQLite

用 SQLite（单文件，无服务依赖）替换手工 tab 分隔文本序列化：

- 引入 `sqlite3.h` 单文件 amalgamation（vendor 方式，与 nlohmann/json 保持一致）。
- `PersistedGuardState` 直接映射为表行，schema 版本由 `PRAGMA user_version` 管理，升级脚本写成 SQL migration，不再是手工字段 patch。
- `RestartPolicyState` 作为关联表，支持后续增加 failure history 时间线（P1-12）。

**迁移策略**：保留旧 `.db` 文本格式读取能力（兼容期），写入时统一用 SQLite；首次启动自动迁移。

#### 3.3 拆分 pgs_bless.cpp

按功能域拆分为多个 `.cpp` 文件，共享同一个 `main()` 入口通过命令路由：

```
tools/
├── pgs_bless_main.cpp     入口 + 命令路由
├── bless_guard.cpp        guard/bless/unbless/policy 命令
├── bless_module.cpp       module load/unload/call/install
├── bless_health.cpp       health-check set/get/clear
├── bless_scheduler.cpp    sched add/list/enable/disable/remove
├── bless_artifact.cpp     artifact get/status/cleanup/policy
├── bless_doctor.cpp       doctor/repair 命令
└── bless_registry.cpp     registry install（现有 PGSRegistryInstall.cpp）
```

每个文件注册自己处理的命令前缀，`main()` 做统一分发。

#### 3.4 增加子系统级单元测试

为拆分后的子系统补充单元测试：

- `GuardEngine`：注册→监控→退出→重启→隔离的状态机跳转，用 mock `HANDLE` 和 `IOCP`。
- `ArtifactStore`：put/get/cleanup/过期/corrupt 判断。
- `PersistenceStore`：v3→v4→v5 迁移路径，缺字段补默认值，格式错误 fail-closed。
- `HealthEngine`：配置解析正负例，探针结果→action 映射。

---

### 第二阶段：协议与传输层升级（中等影响）

**目标**：提升管理协议的安全性、结构化程度和可演进性，不破坏现有 CLI/Qt/Web 的基本能力。

#### 3.5 增加 Named Pipe 传输层

在现有 TCP 传输旁增加 Windows Named Pipe 传输，作为本地管理的推荐通道：

- Pipe 路径：`\\.\pipe\ProcessGuardService`
- DACL：仅允许 `Administrators` 和 `SYSTEM` 连接。
- 协议层保持不变（同样的 token 信封 + 命令字符串），只换底层 I/O。
- `PGSClient` 增加 pipe 连接模式，CLI/Qt 优先尝试 pipe，回退到 TCP（兼容期）。

这样即使 TCP token 泄露，攻击者也必须拥有本机管理员权限才能调用管理 API。

#### 3.6 协议版本协商

在 `ping` 响应中增加 `protocol_version` 字段，客户端可在连接后探测服务端能力边界，为后续命令集扩展提供基础：

```
PING_RESPONSE: OK pgs 0.1.0 protocol 2 capabilities=artifact,health,cluster
```

#### 3.7 命令参数结构化（渐进）

优先将参数最复杂的命令（`health-check set`、`module artifact policy`、`sched add`）的参数改为 JSON body 而非 pipe-separated 字符串，其余命令保持向后兼容：

```
module call health health-check set {"pid":1234,"config":{"type":"http",...}}
```

服务端 `dispatchCommandLine()` 识别 `{` 前缀后切换到 JSON 解析路径，旧管道格式继续支持兼容期。

---

### 第三阶段：扩展性与部署增强（较大改动）

**目标**：支持更复杂的部署场景，为模块生态扩展提供更好的基础。

#### 3.8 模块 ABI v4 设计

当前 ABI v3 已满足大多数需求，v4 可在不破坏已有模块的前提下增加：

- **capability enforcement**：`PG_GetCapabilities()` 导出，`ModuleManager` 在 load 时校验，`module call` 时按 caller 来源和模块声明的 capability 做运行时鉴权。
- **结构化错误码**：`PG_Invoke` 返回 `int` 错误码 + `errorJson` 输出，不再只靠 `OK/ERR` 前缀字符串。
- **模块间依赖声明**：`module.manifest.json` 增加 `depends` 字段，`ModuleManager` 按依赖顺序加载。

#### 3.9 依赖管理规范化

- `nlohmann/json.hpp`、`sqlite3.h`（新增）统一放入 `third_party/` 目录并记录来源版本。
- Qt 和 MinGW 工具链版本通过 `tools/TOOLCHAIN_VERSIONS.txt` 明确记录，CI 缓存 key 从该文件 hash 推导，不再手工维护 `v5` 标签。
- 考虑引入 `vcpkg` 或 `CPM.cmake` 管理未来新增的 C++ 依赖，避免手工 vendor。

#### 3.10 配置文件统一化

目前运行态配置散落在多处：
- `pgs_guard_state.db`（守护列表 + token hash）
- `artifact_policy.cfg`（artifact 策略）
- `modules\notify\notify.cfg`（通知配置）
- `modules\sched\pgs_sched.db`（调度数据）
- `modules\profile\pgs_profiles.db`（策略 profile）

建议以 SQLite 为统一存储后端，各子系统使用不同的 table，共享事务和 WAL 日志，避免多个独立文件的 ACL 维护负担。

#### 3.11 支持多实例隔离运行

当前服务端口（12345）和状态目录（`C:\ProgramData\ProcessGuard`）是硬编码的单实例设计。若未来需要在同一台机器上运行多个 PGS 实例（如隔离不同租户的守护任务），需要：

- 端口和状态目录通过服务名参数化（当前已有 `--port` 支持，需补全数据目录参数）。
- Named Pipe 路径包含实例名。
- Cluster Dashboard 原生支持同机多实例。

---

## 四、实施建议

### 优先级矩阵

| 阶段 | 改进项 | 优先级 | 预估工作量 | 风险 |
|------|--------|--------|-----------|------|
| 一 | ArtifactStore 拆分 | P0 | 小 | 低 |
| 一 | HealthEngine 拆分 | P0 | 小 | 低 |
| 一 | pgs_bless.cpp 拆分 | P1 | 中 | 低 |
| 一 | 补子系统单元测试 | P1 | 中 | 低 |
| 一 | SQLite 状态文件迁移 | P1 | 中 | 中 |
| 二 | Named Pipe 传输层 | P0（安全） | 中 | 中 |
| 二 | 协议版本协商 | P2 | 小 | 低 |
| 二 | 命令参数结构化 | P2 | 中 | 低 |
| 三 | 模块 ABI v4 | P2 | 大 | 中 |
| 三 | 依赖管理规范化 | P1 | 小 | 低 |
| 三 | 配置文件统一化 | P2 | 大 | 中 |

### 操作原则

1. **先拆后改**：在修改行为之前先做结构拆分，每次拆分后运行完整 smoke 确认行为不变。
2. **兼容优先**：协议层改动必须保留旧格式的兼容期（至少一个 minor 版本），不强迫现有 CLI/UI 同步升级。
3. **测试先行**：新增子系统类时先写接口和测试，再实现，避免拆分过程引入回归。
4. **小批量提交**：每个拆分项作为独立 PR，方便 review 和回滚。

---

## 五、总结

PGS 的核心架构决策（Guard ID 抽象、IOCP 监控、C ABI 模块、隔离态）是扎实的，不需要推倒重来。当前最突出的架构债是 `PGS.cpp` 的职责膨胀，这是所有后续改进的基础前提。建议按照"先拆分子系统→再迁移状态存储→最后演进协议层"的顺序推进，每个阶段均可独立验收，不互相阻塞。最终目标是让每个子系统都可以独立理解、独立测试、独立替换，而不影响整体守护能力。
