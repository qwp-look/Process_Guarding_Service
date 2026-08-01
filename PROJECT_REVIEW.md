# Process_Guarding_Service 项目全面评审

> 评审时间：2026-07-27  
> 版本：0.1.0-beta.1  
> 评审者：Kiro（AI）

---

## 一、项目概述

PGS（Process Guarding Service）是一个 Windows 进程守护工具，以 Windows 服务形态运行，对目标进程实施持续监控和自动重启。项目由 `qwp-look` 和 AI 协作开发，目标用户是需要在 Windows 上无人值守运行后台程序、业务客户端或监控脚本的个人和企业。

### 核心能力矩阵

| 能力 | 状态 |
|------|------|
| 进程崩溃自动重启 | 已完成 |
| 服务重启后恢复守护列表 | 已完成 |
| Qt 桌面管理端 | 已完成 |
| Web 管理端 | 已完成 |
| Cluster Dashboard | 已完成 |
| 模块插件系统（16 个 bundled 模块） | 已完成 |
| 健康探针（process/TCP/HTTP） | 已完成 |
| ArtifactStore / OperationStore | 已完成 |
| WindowsApps/UWP 支持 | 代码已实现，真实环境待验证 |
| PPL（Protected Process Light）| 默认禁用，需 opt-in |
| 代码签名 | 未完成 |

---

## 二、技术架构评估

### 2.1 技术选型

**语言与标准**：C++17，配合 Windows Win32 API。选择合理——C++ 给了充分的系统级能力（Job Object、IOCP、WTS），C++17 的 STL 足以支撑这个规模的项目，不需要引入更重的框架。

**构建系统**：CMake（MinGW Makefiles）+ MSYS2/MinGW64 工具链。选择成熟，CMake 生成器和 CI 缓存策略设计合理。同时保留了 `build_pgs.bat`/`.sh` 两套脚本，照顾了 Windows 原生和 MSYS 两类开发者。

**UI**：Qt6（`qt6-base`、`qt6-httpserver`、`qt6-websockets`）。Qt 桌面端体验完善，Web 端直接用 Qt HttpServer 嵌入，避免引入独立 Node/Python 后端，减少部署复杂度，是合适的权衡。

**JSON 处理**：引入 `nlohmann/json.hpp`（单头文件）。这解决了安全文档里 P2-15 提到的旧"轻量字符串查找"解析的脆弱性问题，方向正确。不过从代码来看，`ModuleManager` 和 `PGSProtocol` 中仍有部分旧的 `jsonStringValue()` 辅助函数路径，迁移尚未全面完成。

### 2.2 核心架构设计

`PGS` 类是整个服务的核心，持有：

- **TCP 管理端点**（loopback 127.0.0.1:12345）
- **固定大小 Worker Pool**（4 个 client worker 线程）
- **监控线程**（`monitorLoop`）+ IOCP 事件驱动
- **健康探针线程**（`healthLoop`）
- **通知线程**（`notifyLoop`）
- **持久化归档**（tab 分隔文本，状态版本 v5）

**亮点设计**：

1. **Guard ID 而非 PID 作为逻辑身份**。进程重启后 PID 变化，但 `guardId` 不变，策略和计数器持续绑定在逻辑守护对象上。这是正确的抽象——大多数同类工具用 PID/路径做 key，会在多实例场景出错。

2. **Job Object + IOCP 双路径监控**。IOCP 作为快速唤醒路径，句柄轮询作为兜底，保证在 IOCP 投递失败时仍能检测进程退出。`kill-on-exit` 默认关闭，意味着 PGS 自身崩溃时守护进程可以继续存活并在服务重启后被重新接管，这是一个经过深思的设计决策。

3. **隔离态（Quarantine）机制**。守护对象重启失败后不直接从列表删除，而是进入 `quarantined` 状态，保留失败码和失败原因，等待人工干预。相较于"沉默丢弃"，可观测性大幅提升。

4. **模块 ABI 的 C 接口设计**。模块是 Windows DLL，导出 C ABI（`PG_Invoke` 等），通过 `LoadLibrary` 动态加载。C ABI 保证了 ABI 稳定性，不受 C++ name mangling、编译器版本影响。

**可改进点**：

- **协议层是裸 TCP 文本行**，认证是 token 信封（`token <base64-token> <command>`）。功能上可用，但安全文档 P1-06 已指出其局限：token 泄露后同机任意用户可调用管理 API。迁移到 Windows Named Pipe 可直接复用 OS 的用户身份/ACL 机制。
- **Worker Pool 固定 4 个线程**，对于管理型低并发场景完全够用，但没有动态扩缩能力。这不是问题，只是一个硬编码上限。
- **状态文件是 tab 分隔文本**，到 v5 已有不少字段。字段解析逻辑在 `PGS.cpp` 中手工完成，迁移到结构化格式（如 SQLite）会更健壮，但成本更高，当前规模下还不是瓶颈。

---

## 三、代码质量评估

### 3.1 整体质量

代码质量**中上**，整体逻辑清晰，关键路径有注释说明设计决策（而非仅描述行为）。例如 `PGS.h` 中 `guardId` 的注释解释了为什么不能用 PID/path 做 key，`killOnExit` 的注释解释了默认关闭的原因——这是有价值的注释，不是噪音。

### 3.2 主要优点

- **关注点分离清晰**：`pgs_service.cpp` 只做生命周期宿主（install/start/stop），所有守护逻辑在 `PGS` 类中，Console 模式和 SCM 模式共享同一套保护逻辑。
- **头文件接口设计节制**：`PGS.h` 中 private 区域的 helper 函数是 static，公有接口只暴露业务语义。
- **错误路径有 fail-closed 设计**：`modules.lock` 存在但损坏时不回退到 name-only allowlist；metadata id 不一致按 corrupt 处理；这是防御性编程的正确姿势。

### 3.3 主要问题

1. **`PGS.cpp` 文件必然巨大**。单类承载了 TCP 服务、守护逻辑、持久化、模块调用、健康探针、事件队列等所有职责。随着功能增加，可维护性会下降。当前阶段可接受，但这是明确的技术债。

2. **JSON 解析未完全迁移**。`nlohmann/json.hpp` 已引入，但安全文档 P2-15 明确提到旧的轻量字符串解析路径还没有全面替换。社区模块增多后，这个问题的风险权重会上升。

3. **状态文件手工序列化**。tab 分隔文本在 v5 已有约 20 个字段，每个字段都要手工 parse，错误处理散落在 `loadPersistedState()` 中。没有 schema 校验，字段顺序和缺省值靠代码约定维护。

4. **测试覆盖不均匀**。有 `test_pgs_core.cpp`、`test_module_manager.cpp`、`test_sched_cron.cpp` 三个单元测试文件，但主业务逻辑（守护/重启/隔离流程）的测试依赖 `PGS_ENABLE_TEST_HOOKS` 宏，大量逻辑通过集成 smoke 测试间接覆盖，不够精细。

---

## 四、功能完整性评估

### 4.1 核心守护功能

**完整**。`bless`/`unbless`/`bless-start`、重启策略（窗口、延迟、退避）、隔离态、Job Object 进程族管理均已实现并有 smoke 覆盖。

### 4.2 管理界面

- **CLI（pgs_bless）**：功能最完整，几乎所有操作都有对应命令。
- **Qt 桌面端**：守护列表、模块页、Scheduler、Health Policy、Doctor/Repair 页均已完成，可用性较高。
- **Web 管理端**：基础功能覆盖，Structured Result 区域已补，但浏览器 DOM 自动化测试仍缺失。
- **Cluster Dashboard**：节点 add/edit/test/remove、凭据保护、guard 详情已完成；真实 remote gateway 双节点联调仍待验收。

### 4.3 模块生态

16 个 bundled 模块覆盖面合理：调度（sched）、健康（health）、Profile、报告（report）、通知（notify）、指标（metrics）、备份（backup）、事件日志（eventlog）、Dump、服务守护（service_guard）、文件监视（file_watch）、策略模板（policy）、远程代理（remote_agent）、更新验证（update）、脚本运行（script_runner，默认禁用）、PPL。

**高风险模块的设计判断是正确的**：`dump` 需要 `--confirm`，`script_runner` 默认禁用、final-path 限制脚本目录并在运行前重验 SHA-256，`service_guard` mutation 需要 `confirm=1`、默认拒绝受保护服务并支持持久化 allowlist。这些设计是有意识的安全门槛，不是遗漏。

### 4.4 WindowsApps 支持

代码已实现（AUMID 推导、activation、注册），但真实 Store/UWP 环境验证尚未完成（P0-01、P0-02）。这是声明的已知限制，不是隐藏的 bug。

---

## 五、安全性评估

安全文档非常详尽，且对已完成和未完成项有清晰区分，说明安全意识是项目的一线关注，不是马后炮。

### 5.1 已解决的安全问题

| 问题 | 解决方案 |
|------|---------|
| Web 页面嵌入 API token | 改为 HttpOnly cookie + CSRF nonce |
| modules.lock 损坏回退到 name-only allowlist | fail-closed，空 allowlist 拒绝加载 |
| ArtifactStore metadata 不一致 | id/文件名不一致按 corrupt 处理 |
| permissive 模式无撤销路径 | 新增 `module permissive status/on/off`，开启需 `--confirm` |
| dump artifact 敏感度 | 标记 `sensitive=high`，TTL 裁剪到 6 小时 |
| script_runner 默认开放 | 默认禁用，run 需 `--confirm`，final-path 限制到服务数据目录，登记 hash 并运行前重验 |
| bootstrap token 文件 ACL（P0-04） | 写入/repair 用 `secureBootstrapTokenAcl`（SY+BA，无交互用户 ACE）；`doctor` 的 `bootstrap_token_acl` 只读诊断既有文件；单测 163/0 |

### 5.2 仍存在的安全风险

**P0 级（应优先处理）**：

- **管理协议是裸 loopback TCP + token**（P1-06）。token 泄露后同机任意用户可调用管理 API。Named Pipe + ACL 是更彻底的解法，但迁移成本不低。短期缓解：确保 state 目录 ACL 为 SYSTEM + Administrators。

**P1 级（下一轮安全专项）**：

- **代码签名未配置**（P1-10）。用户无法验证下载物来源，installer/exe/dll/sys 均未签名。这是公开发行前必须完成的。
- **模块目录 ACL 递归 fail-closed 已按验收修正落地**（P0-03）。真递归枚举、启动只 audit 不自动 repair、显式 repair 修 owner+DACL、嵌套路径单测与 smoke 显式 repair。剩余安装态/VM 非管理员负例。
- **bootstrap token ACL 提升权限/VM 专项验证**（P0-04 核心已完成）。剩余 elevated `test_bootstrap_token_acl.ps1` / 异常 ProgramData 与备份还原场景。
- **审计日志完整性**（P2-11）。当前 PGS events 是内存环，服务重启后丢失；Web remote audit 是 append 文本，可被本地管理员篡改。

**P2 级（加固/完善）**：

- capability policy 尚未端到端强制（P2-12）。
- JSON/manifest 解析未全面迁移到结构化 parser（P2-15）。
- Cluster 节点操作无独立审计事件（P2-12a）。

### 5.3 总体安全评级

**当前状态**：可用于受控内网环境和个人使用，不适合直接暴露到公网或作为高安全要求的生产基础设施。完成代码签名、Named Pipe 迁移、模块 ACL 递归验证后，安全等级可以显著提升。

---

## 六、测试与 CI/CD 评估

### 6.1 测试层次

| 层次 | 覆盖情况 |
|------|---------|
| 单元测试（CTest） | `test_pgs_core`、`test_module_manager`、`test_sched_cron`，覆盖基础逻辑 |
| 集成 smoke（MSYS shell） | `smoke_test_pgs.sh`，覆盖守护/重启/隔离/模块/artifact 主流程 |
| 健康探针负例 | TCP closed、HTTP 500 unexpected status 已覆盖 |
| 协议契约测试 | `protocol_contract.ps1`，轻量检测响应字段 |
| Release smoke | `release_smoke.ps1`，验证 installer/zip/manifest/SBOM 存在和运行 |
| 压力/长稳测试 | `pressure_pgs.ps1`、`long_stability.ps1` 已存在但**无基线** |
| Cluster API smoke | `cluster_api_smoke.ps1` 已补完 |
| VM E2E 验收 | `vm_acceptance.ps1` 已扩展，但**本轮未在真实 VM 运行** |
| UI 自动化 | **缺失**，无 Playwright/WinAppDriver 覆盖 |

### 6.2 CI/CD 流水线

GitHub Actions 流水线设计较完整：

```
checkout → 缓存 MinGW64 工具链 → 构建 C++ 核心+CLI → 
  单元测试 × 3 → smoke 测试 → Qt 桌面构建 → Qt Web 构建
```

**优点**：
- MinGW64 工具链有缓存策略（key: `msys2-mingw64-installed-v5`），减少 CI 时间。
- smoke 使用动态端口（`PGS_SMOKE_PORT`），避免端口冲突。
- publish workflow 生成 `SHA256SUMS.txt`、`release-manifest.json`、`sbom.spdx.json`，并请求 GitHub artifact attestation。

**不足**：
- 没有独立的 release smoke 步骤在 CI 中运行（只有 build + unit + smoke）。
- 没有安全扫描步骤（SAST/依赖扫描）。
- publish workflow 仍未经过真实 GitHub Release 验证。

---

## 七、文档质量评估

文档是这个项目的**显著亮点**之一。

按读者分群（普通用户/高级用户/开发者）组织，有明确的文档入口（`docs/INDEX.md`），架构文档、协议文档、安全交接文档、未完成功能交接文档分类清晰。

特别值得肯定的是两份"交接文档"：
- `docs/SECURITY_HARDENING_BACKLOG.md`：每个安全风险都有影响组件、当前行为、风险描述、建议修复、验证方式、优先级，是可以直接作为安全专项 Backlog 使用的。
- `docs/UNFINISHED_FEATURES_BACKLOG.md`：对每个未完成功能的状态、原因、下一步都有明确记录，并带时间戳，未来接手的人可以直接从这里继续。

这种文档习惯在个人/小团队项目中非常罕见，是值得保持的工程实践。

---

## 八、整体评价

### 8.1 优势

1. **架构核心设计扎实**：Guard ID 抽象、IOCP 驱动监控、隔离态机制、模块 C ABI 这四个核心设计决策都是经过深思的，不是堆砌功能。
2. **功能覆盖面合理**：16 个模块覆盖了监控、调度、报告、通知、备份等典型需求，没有过度扩张到系统已有能力的领域。
3. **安全意识贯穿始终**：高风险操作有 `--confirm` 门槛，默认 fail-closed，permissive 模式有显式撤销路径，dump 结果有 TTL 和敏感分类。
4. **文档质量高**：交接文档的完整性和可操作性是个人项目中少见的。
5. **CI 流水线基本完整**：构建、单元测试、集成 smoke、发布元数据生成均已自动化。

### 8.2 主要风险

1. **代码签名缺失**：这是公开发行前的硬阻塞项。没有签名的 installer/exe/DLL 会触发 Windows Defender 和 SmartScreen，对普通用户是明显的安装阻力，也是供应链完整性的缺口。
2. **管理协议的本地安全边界**：loopback TCP + token 足以防外部访问，但不足以做本机用户隔离。在多用户 Windows 服务器场景下，这是潜在的横向移动路径。
3. **PGS.cpp 的体量**：单文件承载过多职责，随着功能增长，可维护性和可测试性都会下降。建议逐步将 ArtifactStore、OperationStore、HealthLoop、NotifyLoop 抽出为独立类。
4. **压力/长稳测试无基线**：没有基准数据，就无法判断性能/稳定性回归。在公开 beta 之前应至少跑一次完整基线。

### 8.3 下一步优先级建议

| 优先级 | 任务 |
|--------|------|
| P0 | 代码签名配置 |
| P0 | 在真实管理员 VM 运行完整 `vm_acceptance.ps1` |
| P1 | bootstrap token ACL 提升权限/VM 专项验证（核心 P0-04 已完成） |
| P1 | 压力/长稳测试基线（`-Iterations 500`，`-Minutes 240`）|
| P1 | 模块目录 ACL 递归验证安装态/VM 负例（核心 fail-closed 已完成） |
| P1 | Named Pipe 传输层（替代或并行裸 TCP）|
| P1 | PGS.cpp 核心拆分（ArtifactStore、HealthEngine 抽出）|
| P2 | Playwright/DOM smoke（Web + Cluster UI）|
| P2 | JSON 解析全面迁移到 nlohmann/json |
| P2 | 完整 failure code taxonomy + failure history 持久化 |

---

## 九、结论

PGS 是一个**设计理念清晰、工程规范较高的 Windows 进程守护工具**。核心守护逻辑完整可用，模块生态有扩展空间，文档和交接材料完善，CI 基础扎实。当前的主要缺口是代码签名、管理协议安全层加固、以及部分高级场景（UWP/PPL）的真实环境验证。在个人或受控内网场景下，0.1.0-beta.1 已经具备实际使用价值；公开生产发行需要先完成上述 P0/P1 安全专项。
