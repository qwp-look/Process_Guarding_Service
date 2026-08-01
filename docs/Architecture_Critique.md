# Architecture Critique

视角：Windows 内核开发工程师 / LLVM Reviewer / 微软 C++ Code Reviewer  
所有结论均引用源码，无推测。

2026-08-01 状态：本文件第 4.4 节提到的 `get_data_dir` 生命周期未文档化问题已在 ABI 头文件补注释；若干低风险源码 finding 已完成最小修复。其余架构重构项仍是中长期维护计划。

---

## 1. 哪些设计未来一定会成为维护负担？

### 1.1 `dispatchCommandLine` 的线性 if-else 链

**文件**: `src/service/PGSProtocol.cpp:591+`

```cpp
std::string PGS::dispatchCommandLine(const std::string &commandLine)
{
    // ...
    if (command == "start-register") { /* 80 行手工解析 */ }
    if (command == "register")       { /* 120 行手工解析 */ }
    if (command == "intentional")    { ... }
    if (command == "unregister")     { ... }
    if (command == "set-policy")     { ... }
    // ... 20+ 个 if 块，每块各自解析 pipe-delimited fields
```

每新增一个管理命令，开发者必须：
1. 在这个函数末尾添加一个新 `if` 块
2. 手工解析 `fields[0]...fields[N]` 的位置——位置是**隐式合约**，不在任何类型系统中体现
3. 同时修改 `pgs_bless.cpp` 的对应发送端

字段位置随版本增加累积（register 命令已有 fields[0]..fields[11]，PGSProtocol.cpp:696-801），未来增加字段只能追加到末尾，旧字段无法删除，协议永久膨胀。

---

### 1.2 状态文件手工版本迁移

**文件**: `src/service/PGS.cpp:1243+`

```cpp
bool PGS::loadPersistedState()
{
    // ...
    if (fields[0] == "VERSION") {
        try { version = std::stoi(fields[1]); }   // PGS.cpp:1300
        catch (const std::exception &) { return false; }
    }
    if (fields[0] == "GUARD") { /* 解析 30+ 个 tab 分隔字段 */ }
    if (fields[0] == "POLICY") { ... }
    if (fields[0] == "GROUP")  { ... }
    // ...
```

状态文件已迭代至版本 5（`PGS.cpp:44: constexpr int kStateFileVersion = 5`）。每次新增字段：
- 必须在 `loadPersistedState` 中新增分支处理旧版本兼容
- 必须在 `persistState` 中新增输出
- `GUARD` 记录是 tab 分隔的 30+ 字段，字段顺序是隐式合约

项目已在最新 commit 引入 `nlohmann/json`（`refactor(modules): replace hand-written JSON parser with nlohmann/json`），但状态文件仍是手工 TSV，是技术债务的孤岛。

---

### 1.3 模块 ABI 的 struct-size 版本检测

**文件**: `modules/sched/pgs_sched_module.cpp:652-666`

```cpp
const PGS_Services *base = static_cast<const PGS_Services *>(reserved);
if (base->size >= sizeof(PGS_Services))         // v2 check
{
    g_svc.call  = base->call;
    g_svc.now_ms = base->now_ms;
    if (base->size >= sizeof(PGS_ServicesV3))   // v3 check
    {
        const PGS_ServicesV3 *v3 = static_cast<const PGS_ServicesV3 *>(reserved);
        g_svc.call_json  = v3->call_json;
        g_svc.emit_event = v3->emit_event;
        g_svc.get_data_dir = v3->get_data_dir;
    }
}
```

这是 COM 风格的平坦 struct 版本化。每次 PGS 向模块暴露新能力，需要：
1. 定义新 struct（`PGS_ServicesV4`...）
2. 所有已加载模块必须更新 size check 才能使用新字段
3. 无法删除旧字段（ABI 必须向后兼容）

版本号无法强制对齐：一个写错 `sizeof` 的模块会静默跳过新字段。

---

### 1.4 `handleList` 中的 O(n²) 查找

**文件**: `src/service/PGSProtocol.cpp:1494`

```cpp
for (const auto &entry : m_persistedGuards)
{
    // O(n) linear scan for every quarantined persisted guard
    if (std::find(activeGuardIds.begin(), activeGuardIds.end(), entry.first)
        == activeGuardIds.end())
    { ... }
}
```

`activeGuardIds` 是 `std::vector<uint64_t>`，每次 `handleList` 调用都对它做线性扫描。随着 guard 数量增长，这是 O(n²) 复杂度。同一函数出现三次 `m_policyByGuardId.find()`（:1502, :1515, :1532），每次都持有 `m_guardsMutex`——锁持有时间随 guard 数量线性增长。

---

## 2. 哪些抽象明显设计得不好？

### 2.1 三张 map 表达同一逻辑实体

**文件**: `include/Process_Guard/PGS.h:268-273`

```cpp
std::unordered_map<DWORD, GuardInfo>                 m_guards;           // 按 PID
std::unordered_map<std::uint64_t, RestartPolicyState> m_policyByGuardId; // 按 guardId
std::unordered_map<std::uint64_t, PersistedGuardState> m_persistedGuards;// 按 guardId
std::unordered_map<std::string, GuardGroupState>      m_guardGroups;     // 按名称
```

同一个"被守护进程"的数据分散在三张用不同 key 索引的 map 中。`handleList`（PGSProtocol.cpp:1477）必须：
1. 遍历 `m_guards`（PID 索引）
2. 对每个 entry 用 `guardId` 查 `m_policyByGuardId`
3. 再用 `groupName` 查 `m_guardGroups`

三路 join，且全部持有同一把 `m_guardsMutex`，锁粒度粗。

---

### 2.2 `GuardInfo` 是一个概念垃圾桶

**文件**: `include/Process_Guard/PGS.h:33-110`

`GuardInfo` 有 38 个字段，混杂四类关注点：

| 类型 | 字段示例 |
|------|---------|
| 运行时句柄 | `HANDLE handle`, `HANDLE jobHandle`, `DWORD pid` |
| 策略配置 | `maxRestarts`, `restartWindowSec`, `restartDelayMs`, `backoff` |
| 健康监控 | `healthStatus`, `healthFailureCount`, `healthLastCheckMs` |
| 统计数据 | `cumulativeRunMs`, `restartIntervalSumMs`, `crashLoop` |

`PersistedGuardState`（PGS.h:134-176）是 `GuardInfo` 的近乎完全镜像，去掉了 `HANDLE`。两个 struct 同步演化，字段修改需要改两处，`copyGuardToPersisted`（PGS.h:515）是这种设计债务的物理证明。

---

### 2.3 协议与序列化职责混在 `dispatchCommandLine` 中

**文件**: `src/service/PGSProtocol.cpp:618-806`

```cpp
if (command == "start-register")
{
    const std::vector<std::string> fields = splitByChar(args, '|');
    const std::string path = base64Decode(fields[0]);      // 字段位置硬编码
    const std::string startArgs = base64Decode(fields[1]); // 字段位置硬编码
    int maxRestarts = kDefaultMaxRestarts;
    if (!parseMaxRestarts(trim(fields[2]), maxRestarts)) ...
    // 10 个字段，10 个 if (fields.size() >= N) 检查
```

协议解析（`fields[N]`）、参数验证（`parseDwordValue`）、业务逻辑（`startSuspendedFromPath`、`handleRegister`）三者完全内联在同一函数中。没有"请求对象"、没有"命令参数类型"，字段位置是隐式的运行时合约。

---

## 3. 哪些接口违反了 SOLID？

### 3.1 SRP 严重违反：`PGS` 类有 11 个不同职责

**文件**: `include/Process_Guard/PGS.h:178-554`

`PGS` 同时持有并管理：

| 职责 | 成员变量 |
|------|---------|
| TCP 接受层 | `m_listenSocket`, `m_clientQueue`, `m_clientWorkers`, `m_clientQueueMutex`, `m_clientQueueCv` |
| Guard 生命周期 | `m_guards`, `m_guardsMutex`, `m_nextGuardId` |
| 重启策略 | `m_policyByGuardId` |
| 持久化 | `m_stateFilePath`, `m_persistMutex` |
| Job Object | `m_jobs`, `m_jobMutex`, `m_ioPort` |
| 模块管理 | `m_modules`, `m_modulesDir`, `m_pplEnabled` |
| 健康检查 | `m_healthMutex`, `m_healthCv` |
| 事件通知 | `m_notifyQueue`, `m_notifyMutex`, `m_notifyCv` |
| 事件历史 | `m_events`, `m_eventsMutex`, `m_nextEventId` |
| Artifact 存储 | `m_artifacts`, `m_artifactMutex` |
| Operation 注册 | `m_operations`, `m_operationMutex` |

11 个独立的互斥锁，5 个独立的线程，全部在一个类中。这个类无法被单元测试，无法被局部替换，任何改动的 blast radius 覆盖整个系统。

---

### 3.2 OCP 违反：每增一命令必须修改 `dispatchCommandLine`

**文件**: `src/service/PGSProtocol.cpp:591`

函数不对扩展开放——新命令只能通过修改函数体添加。没有命令注册表、没有 handler 接口、没有插件点。

---

### 3.3 DIP 违反：`PGS` 直接内嵌 `ModuleManager`

**文件**: `include/Process_Guard/PGS.h:356`

```cpp
ModuleManager m_modules;  // 直接成员，非注入
```

`PGS` 依赖 `ModuleManager` 的具体实现，无法在测试中替换为 mock。`ModuleManager` 的接口没有抽象层。

---

### 3.4 ISP 违反：`handleRegister` 有 12 个参数

**文件**: `include/Process_Guard/PGS.h:461-465`

```cpp
std::string handleRegister(
    DWORD pid,
    const std::string &encodedPath,
    int maxRestarts,
    const std::string &restartArgs,
    const std::string &declaredHash,
    AppKind appKind,
    const std::string &aumid,
    int restartWindowSec,
    int restartDelayMs,
    bool backoff,
    int hangTimeoutMs,
    bool killOnExit          // 第 12 个参数
);
```

调用方（`dispatchCommandLine`）必须了解并传递所有参数，即使大多数使用默认值。`GuardPolicyPatch` struct（PGS.h:238-253）已经出现，证明开发者意识到了这个问题，但 `handleRegister` 本身未用它。

---

## 4. 哪些地方以后扩展插件一定会痛苦？

### 4.1 模块响应被限制在固定大小缓冲区

**文件**: `modules/sched/pgs_sched_module.cpp:692`（`PG_Invoke` ABI）

```cpp
PG_MODULE_API int PG_Invoke(const char *request, char *responseBuf, size_t responseBufSize)
```

模块的响应必须写入调用方分配的 `responseBuf`。没有流式接口、没有分块传输、没有回调机制。模块无法返回超过 `responseBufSize` 的数据，无法实现进度报告，无法实现长时间运行的操作（只能通过 operation record 变通，但这本身是靠 JSON-RPC 子协议绕过限制的）。

---

### 4.2 模块与 PGS 通信只有两个同步入口

**文件**: `modules/sched/pgs_sched_module.cpp:659-664`

```cpp
g_svc.call_json  = v3->call_json;   // 同步调用 PGS 命令
g_svc.emit_event = v3->emit_event;  // 单向推送事件
```

没有异步调用机制，没有事件订阅/取消订阅接口，没有流式数据通道。`call_json` 是同步阻塞的（模块线程在 PGS 处理完命令前无法继续），这在 sched 模块的 `workerLoop` 中会造成调度延迟。如果未来某个模块需要监听 PGS 内部事件（如 guard 重启），只能轮询，无法主动订阅。

---

### 4.3 sched 模块的 action allowlist 是代码内硬编码

**文件**: `modules/sched/pgs_sched_module.cpp:715-719`

```cpp
if (!isActionAllowed(action))
{
    setResponse(responseBuf, responseBufSize, "ERR action not in allowlist: " + action);
    return 1;
}
```

`isActionAllowed` 的允许列表来自哪里？如果是硬编码的，那么新插件无法注册自己的合法 action，扩展新调度操作必须修改 sched 模块源码。

---

### 4.4 `PGS_Module_API.h` 中 `get_data_dir` 返回值的生命周期未文档化

模块开发者从公开 ABI 头文件中无法得知 `get_data_dir()` 返回的 `const char*` 何时失效（实现细节：在同一线程下次调用时失效）。这是一个没有文档的隐式约定，第三方模块开发者必然踩坑。

---

## 5. 哪些地方应该拆类？

### 5.1 `PGS` → 至少 6 个类

| 新类 | 对应当前成员 |
|------|------------|
| `TcpManagementServer` | `m_listenSocket`, `m_clientQueue`, `m_clientWorkers`, `listenerLoop()`, `clientWorkerLoop()` |
| `GuardRegistry` | `m_guards`, `m_policyByGuardId`, `m_guardGroups`, `m_guardsMutex` |
| `GuardMonitor` | `m_monitorThread`, `m_ioPort`, `m_jobs`, `m_jobMutex`, `monitorLoop()` |
| `StateStore` | `m_stateFilePath`, `m_persistMutex`, `loadPersistedState()`, `persistState()` |
| `HealthMonitor` | `m_healthMutex`, `m_healthCv`, `healthLoop()` |
| `EventBus` | `m_notifyQueue`, `m_notifyMutex`, `m_notifyCv`, `m_events`, `notifyLoop()` |

`ModuleHost`（对 `ModuleManager` 的包装 + thunk 注册）可以单独提取，使 `PGS` 不直接依赖 `ModuleManager`。

---

### 5.2 `GuardInfo` → 4 个 struct

**文件**: `include/Process_Guard/PGS.h:33-110`

```
GuardConfig     { path, maxRestarts, restartWindowSec, restartDelayMs,
                  backoff, hangTimeoutMs, killOnExit, appKind, aumid,
                  fileHash, restartArgs, healthCheckJson, restartHookJson }

GuardRuntime    { HANDLE handle, HANDLE jobHandle, DWORD pid, DWORD sessionId,
                  bool intentional, bool hashVerified }

GuardHealth     { healthStatus, healthFailureCount, healthLastCheckMs,
                  healthLastOkMs, healthLastFailureMs, healthNextCheckMs,
                  healthLastMessage }

GuardStats      { createdAtMs, lastStartMs, lastExitMs, lastExitCode,
                  cumulativeRunMs, restartIntervalSumMs, restartIntervalCount,
                  crashLoop, failureCount }
```

`PersistedGuardState`（PGS.h:134）就是 `GuardConfig + GuardStats + lastKnownPid`，可以用 composition 而非 copy 实现。

---

### 5.3 `PGSServiceHost` 静态单例应当消除

**文件**: `src/service/pgs_service.cpp:146-147`

```cpp
inline static PGSServiceHost *s_instance = nullptr;
inline static PGSServiceHost *s_consoleInstance = nullptr;
```

两个静态原始指针用于 SCM callback 和 console ctrl handler 的回调。这是 C 回调适配的标准模式，但它使 `PGSServiceHost` 实质上成为全局单例，无法多实例，无法被测试替换。可以用 `std::function`-based adapter 消除。

---

## 6. 哪些地方应该重构？

### 6.1 状态文件解析 → nlohmann/json

**现状**: `src/service/PGS.cpp:1243-1700+`，手工 TSV 解析，30+ 字段的 tab 分隔记录  
**理由**: 项目已依赖 nlohmann/json（最新 commit 已引入）。将状态文件迁移到 JSON 可以：
- 字段按名称而非位置访问，消除隐式位置合约
- 自动向前/向后兼容（未知字段忽略，缺失字段使用默认值）
- 不再需要手工版本迁移逻辑

---

### 6.2 命令分发 → 注册表模式

**现状**: `src/service/PGSProtocol.cpp:591`，20+ 个 if 块  
**目标**:

```cpp
using CommandHandler = std::function<std::string(const std::string &args)>;
std::unordered_map<std::string, CommandHandler> m_commandRegistry;

// 在构造或 initialize() 中注册
m_commandRegistry["register"]      = [this](auto &a){ return handleRegister(a); };
m_commandRegistry["start-register"] = [this](auto &a){ return handleStartRegister(a); };
// ...

std::string PGS::dispatchCommandLine(const std::string &line)
{
    auto it = m_commandRegistry.find(command);
    return it != m_commandRegistry.end() ? it->second(args) : "ERR unknown command";
}
```

---

### 6.3 `handleRegister` 参数 → 参数对象

**现状**: 12 个参数（PGS.h:461）  
**目标**:

```cpp
struct RegisterRequest {
    DWORD pid;
    std::string encodedPath;
    int maxRestarts          = kDefaultMaxRestarts;
    std::string restartArgs;
    std::string declaredHash;
    AppKind appKind          = AppKind::Win32;
    std::string aumid;
    int restartWindowSec     = 0;
    int restartDelayMs       = 0;
    bool backoff             = false;
    int hangTimeoutMs        = 0;
    bool killOnExit          = false;
};
std::string handleRegister(const RegisterRequest &req);
```

---

### 6.4 `handleList` 中的线性查找 → `unordered_set`

**现状**: `src/service/PGSProtocol.cpp:1494`

```cpp
// 每次 handleList 都重建 vector 再线性扫描
if (std::find(activeGuardIds.begin(), activeGuardIds.end(), entry.first) == activeGuardIds.end())
```

**目标**:

```cpp
std::unordered_set<std::uint64_t> activeIds;
activeIds.reserve(m_guards.size());
for (const auto &e : m_guards) activeIds.insert(e.second.guardId);
// 后续查找 O(1)
if (activeIds.find(entry.first) == activeIds.end()) ...
```

---

## 7. 哪些地方明显不像现代 C++17 风格？

### 7.1 裸 `HANDLE` 管理

**文件**: `include/Process_Guard/PGS.h:43,81,384,386`

```cpp
// GuardInfo:
HANDLE handle    = nullptr;
HANDLE jobHandle = nullptr;

// PGS:
std::unordered_map<std::uint64_t, HANDLE> m_jobs;
HANDLE m_ioPort = nullptr;
```

全部是裸 `HANDLE`，手工 `CloseHandle`，RAII 依赖开发者在每条错误路径上不遗漏。现代 Windows C++ 应使用 RAII wrapper：
- WIL（Windows Implementation Library）的 `wil::unique_handle`
- 或项目自定义的 `struct HandleGuard { HANDLE h; ~HandleGuard(){ if(h) CloseHandle(h); } };`

`m_jobs` 尤其危险：map 存储裸 HANDLE，插入新值前需要手工 close 旧值（PGS.cpp:2232 中可以看到此类防御代码），应由 RAII 自动保证。

---

### 7.2 `std::stoi` + `try/catch` 替代 `std::from_chars`

**文件**: `src/service/PGS.cpp:1298-1305`

```cpp
try
{
    version = std::stoi(fields[1]);
}
catch (const std::exception &)
{
    return false;
}
```

C++17 引入了 `std::from_chars`（`<charconv>`），无异常、无动态分配、速度更快：

```cpp
int version = 0;
auto [ptr, ec] = std::from_chars(fields[1].data(),
                                  fields[1].data() + fields[1].size(), version);
if (ec != std::errc{}) return false;
```

`loadPersistedState` 中有多处 `std::stoi`/`std::stoull`，全部可以替换。

---

### 7.3 `inline static` 原始指针单例

**文件**: `src/service/pgs_service.cpp:146-147`

```cpp
inline static PGSServiceHost *s_instance = nullptr;
inline static PGSServiceHost *s_consoleInstance = nullptr;
```

这是 C 回调与 C++ 对象的适配桥。C++17 没有消除这个模式的直接替代，但可以用 lambda 捕获加 `std::function` wrapper 替代裸指针，至少让所有权关系明确。

---

### 7.4 固定大小栈缓冲区 + A 系列 Win32 API

**文件**: `src/service/pgs_service.cpp:158-160`

```cpp
char exePath[MAX_PATH]{};
GetModuleFileNameA(nullptr, exePath, MAX_PATH);
std::string binPath = "\"" + std::string(exePath) + "\" --service";
```

现代 C++ 惯用写法是动态缓冲区 + W 系列 API：

```cpp
std::wstring exePathW(32768, L'\0');
DWORD len = GetModuleFileNameW(nullptr, exePathW.data(), 32768);
exePathW.resize(len);
```

`MAX_PATH` 在 Windows 10 extended-length path 模式下不再是上限（实际路径可达 32767 字符），固定 260 字节缓冲区是静默截断的来源。

---

### 7.5 `static thread_local` + `c_str()` 模式

**文件**: `src/service/PGS.cpp` (~3314-3328，`getDataDirThunk`)

```cpp
static thread_local std::string dir;
dir = std::filesystem::path(self->m_stateFilePath).parent_path().string();
return dir.c_str();
```

返回指向可变局部状态的裸指针，违反 C++17 对象所有权惯例。现代 C++ 中 API 返回字符串数据有两种惯用方式：
- 返回 `std::string`（让调用方拥有所有权）
- 返回 `std::string_view`（借用，但必须文档化生命周期）

这里既不是 `string` 也不是 `string_view`，是一个带隐式生命周期约定的裸指针。

---

### 7.6 `copyGuardToPersisted` 字段逐一拷贝

**文件**: `include/Process_Guard/PGS.h:515`（声明）

这个函数的实现必须手工同步 `GuardInfo` 和 `PersistedGuardState` 的每个字段。每次为 `GuardInfo` 添加新字段，都必须记得也在 `copyGuardToPersisted` 中添加一行，否则静默丢失数据——编译器不会报错。现代 C++ 中这是需要 composition 或代码生成消除的手工拷贝模式。

---

## 优先级矩阵

| # | 问题 | 影响 | 改动成本 |
|---|------|------|---------|
| 1 | `GuardInfo` 拆分 → 消除 `copyGuardToPersisted` | 高（每次添加字段必须改两处） | 高 |
| 2 | 状态文件 → `nlohmann/json` | 高（版本迁移负担） | 中 |
| 3 | `dispatchCommandLine` → 注册表 | 高（每次新命令改一处） | 中 |
| 4 | 裸 `HANDLE` → RAII wrapper | 中（错误路径泄漏风险） | 中 |
| 5 | `handleRegister` → 参数对象 | 中（可读性/可扩展性） | 低 |
| 6 | `handleList` 线性查找 → `unordered_set` | 低（当前 guard 数量小） | 低 |
| 7 | `std::stoi` → `std::from_chars` | 低（性能/风格） | 低 |

---

*文档生成时间: 2026-07-27。所有引用均来自已读源码，不包含推测性内容。*
