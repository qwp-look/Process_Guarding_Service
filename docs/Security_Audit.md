# Security Audit

Scope: source-code-level review of Process_Guarding_Service.  
All findings are confirmed from source. No speculative issues are included.

2026-08-01 状态：本文件记录的 FIND-01..FIND-06 已在当前工作树完成代码修复并通过 CMake build / CTest 验证；条目正文保留为历史审计依据和回归测试参考。

---

## FIND-01 — Unicode 转换错误：`narrowToWideBestEffort` 逐字节零扩展

**Category**: Unicode / UTF-8 / UTF-16 转换错误  
**Severity**: High  
**File**: `include/Process_Guard/PGUtil.h:136`  
**Function**: `narrowToWideBestEffort`

### 源码

```cpp
// PGUtil.h:103-137 (return on line 136)
inline std::wstring narrowToWideBestEffort(const std::string &input)
{
    if (input.empty()) { ... }
    // MultiByteToWideChar path for valid UTF-8 ...
    // fallback:
    return std::wstring(input.begin(), input.end()); // line 136
}
```

### 为什么成立

C++ iterator 构造 `wstring(char_iter, char_iter)` 对每个 `char` 做零扩展转换，不做任何编码解析。UTF-8 双字节序列（如 `\xC3\xA9` = é）拆成两个 wchar_t（`U+00C3`, `U+00E9`）而非正确的 `U+00E9`。

### 受影响的调用点

| 文件 | 行 | 用途 |
|------|----|------|
| `tools/pgs_bless.cpp:366` | 启动路径转 wide |
| `tools/pgs_bless.cpp:395` | startArgs 转 wide |
| `tools/pgs_bless.cpp:562–563` | AUMID + WinApp 参数 |
| `tools/pgs_bless.cpp:885, 960, 1601, 1668` | 模块目录路径 |
| `include/Process_Guard/PGUtil.h:852` | `findAppxManifestForExecutable` |
| `include/Process_Guard/PGUtil.h:905, 927` | AppX manifest 解析 |

所有调用点均使用非 ASCII 路径或 AUMID 时静默产生错误的 wide 字符串，导致路径对比、文件操作或进程启动失败或绕过。

### 修复建议

移除 fallback 分支，或将其替换为 `MultiByteToWideChar(CP_UTF8, ...)` 调用（与函数体的主路径保持一致）。名称已暗示"best effort"，但当前 fallback 产生的结果比失败更危险。

---

## FIND-02 — Unicode 转换错误：`moduleDirOf` wchar_t 截断

**Category**: Unicode / UTF-8 / UTF-16 转换错误  
**Severity**: Medium  
**File**: `modules/sched/pgs_sched_module.cpp:623`  
**Function**: `moduleDirOf` (anonymous namespace)

### 源码

```cpp
// pgs_sched_module.cpp:615-624
std::string moduleDirOf(HMODULE self)
{
    wchar_t path[MAX_PATH] = {0};
    DWORD len = GetModuleFileNameW(self, path, MAX_PATH);
    if (len == 0 || len >= MAX_PATH) return "";
    std::wstring w(path);
    std::size_t slash = w.find_last_of(L"\\/");
    return (slash == std::wstring::npos)
        ? std::string(".")
        : std::string(w.begin(), w.begin() + slash); // line 623 — truncation
}
```

### 为什么成立

`std::string(wstring_iter, wstring_iter)` 将每个 `wchar_t` 截断为低 8 位。对于 ASCII 路径正确；一旦 DLL 安装在含非 ASCII 字符的目录下（如 `C:\用户\...`），`g_moduleDir` 存储的是损坏字符串，`dbPathFor()` 生成的 SQLite 路径无效，sched 模块无法持久化调度数据。

### 修复建议

```cpp
// 替换 line 623
int n = WideCharToMultiByte(CP_UTF8, 0, w.c_str(),
                             static_cast<int>(slash), nullptr, 0, nullptr, nullptr);
std::string out(n > 0 ? n : 0, '\0');
if (n > 0)
    WideCharToMultiByte(CP_UTF8, 0, w.c_str(), static_cast<int>(slash),
                        out.data(), n, nullptr, nullptr);
return out;
```

---

## FIND-03 — TOCTOU：`startSuspendedFromPath` 检查与启动之间的竞态

**Category**: TOCTOU  
**Severity**: Medium  
**File**: `src/service/PGSProtocol.cpp:539, 558`  
**Function**: `startSuspendedFromPath`

### 源码

```cpp
// PGSProtocol.cpp:531-558
std::vector<wchar_t> fullPathBuf(32768, L'\0');
GetFullPathNameW(rawPath.c_str(), ..., fullPathBuf.data(), nullptr); // line 532
const std::wstring fullPath(fullPathBuf.data(), fullLen);

const DWORD attr = GetFileAttributesW(fullPath.c_str()); // CHECK — line 539
if (attr == INVALID_FILE_ATTRIBUTES || (attr & FILE_ATTRIBUTE_DIRECTORY) != 0)
    ...  // reject

// ... build command line ...

CreateProcessW(nullptr, writable.data(), ...); // USE — line 558
```

### 为什么成立

`GetFullPathNameW` 展开相对路径和 `.`/`..` 分量，但**不解析符号链接或 junction**。若路径中某目录分量是 junction，攻击者可在 `GetFileAttributesW`（line 539）通过之后、`CreateProcessW`（line 558）执行之前，原子地重定向该 junction 到另一个目录，导致被启动的可执行文件与校验通过的文件不同。

注意：hash/签名校验在 ModuleManager 管道中进行，`startSuspendedFromPath` 本身无此校验，故这里的存在性/类型检查是唯一拦截点。

### 修复建议

在 `GetFileAttributesW` 之后、`CreateProcessW` 之前，用 `CreateFile` 打开文件句柄，再以 `GetFinalPathNameByHandleW` 获取真实路径，将 `CreateProcessW` 的第一参数（`lpApplicationName`）设为该真实路径，而非仅依赖命令行字符串。

---

## FIND-04 — Lifetime Bug：`getDataDirThunk` 返回指向可变 `thread_local` 字符串的裸指针

**Category**: Lifetime Bug / Use After Free (逻辑)  
**Severity**: Medium  
**File**: `src/service/PGS.cpp` (approx. lines 3314–3328)  
**Function**: `PGS::getDataDirThunk`

### 源码

```cpp
const char *PGS::getDataDirThunk(void *context)
{
    PGS *self = static_cast<PGS *>(context);
    static thread_local std::string dir;       // 每次调用重新赋值
    dir = std::filesystem::path(self->m_stateFilePath)
              .parent_path().string();
    return dir.c_str();   // 指针在下次赋值后失效
}
```

### 为什么成立

C++ 标准保证 `c_str()` 返回的指针仅在对同一 `string` 对象的下一次修改操作之前有效（`[string.accessors]`）。`dir = ...` 赋值可能重新分配内部缓冲区。若已加载的模块：

1. 调用 `get_data_dir()` 获得指针 `p`
2. 在同一线程上再次触发任何调用 `getDataDirThunk` 的路径（如通过回调链）
3. 然后解引用 `p`

则 `p` 已指向已释放或被覆盖的内存。

### 修复建议

```cpp
const char *PGS::getDataDirThunk(void *context)
{
    PGS *self = static_cast<PGS *>(context);
    // 返回指向生命周期稳定的成员字符串，而非每次重建的 thread_local
    return self->m_dataDirCache.c_str(); // 在 initialize() 时一次性设置
}
```
即在 `PGS::initialize()` 阶段一次性计算并存入成员变量 `m_dataDirCache`，`getDataDirThunk` 仅返回其 `c_str()`。

---

## FIND-05 — Unicode 错误：`installService` 使用 `GetModuleFileNameA` 注册服务路径

**Category**: Unicode / UTF-8 / 路径规范化错误  
**Severity**: Medium  
**File**: `src/service/pgs_service.cpp:158–160`  
**Function**: `PGSServiceHost::installService`

### 源码

```cpp
// pgs_service.cpp:158-160
char exePath[MAX_PATH]{};
GetModuleFileNameA(nullptr, exePath, MAX_PATH);
std::string binPath = "\"" + std::string(exePath) + "\" --service";
```

`binPath` 随后传入 `CreateServiceA(...)` 作为服务可执行路径。

### 为什么成立

`GetModuleFileNameA` 将真实 wide 路径转换为当前 ANSI 代码页。凡是代码页无法表示的字符（任何非 ASCII 字符，以及 ANSI 代码页以外的字符）都会被替换为 `?`，产生无效路径。SCM 随后将以该损坏路径启动服务，导致服务启动失败。此外，`MAX_PATH` 限制无法处理含 `\\?\` 扩展路径的安装目录。

### 修复建议

```cpp
wchar_t exePathW[32768]{};
GetModuleFileNameW(nullptr, exePathW, 32768);
// 转 UTF-8 或直接使用 CreateServiceW
std::wstring binPathW = L"\"" + std::wstring(exePathW) + L"\" --service";
CreateServiceW(scm, ..., binPathW.c_str(), ...);
```

---

## FIND-06 — Integer Overflow：无限重启模式下 `restartCount` 无上界递增

**Category**: Integer Overflow  
**Severity**: Low  
**File**: `src/service/PGS.cpp:3899`  
**Function**: `PGS::recordRestartAndEffectiveCount`

### 源码

```cpp
// PGS.cpp:3888-3901
int PGS::recordRestartAndEffectiveCount(..., RestartPolicyState &policy, int windowSec)
{
    ...
    if (windowSec > 0) { /* 滑动窗口路径，安全 */ }
    ++policy.restartCount;   // line 3899 — 无上界
    return policy.restartCount;
}
```

`policy.restartCount` 类型为 `int`。当 `maxRestarts < 0`（无限重启）且非滑动窗口模式时，该值每次重启递增，无任何饱和处理。

### 为什么成立

加载时有截断保护（`PGS.cpp:1364–1365`）：
```cpp
policy.restartCount = static_cast<int>(
    std::min<uint64_t>(count, (uint64_t)INT_MAX));
```
但运行时递增路径缺少同等保护。`INT_MAX` 次重启后（约 2.1 × 10⁹），有符号整数溢出为 C++ 未定义行为。实际可达性极低，但与加载时的防护逻辑不一致。

### 修复建议

```cpp
if (policy.restartCount < std::numeric_limits<int>::max())
    ++policy.restartCount;
```

---

*文档生成时间: 2026-07-27。所有结论均来自源码，无推断。*
