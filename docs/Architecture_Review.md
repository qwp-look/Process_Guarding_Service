# Architecture Review

Scope: design-level analysis of confirmed source-code bugs in Process_Guarding_Service.  
Every section maps 1:1 to a finding in `Security_Audit.md`. No new issues are introduced.

2026-08-01 状态：与 `Security_Audit.md` 对应的 6 个源码 finding 已完成最小修复；本文保留原始架构分析，后续重点转向统一 helper、Named Pipe、模块 ACL 和结构化解析等未完成安全项。

---

## 1. Wide/Narrow 字符串转换策略不一致

**对应**: FIND-01 (`PGUtil.h:136`) + FIND-02 (`pgs_sched_module.cpp:623`) + FIND-05 (`pgs_service.cpp:159`)

### 问题描述

项目中存在三条独立的 wide↔narrow 转换路径：

| 路径 | 位置 | 正确性 |
|------|------|--------|
| `utf8ToWide` / `wideToUtf8`（`MultiByteToWideChar` / `WideCharToMultiByte`） | `PGUtil.h` 主路径 | 正确 |
| `narrowToWideBestEffort` fallback | `PGUtil.h:136` | 错误：零扩展 |
| `moduleDirOf` 返回值 | `pgs_sched_module.cpp:623` | 错误：`wchar_t` 截断 |
| `GetModuleFileNameA` + `CreateServiceA` | `pgs_service.cpp:159` | 错误：ANSI 代码页 |

根本原因是没有一个统一的"边界层"规定所有 Win32 调用必须使用 W 系列 API，narrow 字符串在内部始终为 UTF-8。这三处错误是相同根因的三次独立体现。

### 架构建议

1. 在项目中建立规则：**所有 Win32 API 调用使用 W 系列**，narrow 字符串仅在 I/O 边界（TCP 协议、日志）出现。
2. 删除 `narrowToWideBestEffort` 的 fallback 分支（`PGUtil.h:136`），在无法转换时返回空字符串并报错，而非静默产生错误结果。
3. `moduleDirOf`（`pgs_sched_module.cpp:623`）应改用 `WideCharToMultiByte(CP_UTF8, ...)` 与项目主路径对齐，或直接持有 `std::wstring` 类型的 `g_moduleDir`。
4. `installService`（`pgs_service.cpp:159`）改用 `GetModuleFileNameW` + `CreateServiceW`，彻底消除 ANSI 代码页依赖。

---

## 2. 模块回调 ABI 中裸指针的生命周期契约未定义

**对应**: FIND-04 (`PGS.cpp` ~3314–3328)

### 问题描述

`PGS_ServicesV3::get_data_dir` 回调的返回类型是 `const char *`。`getDataDirThunk` 的实现：

```cpp
static thread_local std::string dir;
dir = ...;          // 每次调用重新赋值，可能重新分配缓冲区
return dir.c_str(); // 调用方收到的指针生命周期仅至下次赋值
```

ABI 头文件（`PGS_Module_API.h`）中**未文档化该指针的生命周期**。模块开发者无从得知指针何时失效。

### 架构建议

有两种可行设计方向：

**方向 A（最小改动）** — 固定生命周期  
在 `PGS::initialize()` 时计算 `m_dataDirCache`（`std::string` 成员），`getDataDirThunk` 直接返回 `m_dataDirCache.c_str()`。指针与 PGS 实例同寿命。在 ABI 注释中记录："指针在 `PG_Shutdown` 调用之前有效"。

**方向 B（更安全）** — 将字符串所有权转移给调用方  
将回调签名改为调用方提供缓冲区：
```c
typedef int (*PG_GetDataDir)(void *context, char *buf, size_t bufLen);
```
消除裸指针所有权歧义，代价是 ABI 版本升级（需要 v4）。

无论选哪个方向，都应在 `PGS_Module_API.h` 中明确注释指针的有效范围。

---

## 3. 可执行文件启动路径缺少符号链接解析

**对应**: FIND-03 (`PGSProtocol.cpp:539, 558`)

### 问题描述

`startSuspendedFromPath` 使用 `GetFullPathNameW` 规范化路径，然后：

1. `GetFileAttributesW(fullPath)` — 校验文件存在且非目录
2. `CreateProcessW(nullptr, command, ...)` — 启动进程

`GetFullPathNameW` 不解析 junction 或符号链接。若路径中包含 junction，两次调用之间存在 TOCTOU 窗口。

更深层的设计问题是：`startSuspendedFromPath` 承担了两个职责——路径校验和进程创建，但两者之间没有原子保证。

### 架构建议

将路径解析与进程创建合并为原子操作：

```
CreateFile(fullPath, GENERIC_READ, FILE_SHARE_READ, ...)
  → GetFinalPathNameByHandleW(handle, ...)   // 获取真实路径，解析所有 junction/symlink
  → CreateProcessW(realPath, command, ...)   // lpApplicationName = realPath（不依赖命令行解析）
  → CloseHandle(fileHandle)
```

将 `lpApplicationName`（第一参数）设为真实路径，`lpCommandLine` 中的可执行名仅用于 `argv[0]`，避免 Windows 重新解析命令行中的路径。

---

## 4. `restartCount` 饱和处理不一致

**对应**: FIND-06 (`PGS.cpp:3899`)

### 问题描述

加载持久化状态时有饱和截断（`PGS.cpp:1364–1365`）：
```cpp
policy.restartCount = static_cast<int>(
    std::min<uint64_t>(count, (uint64_t)INT_MAX));
```

运行时递增路径（`PGS.cpp:3899`）无对应保护：
```cpp
++policy.restartCount;
```

防护逻辑只覆盖了加载路径，遗漏了运行时路径，两者不对称。

### 架构建议

在 `recordRestartAndEffectiveCount` 中补充饱和递增：
```cpp
if (policy.restartCount < std::numeric_limits<int>::max())
    ++policy.restartCount;
```

若需更系统的方案，将 `restartCount` 类型改为 `uint32_t`（与持久化格式的 `uint64_t` 对齐），并在比较 `maxRestarts` 时使用 `static_cast`，消除有符号/无符号混合比较。

---

## 优先级汇总

| # | 对应 Finding | 影响 | 修复成本 |
|---|-------------|------|---------|
| 1 | FIND-01: `narrowToWideBestEffort` fallback | 高：路径校验静默失效 | 低：删除 fallback 分支 |
| 2 | FIND-05: `GetModuleFileNameA` | 高：服务无法在非ASCII路径下注册 | 低：换 W 系列 API |
| 3 | FIND-02: `moduleDirOf` 截断 | 中：sched DB 路径损坏 | 低：换 `WideCharToMultiByte` |
| 4 | FIND-04: `getDataDirThunk` 裸指针 | 中：模块可读到悬空内存 | 中：固定成员变量 |
| 5 | FIND-03: TOCTOU in startSuspended | 中：junction 条件竞争 | 中：加入 `GetFinalPathNameByHandleW` |
| 6 | FIND-06: `restartCount` 溢出 | 低：极端情况 UB | 低：饱和递增 |

---

*文档生成时间: 2026-07-27。所有结论均来自已确认的问题清单，无新增问题。*
