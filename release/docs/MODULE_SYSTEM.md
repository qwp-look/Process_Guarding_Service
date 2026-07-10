# ProcessGuard 模块系统与 PPL 模块说明

本文档描述 PGS（ProcessGuard Service）的**可加载模块（插件）系统**，以及基于该系统实现的**首个模块——PPL 模块**（进程保护级别 / Protected Process Light 控制）。

模块系统让 PGS 的能力可以按需扩展：把新功能写成独立 DLL 模块，放入模块目录，PGS 启动时自动加载，运行时通过统一接口调用。PPL 模块即此模式的范例——它复用 StarlightGUI 的 `Sirius.sys` 内核驱动，对任意进程设置 / 查询 / 清除 PPL 保护。

---

## 1. 设计目标与边界

**目标**

- PGS 核心保持单一职责（守护对象生命周期），新能力以**模块**形式叠加，不污染核心。
- 模块用统一 C ABI 暴露，语言/编译器无关（MinGW g++ 构建的 PGS 可加载任意符合 ABI 的 DLL）。
- 模块能力通过 PGS 既有 TCP 管理协议暴露；`pgs_bless`、Qt、Web 三端复用共享的 `PGSClient` 发送 / 接收实现，避免每个入口重复实现 socket 细节。
- 首个模块验证整条链路：PPL 设置能力 = 一个模块，内部调用内核驱动。

**边界（本轮范围）**

- 模块加载进 **PGS 服务进程自身**（`LoadLibrary`），不是往被守护的目标进程注入 DLL。
- PPL 模块只做 **set / get / clear** 三种操作，复用既有 `Sirius.sys`，不自建驱动。
- Qt / Web 管理端的 UI 面板不在本轮范围（底层 TCP 命令已就绪，UI 后续接入）。

---

## 2. 架构总览

```
┌──────────────────────────────────────────────────────────────┐
│                       pgs_bless.exe (CLI)                     │
│   module list | load | unload | call                          │
│   ppl set | get | clear        ──┐                            │
└──────────────────────────────────┼───────────────────────────┘
                                   │ TCP 127.0.0.1:12345
                                   │ 行协议: "token <t> <verb> <args>"
┌──────────────────────────────────▼───────────────────────────┐
│                    pgs_service.exe (PGS 核心)                 │
│  processMessage() ──┬─ module <sub> ──► handleModuleCommand   │
│                     └─ ppl <sub>    ──► handlePplCommand      │
│                                                          │     │
│   ModuleManager (线程安全) ◄────────────────────────────┘     │
│   ├─ loadFromDirectory(<exe>/modules/)  扫描顶层 *.dll + 下钻一层子目录 │
│   ├─ load / unload / list / invoke                             │
│   └─ 持有: { name, version, HMODULE, PG_Init/Shutdown/Invoke }│
└──────────────────────────────────┬───────────────────────────┘
                                   │ LoadLibrary + GetProcAddress
                                   │ PG_Invoke("op=set;pid=N;signer=X")
┌──────────────────────────────────▼───────────────────────────┐
│        modules/ppl/pgs_ppl_module.dll (PPL 模块, 同目录含 module.html) │
│   PG_GetName="ppl"  PG_Invoke 解析 op=set/get/clear           │
│   SiriusDriverClient                                           │
│   ├─ SCM 加载 Sirius.sys (服务名 "Sirius for StarlightGUI")   │
│   ├─ CreateFileW("\\\\.\\Sirius")                             │
│   └─ DeviceIoControl(Protection IOCTL) set / query            │
└──────────────────────────────────┬───────────────────────────┘
                                   │ IOCTL
                            ┌──────▼──────┐
                            │  Sirius.sys │ (内核驱动, 复用 StarlightGUI)
                            └─────────────┘
```

数据流（以 `pgs_bless ppl set --pid 1234 --signer Antimalware` 为例）：

1. `pgs_bless` 组装行命令 `ppl set 1234 Antimalware`，加 token 信封发出。
2. PGS `processMessage` 剥信封 → 命中 `command == "ppl"` → `handlePplCommand`。
3. `handlePplCommand` 构造模块请求 `op=set;pid=1234;signer=Antimalware`，调 `m_modules.invoke("ppl", ...)`。
4. `ModuleManager::invoke` 找到 ppl 模块，调其 `PG_Invoke`。
5. 模块解析 KV，映射 signer，调 `SiriusDriverClient::setPPL`。
6. 驱动客户端加载/打开 Sirius 设备，发 `IOCTL_SIRIUS_SET_PROCESS_INFORMATION(Protection)`。
7. 结果沿原路返回：模块写 `OK set type=Light signer=Antimalware` → PGS 透传 → bless 打印。

---

## 3. 模块 C ABI（`PGModule.h`）

每个模块 DLL 必须导出下列 `extern "C"` 函数（见 `include/Process_Guard/PGModule.h`）：

| 函数 | 必需 | 作用 |
|------|------|------|
| `const char* PG_GetName(void)` | 是 | 模块短名（UTF-8 静态串），如 `"ppl"`。作为调用键，大小写不敏感。 |
| `const char* PG_GetVersion(void)` | 否 | 版本串，如 `"1.0.0"`。缺失时为空。 |
| `unsigned int PG_GetAbiVersion(void)` | 否 | 返回构建时的 `PG_MODULE_ABI_VERSION`，供兼容性检查。 |
| `int PG_Init(void* reserved)` | 否 | 加载后调用一次。返回 0 成功；非 0 则 PGS 卸载该模块并报错。`reserved` 当前为 `NULL`。 |
| `void PG_Shutdown(void)` | 否 | 卸载前调用一次。可缺失。 |
| `int PG_Invoke(const char* request, char* responseBuf, size_t responseBufSize)` | 是 | 执行操作。成功返回 0，失败返回非 0。响应写入 `responseBuf`（NUL 结尾 UTF-8）。 |

**ABI 版本**：`PG_MODULE_ABI_VERSION` 当前为 `1`。不兼容变更时递增。

**请求/响应格式**：沿用 PGS 的 `KEY=VALUE;...` KV 风格（UTF-8），不引入 JSON 依赖。
- 请求示例：`op=set;pid=1234;signer=Antimalware`
- 响应示例：`OK`、`OK type=Light signer=Antimalware`、`ERR invalid signer: foo`

**导出宏**：模块编译时定义 `PG_MODULE_EXPORTS`，使 `PG_MODULE_API` 解析为 `__declspec(dllexport)`；PGS 侧不定义该宏，仅用 `GetProcAddress` 取地址，无需链接导入库。

---

## 4. ModuleManager

`include/Process_Guard/ModuleManager.h` + `src/modules/ModuleManager.cpp`。

**职责**：线程安全地发现、加载、卸载、调用模块。

**关键行为**

- `loadFromDirectory(dir)`：用 `FindFirstFileW` 扫描——既加载 `dir\*.dll`（顶层散落 DLL），**也下钻一层子目录**加载 `dir\<文件夹>\*.dll`（推荐的 per-folder 布局）。**单个模块加载失败不会中断整轮扫描**（静默跳过），避免一个坏 DLL 拖垮全部插件。返回本轮成功加载数量。
- `load(path, err)`：加载单个 DLL。校验必需导出（`PG_GetName` + `PG_Invoke`），查重（按小写名），调 `PG_Init`；任一失败则 `FreeLibrary` 并返回错误。
- `unload(name, err)`：按名（大小写不敏感）卸载，先 `PG_Shutdown` 再 `FreeLibrary`。
- `list()`：返回 `{name, version}` 快照。
- `invoke(name, request, response, err)`：按名查找并调 `PG_Invoke`，提供 8 KB 响应缓冲。**模块未找到返回 false**；模块内部业务错误（模块写了 `ERR ...`）仍返回 true，由调用方看响应串。

**线程安全**：所有公开方法持 `std::mutex`。PGS 的工作线程池（4 个）会并发处理客户端请求，模块调用必须可重入——模块自身若维护共享状态需自行加锁。

**生命周期**：由 `PGS` 持有成员 `ModuleManager m_modules`。`PGS::initialize()` 总是创建/加固
`<exe>\modules` 根目录并配置 ABI v2 services；默认不自动扫描加载模块。只有显式启用 PPL/module
opt-in 时才递归加固 modules tree 并扫描加载。`PGS` 析构时 `ModuleManager` 析构会对每个已加载模块调
`PG_Shutdown` 并 `FreeLibrary`。

---

## 5. PGS 核心接线

修改点见 `src/service/PGS.h` 与 `src/service/PGS.cpp`（文件头已注明 Modified by PGS）。

**成员**

- `ModuleManager m_modules;` — 模块注册表。
- `std::string m_modulesDir;` — 模块目录绝对路径。

**方法**

- `static std::string moduleDirectoryOfSelf();` — 取 `pgs_service.exe` 所在目录 + `\modules`。
- `handleModuleCommand(args)` / `handlePplCommand(args)` — 命令处理。

**初始化**（`initialize()`）：在置 `m_initialized=true` 之前，创建/加固 `m_modulesDir`。PPL opt-in 时会
递归加固整个 modules tree，随后扫描 `m_modulesDir` 加载允许的模块，并记录日志（加载数量 / 目录）。
非 opt-in 启动不自动扫描，但显式 `module load` 会先读取 `modules.allow`，再按同一 allowlist/签名/哈希
规则加载指定 DLL。

**命令分发**（`processMessage`）：在 `ping` 分支前新增：

- `module list` → `OK count=N` + 每行 `name\tversion`
- `module load <base64路径>` → 解码后 `ModuleManager::load`
- `module unload <name>` → `ModuleManager::unload`
- `module call <name> <kv请求>` → `ModuleManager::invoke`，透传模块响应
- `ppl set <pid> <signer>` → 构造 `op=set;pid=N;signer=X` 调 ppl 模块（便利封装，免记模块调用语法）
- `ppl get <pid>` / `ppl clear <pid>` → 同上

所有命令复用既有 token 认证信封与 `splitByChar`/`parsePid` 等 KV 辅助，风格与原有命令一致。ppl 模块未加载时返回 `ERR ppl module not loaded`。

---

## 6. PPL 模块（`modules/ppl/`）

### 6.1 文件组成

| 文件 | 说明 | 来源 |
|------|------|------|
| `pgs_ppl_module.cpp` | 实现 PGModule ABI，解析 op=set/get/clear | 新增（PGS） |
| `SiriusDriverClient.h` | 驱动加载 + IOCTL 客户端 | 衍生自 StarlightGUI `DriverUtils`/`KernelInstance` |
| `SiriusIO.h` | Sirius 驱动 IOCTL/结构定义 | 衍生自 StarlightGUI，MinGW 适配 |
| `Sirius.sys` | 预编译内核驱动二进制 | 复制自 StarlightGUI `Assets/` |

### 6.2 操作语义

| op | 请求 KV | 行为 | 成功响应 |
|----|---------|------|----------|
| `set` | `op=set;pid=N;signer=X` | 设该进程为 PPL（Protected Light）+ 指定 signer | `OK set type=Light signer=X` |
| `get` | `op=get;pid=N` | 查询当前保护类型与 signer | `OK type=Light signer=X` |
| `clear` | `op=clear;pid=N` | 清除保护（type=None, signer=None） | `OK cleared` |

**signer 取值**（字符串，大小写不敏感；也接受 0–255 数字）：

`None` / `Authenticode` / `CodeGen` / `Antimalware` / `Lsa` / `Windows` / `WinTcb` / `WinSystem` / `App`

对应 `PS_PROTECTED_SIGNER`（见 `SiriusIO.h`）。ProtectionType 固定 `PsProtectedTypeProtectedLight`，与 StarlightGUI 的 `SetPPL` 行为一致。

### 6.3 驱动客户端工作流（`SiriusDriverClient`）

1. `ensureDevice()` 懒加载：
   - 解析 `Sirius.sys` 路径（优先模块 DLL 同目录，其次主 exe 目录）。
   - `loadSiriusDriver()`：`OpenSCManager` → `OpenService("Sirius for StarlightGUI")`；存在则按需 `StartService`，不存在则 `CreateService` + `StartService`。**服务名沿用 StarlightGUI**，若其已加载驱动则直接复用。
   - `CreateFileW("\\\\.\\Sirius", ...)` 打开设备。若设备已存在（别处已加载驱动）则即使 SCM 步骤失败也尝试打开。
2. `setPPL(pid, type, signer)`：填 `SI_PROCESS_PROTECTION{type, signer}`，构造 `SI_PROCESS_INFORMATION{Protection, pid, &prot, 0}`，发 `IOCTL_SIRIUS_SET_PROCESS_INFORMATION`。
3. `getPPL(pid, outType, outSigner)`：同结构，发 `IOCTL_SIRIUS_QUERY_PROCESS_INFORMATION`，驱动回填 `SI_PROCESS_PROTECTION`。

**延迟初始化**：`PG_Init` 不打开设备——`Sirius.sys` 可能尚未可加载（测试签名未开）。首次调用时才尝试，失败返回清晰错误（如 `ERR OpenSCManager failed, error=5`），模块加载不受影响。

---

## 7. CLI 用法（`pgs_bless`）

新增子命令（详见 `pgs_bless --help`）：

```
pgs_bless module list
pgs_bless module load --path <dll绝对路径>
pgs_bless module unload --name <模块名>
pgs_bless module call --name <模块名> --request "op=set;pid=N;signer=X"

pgs_bless ppl set --pid <pid> --signer <None|Authenticode|CodeGen|Antimalware|Lsa|Windows|WinTcb|WinSystem>
pgs_bless ppl get --pid <pid>
pgs_bless ppl clear --pid <pid>
```

通用选项（与既有命令一致）：`--host`、`--port`、`--token`。`ppl` 是 `module call ppl` 的便利封装；`module call` 可用于任意模块。

**典型流程**

```bash
pgs_bless ping                              # 连通性
pgs_bless module list                       # 应见 ppl 1.0.0
pgs_bless ppl get --pid 1234                # 查当前保护级
pgs_bless ppl set --pid 1234 --signer Antimalware
pgs_bless ppl get --pid 1234                # 确认 signer=Antimalware
pgs_bless ppl clear --pid 1234              # 清除保护
```

---

## 8. 构建

构建脚本已更新（`tools/build_pgs.bat` / `build_pgs.sh`）：

- 编译 `src/modules/ModuleManager.cpp` → `ModuleManager.o`，链入 `pgs_service.exe`。
- 用 `g++ -shared` 构建 `modules/ppl/pgs_ppl_module.dll`（per-folder 布局）。
- 复制 `Sirius.sys`、`module.html` 及 MinGW 运行时 DLL 到 `build/modules/ppl/`（模块文件夹自包含）。

```
cd Process_Guarding_Service
tools\build_pgs.bat      # 或在 MSYS2 MinGW64 终端: tools/build_pgs.sh
```

产物：

- `build/pgs_service.exe`
- `build/pgs_bless.exe`
- `build/modules/ppl/pgs_ppl_module.dll`
- `build/modules/ppl/Sirius.sys`
- `build/modules/ppl/module.html`

> 注：`build_pgs.bat` 现在会把 `C:\msys64\mingw64\bin` 加入 `PATH`，确保 g++ 能找到 `cc1plus` 等内部组件，因此可从任意终端运行（不必先开 MSYS2 终端）。

---

## 9. 如何编写一个新模块

1. 新建目录 `modules/<你的模块>/`。
2. 编写 `my_module.cpp`，`#include "Process_Guard/PGModule.h"`，定义 `PG_MODULE_EXPORTS`，实现 5 个导出函数。最小骨架：

   ```cpp
   #define PG_MODULE_EXPORTS
   #include "Process_Guard/PGModule.h"
   #include <cstring>
   #include <string>

   static const char* kName = "example";
   static const char* kVer = "1.0.0";

   extern "C" PG_MODULE_API const char* PG_GetName(void) { return kName; }
   extern "C" PG_MODULE_API const char* PG_GetVersion(void) { return kVer; }
   extern "C" PG_MODULE_API unsigned int PG_GetAbiVersion(void) { return PG_MODULE_ABI_VERSION; }
   extern "C" PG_MODULE_API int PG_Init(void*) { return 0; }
   extern "C" PG_MODULE_API void PG_Shutdown(void) {}

   extern "C" PG_MODULE_API int PG_Invoke(const char* request, char* resp, size_t respSize)
   {
       // 解析 "op=xxx;key=val;..." KV，执行，写响应
       std::string r = request ? request : "";
       // ... 你的逻辑 ...
       std::string out = "OK done";
       std::snprintf(resp, respSize, "%s", out.c_str());
       return 0;
   }
   ```

3. 在 `build_pgs.bat` / `build_pgs.sh` 仿照 PPL 模块加一行 `-shared` 构建，输出到 `build/modules/<你的模块>/my_module.dll`（per-folder 布局）。
4.（可选但推荐）在该目录放一个 `module.html`，作为该模块在 Qt 管理端「模块管理」标签页的说明页（见第 13 节）。
5. 运行 `pgs_bless module list` 应见你的模块；`pgs_bless module call --name example --request "op=..."` 调用。

**约定**

- **文件夹名 = 模块名**：`PG_GetName()` 的返回值必须与其所在文件夹名一致，Qt 管理端才能用「文件夹名」作为子页面名并通过 `module call --name <文件夹>` 路由到该模块。
- 模块名唯一、小写短名（如 `ppl`、`example`）。同名模块第二次加载被拒。
- `PG_Invoke` 必须线程安全（PGS 工作池并发调用）。
- 不要在 `PG_Init` 里做可能失败的重资源初始化（如打开驱动）；延迟到首次 `PG_Invoke`，返回清晰错误即可。
- 响应串遵循 `OK ...` / `ERR ...` 约定，便于 CLI/日志解析。

---

## 10. 运行前提与排错

**PPL 模块真正生效需要**

1. **管理员 / SYSTEM 权限**：PGS 服务以管理员运行，或通过 SCM 安装为服务（默认 LocalSystem）。非管理员下 `ppl set/get` 会返回 `ERR OpenSCManager failed, error=5`（拒绝访问）——这是权限不足，非 bug。
2. **能加载 `Sirius.sys`**：需测试签名模式（`bcdedit /set testsigning on` 后重启），或该驱动已具备有效签名。StarlightGUI 能正常加载它即满足。否则 `ensureDevice` 会返回 `CreateFile`/`StartService` 类错误。
3. **`Sirius.sys` 在位**：与 `pgs_ppl_module.dll` 同目录（`build/modules/`），或与 `pgs_service.exe` 同目录。

**常见错误**

| 现象 | 原因 | 处理 |
|------|------|------|
| `module list` 为空 | 模块目录无 DLL 或加载失败 | 检查 `build/modules/`；看服务日志 `PGS: loaded N module(s)` |
| `ERR ppl module not loaded` | ppl 模块未加载 | `module load --path <pgs_ppl_module.dll 绝对路径>` |
| `ERR OpenSCManager failed, error=5` | 非管理员 | 以管理员运行 PGS |
| `ERR CreateFile(...) failed, error=5` | 驱动未加载/无权限 | 开测试签名；确认 Sirius.sys 在位 |
| `ERR invalid signer: X` | signer 字符串不合法 | 用第 6.2 节列出的取值 |
| `pgs_bless: Failed to connect to PGS` | 服务未运行 | `pgs_service.exe run --token <t>` |

---

## 11. 安全与合规说明

- PPL 提权是高敏感操作。把任意进程提为 PPL（尤其 `WinTcb`/`WinSystem`）后，该进程将难以被终止/调试/读取内存——请明确知晓后果再操作。
- `Sirius.sys` 为第三方（StarlightGUI，作者 Stars）提供的内核驱动二进制，Apache-2.0 授权再分发。复用意味着 PGS 依赖该驱动的加载环境（测试签名或其签名）。长期更干净的做法是自建驱动，但工作量与维护成本显著更高。
- 模块系统会执行任意 DLL 中的代码。仅加载可信来源的模块；模块目录的写入权限应受控。
- **module load 路径白名单**：服务端只允许加载位于 PGS 模块目录（<pgs_service.exe 目录>/modules）之内的 DLL，..、UNC、盘外绝对路径一律拒绝。避免任意本地主体借 module load 把任意 DLL 加载进 SYSTEM 级服务进程。
- **PPL/驱动按需启用（opt-in）**：默认启动 PGS **不会**加载 ppl 模块、也不会加载 Sirius.sys。仅当设置环境变量 PGS_ENABLE_PPL=1 或向 pgs_service 传入 --enable-ppl 时，才会扫描模块目录并加载 PPL 相关模块。降低默认引入内核驱动的风险。
- **ppl set 可对任意进程设 PPL**：包括对 PGS 自身或任意第三方进程设 WinTcb/Antimalware。这是产品设计能力，风险由「opt-in 加载 + 强制 token 鉴权」收敛；非 opt-in 部署下该能力不可达。
- **Sirius.sys 攻击面告警**：一旦加载，Sirius.sys 常驻并暴露设备 \\\\.\\Sirius，具备 ARK 级内核能力（终止/隐藏/挂起进程、注入 DLL、改进程 token、读写内存、关 PatchGuard、关 DSE、删回调等）。任何能打开该设备的本地主体都获得完整内核级能力。PGS 仅在「我们自己创建了该服务」时才在关闭时 STOP+DeleteService 卸载它（StarlightGUI 已加载的不动）；用户态无法修改驱动的设备 DACL，请勿在不受信任的主机上启用 PPL。
- **鉴权前置**：所有 module/ppl 命令仍受 PGS token 鉴权保护；空 token 不再被接受（无 token 时服务自动生成随机 token 并写入受限目录下的 pgs_initial_token.txt）。

---

## 12. 版权与署名

本模块系统为 PGS 新增代码（Apache-2.0）。PPL 模块及其驱动客户端衍生自 StarlightGUI（Apache-2.0，作者 Stars / OpenStarlight）：

- `modules/ppl/Sirius.sys` — StarlightGUI 提供的预编译二进制，原样再分发。
- `modules/ppl/SiriusIO.h` — 衍生自 StarlightGUI `SiriusIO.h`，仅将 MSVC `#pragma warning` 包进 `_MSC_VER`，协议定义未改。
- `modules/ppl/SiriusDriverClient.h` — 逻辑衍生自 StarlightGUI `DriverUtils::LoadKernelDriver` 与 `KernelInstance::GetDriverDevice/SetPPL/SiQueryProcessInformation`。

详见 `NOTICE` 与 `LICENSE.ThirdParty.StarlightGUI.txt`。按 Apache-2.0 §4(b)，PGS 修改过的文件已在头/注释标注 "Modified by PGS"。

---

## 13. Qt 管理端「模块管理」标签页

`qt/pgs_admin_qt` 的第 4 个标签页「模块管理 / Module Management」提供模块的可视化管理：

- **动态子页面**：启动时（及点「刷新模块列表」时）扫描 `<pgs_service.exe 目录>/modules` 下的子目录，每个文件夹生成一个子标签，**子标签名 = 文件夹名 = 模块名**。无需服务运行即可建页。
- **说明页渲染**：每个子页面用 `QTextBrowser` 渲染该文件夹下的 `module.html`（HTML 4 / CSS 2.1 子集，**不执行 JS**）。`module.html` 不存在时显示占位提示。点「重载 HTML」可刷新。
- **命令执行**：子页面通过 `pgs_bless` 与运行中的 `pgs_service` 通信：
  - 「调用 (module call)」：执行 `pgs_bless module call --name <文件夹> --request "<KV>"`。
  - ppl 子页面额外提供 `ppl set / get / clear` 便捷按钮（带 PID 输入与 signer 下拉）。
  - 命令输出显示在该子页面底部的输出区。
- **配置**：标签页顶部可填 `pgs_bless` 路径、token、modules 目录；语言随全局中/英切换同步翻译。

> 约定提醒：因「文件夹名 = 模块名」，新增模块时务必让目录名与 `PG_GetName()` 返回值一致，否则 Qt 子页面虽能建立，但 `module call --name <文件夹>` 会因名字不匹配而失败。

`module.html` 由各模块自行提供，应放在 `modules/<模块名>/module.html`，构建脚本将其与 `*.dll`、`Sirius.sys` 等一并拷入 `build/modules/<模块名>/` 与 `release/modules/<模块名>/`。
## 14. 模块白名单与 Authenticode 签名（v3）

> v3 起模块加载默认 **fail-closed**：必须命中白名单、（当要求签名时）通过 Authenticode 校验，否则一律拒绝加载。本节为 v3 校验机制的权威说明。

### 14.1 校验链

`ModuleManager::load` 顺序：

1. 规范化待加载 DLL 的绝对路径，确认其位于 `<exe>\modules\` 之内（`isPathInsideModulesDir`，拒绝逃逸模块目录的绝对路径）。
2. **白名单命中**：在 `modules.allow` 中按模块名（大小写不敏感，与 `PG_GetName` 比对）查找条目。
3. （条目要求签名时）**Authenticode 校验**：`WinVerifyTrust` 验证文件签名链。
4. （条目给出 sha256 时）**哈希校验**：BCrypt(SHA-256) 计算文件哈希与条目比对。
5. 全过才 `LoadLibrary`；任何一步失败记录明确原因并跳过。

错误串扩容：`"module not in allowlist"` / `"signature verification failed"` / `"hash mismatch"` / `"module path outside modules dir"`。

### 14.2 白名单文件格式

路径：`<pgs_service.exe 目录>\modules\modules.allow`。逐行：

```
# 注释行、空行忽略；# 必须在行首
<name>[|<sha256Hex>][|signed]]
```

- `<name>`：模块 `PG_GetName` 返回值，大小写不敏感。
- 可选 `|<sha256Hex>`：固定该哈希；缺省则不校验哈希。
- 可选 `|signed`：要求 Authenticode 签名有效；缺省则不强制签名。

### 14.3 fail-closed 与 `--allow-all-modules`

- **默认 fail-closed**：`modules.allow` 文件缺失（或无可命中条目）→ 拒绝加载任何模块并日志告警。理由：模块可执行任意代码进入 PGS 进程空间，未显式授权即不该加载。
- **逃生阀 `--allow-all-modules`**：`run`/`install` flag，持久化于归档 `MODULES_PERMISSIVE\t1`，开启旧宽松行为「白名单缺失仍允许加载」用于开发调试。文档明确警告：**生产环境禁用**，等价于关闭模块边界。

### 14.4 目录 ACL 加固

模块目录 `<exe>\modules\` 经 `secureCreateDirectory` 设置 SYSTEM + Administrators 专有 ACL，普通用户不可写入，避免「先植入恶意 DLL 再等加载」的提权路径。状态目录、归档/临时目录同权限制。

PPL 开启时额外递归加固整个 modules tree：

- 子目录也会应用 SYSTEM + Administrators 专有 ACL。
- 已存在的普通文件（DLL、`modules.allow`、`module.html`、`Sirius.sys` 等）会被设置为受保护 DACL。
- 任一子项加固失败时，PPL 模块加载 fail-closed，避免在目录根 ACL 正确但既有子文件仍可被普通用户替换的状态下加载内核能力模块。

非 PPL 默认启动只创建/加固根 modules 目录，不递归改写整个树；这样普通部署不会无谓改变开发目录下的文件 ACL。

### 14.5 排错

| 症状 | 原因 | 处置 |
|------|------|------|
| `module not in allowlist` | DLL 名不在 `modules.allow` | 添加条目或确认 `PG_GetName` 拼写 |
| `signature verification failed` | 条目要求 `signed` 但签名无效/缺失 | 用有效 Authenticode 证书重签模块，或条目去掉 `signed`（仅开发） |
| `hash mismatch` | 文件被改 | 重新计算 sha256 更新条目，或恢复原始文件 |
| `module path outside modules dir` | 指定了 modules 外的绝对路径 | 仅加载 `modules\` 下的 DLL |
| 服务启动加载全部失败并告警 | `modules.allow` 缺失（fail-closed） | 创建白名单并列举所需模块；或临时 `--allow-all-modules`（仅开发） |
