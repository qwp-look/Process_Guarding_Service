# ProcessGuard 技术架构说明（PGS 主线）

## 1. 架构总览

当前采用“服务中心 + 命令行/图形客户端”的模型：

- `PGS`：守护核心（注册、监控、重启、策略）
- `pgs_service`：Windows 服务宿主（对接 SCM）
- `pgs_bless`：命令行运维工具（现已链接共享 `PGSClient`，与 Web/CLI 复用同一 TCP 行协议实现）
- `pgs_admin_qt`：Qt 图形运维端（保留 `QProcess` 作为异步 UI 边界；仍通过 `pgs_bless` / `pgs_service` 做复杂运维动作）
- `pgs_admin_web`：浏览器控制端（已直连 `PGSClient`，不再为每次 API 请求起 `pgs_bless.exe`）

## 2. 模块与职责

- `include/Process_Guard/PGS.h`：核心类型与接口
- `src/service/PGS.cpp`：生命周期、监控、持久化、socket 传输
- `src/service/PGSProtocol.cpp`：管理协议分发、命令处理、模块 / PPL 路由
- `src/service/pgs_service.cpp`：服务安装/启动/停止/状态
- `tools/pgs_bless.cpp`：CLI 命令解析与协议调用（共享 `PGSClient`）
- `src/common/PGSClient.cpp`：共享 TCP 行协议客户端（CLI / Qt / Web 复用）
- `src/common/PGLogger.cpp` + `include/Process_Guard/PGLogger.h`：日志
- `include/Process_Guard/PGModule.h`：模块 C ABI（PG_GetName/Init/Invoke 等）
- `include/Process_Guard/ModuleManager.h` + `src/modules/ModuleManager.cpp`：模块注册表（加载/卸载/调用）
- `modules/ppl/`：PPL 模块（pgs_ppl_module.cpp + Sirius 驱动客户端 + Sirius.sys）
- `qt/pgs_admin_qt/`：Qt GUI

模块边界的设计原则是：

- `PGS` 只关心“守护对象生命周期”
- `pgs_service` 只关心“这个核心如何作为 Windows 服务/控制台进程活着”
- `pgs_bless` 只关心“如何把用户命令转成协议请求”
- `Qt` 管理端只关心“把命令行能力包装成图形运维入口”

这样拆分之后，核心守护逻辑不会被 UI、SCM、参数解析这些外围问题牵着走。

## 3. 关键数据结构

### 3.1 `GuardInfo`

每个被守护进程一条记录，核心字段：

- `pid`、`sessionId`
- `path`
- `maxRestarts`、`restartArgs`
- `fileHash`、`hashVerified`
- `handle`
- `intentional`
- `guardId`

其中 `guardId` 是当前实现里的关键字段：

- `pid` 会在重启后变化，不能直接作为长期策略主键
- `path` 可能被多个实例共享，不能再拿来隔离重启策略
- 因此服务端使用 `guardId` 代表“一个逻辑守护对象”

### 3.2 `RestartPolicyState`

按 `guardId` 跟踪：

- `maxRestarts`
- `restartCount`

这样可避免“同路径多实例互相污染重启次数”的历史问题。

### 3.3 `PersistedGuardState`

这是本轮新增的“归档层”，代表 durable desired state，而不是瞬时运行态：

- `guardId`
- `lastKnownPid`
- `sessionId`
- `path`
- `maxRestarts`
- `restartArgs`
- `fileHash`
- `intentional`
- `hashVerified`

它的作用是：

- 服务进程崩溃后仍保留守护集合
- 服务重启时先读档再恢复
- 若原进程还活着则重新接管
- 若原进程不存在则按归档策略重启
- token hash 也与这份归档一起持久化，但只保存哈希，不保存明文

这样 `m_guards` 负责“当前活着的 guard”，而 `m_persistedGuards` 负责“服务恢复后应该继续拥有的 guard”。

归档文件位置由日志根目录推导；按当前服务宿主默认配置，通常落在：

- `C:\ProgramData\ProcessGuard\state\pgs_guard_state.db`

### 3.4 `PGSClient`

`PGSClient` 是 CLI / Qt / Web 共享的 TCP 行协议实现：

- 负责 `token <base64(token)> <command>` 的认证封装
- 负责单连接的发送 / 接收 / 超时控制
- 复用 `PGUtil.h` 里的 base64、JSON 转义和分隔工具
- 让 `pgs_bless`、Qt 管理端、Web 管理端不再各自重复实现 socket 逻辑

这层只管“怎么把一行命令安全地送到 PGS”，不管业务语义。

### 3.5 `PGSProtocol.cpp`

协议分发从 `PGS.cpp` 拆出到 `src/service/PGSProtocol.cpp` 后，职责更清晰：

- `PGS.cpp`：生命周期、持久化、monitor / restart、socket transport
- `PGSProtocol.cpp`：`processMessage()`、`register/get/list/policy/token/module/ppl` 这些管理命令

这样做的收益是：

- 协议演进不会把监控 / 重启逻辑一起搅动
- 代码体积更容易控制
- 读协议的时候不用在 2000+ 行的大文件里来回跳

## 4. 协议设计

命令（完整清单）：

| 命令 | 参数 | 说明 |
|------|------|------|
| `ping` | — | 探活，返回 `OK pong` |
| `list` | — | 所有守护目标汇总 |
| `get` | `<pid>` | 单个守护对象详情 |
| `register` | `<pid>\|<b64path>\|<maxRestarts>[\|<restartArgs>][\|<hash>]` | 注册守护 |
| `unregister` | `<pid>` | 取消守护 |
| `intentional` | `<pid>` | 标记本次退出为有意，不再重启 |
| `set-policy` | `<pid>\|<maxRestarts>[\|<restartArgs>]` | 改策略 |
| `set-token` | `<b64old>\|<b64new>` | 在线切换 token |
| `stats` | — | `OK guards=N` |
| `module` | `list` / `load <b64path>` / `unload <name>` / `call <name> <kv>` | 模块系统 |
| `ppl` | `set <pid> <signer>` / `get <pid>` / `clear <pid>` | PPL 便利封装（路由到 ppl 模块） |

返回：

- 成功：`OK ...`
- 失败：`ERR ...`

认证封装（当前默认始终启用）：

`token <token> <command>`

实现细节补充：

- 协议仍为纯文本、换行结束；`PGSClient` 是共享的发送 / 接收实现，CLI 与 Web 直接复用它。
- 监听线程只负责 `accept`；worker 池负责 `recv/process/send`
- 客户端连接进入队列后，由固定 worker 线程负责 `recv/process/send`
- socket 设置了收发超时
- 单条消息存在大小上限，避免长消息无界增长
- 响应发送使用 `sendAll`，处理 partial send

这样做的核心原因是：PGS 的协议是“本机管理协议”，不是高吞吐业务协议。目标不是炫技地上复杂网络框架，而是让 `ping/list/register/policy` 这些运维动作在异常条件下也尽量稳定、可诊断。

### 4.1 Token 的运行时规则

- 服务端默认始终开启 token 鉴权（`m_requireAuth=true`）
- 服务端不保存 token 明文，只保存 token 哈希
- token hash 会跟随守护归档一起持久化
- `pgs_service run --token <value>` 可设置本次进程启动 token
- 若本次启动未显式指定 token，则会优先从归档恢复 token hash
- `set-token` 命令用于在线切换 token：必须先验证旧 token 才会更新，并会立即写回归档
- 只有首次启动且此前没有归档时，自动生成随机 64 位十六进制 token（明文写入 `pgs_initial_token.txt`），永不接受空 token
- 客户端行为：`pgs_bless` 使用 `--token <value>` 或环境变量 `PGS_AUTH_TOKEN`；Qt GUI 通过 `PGS_AUTH_TOKEN` 环境变量传给 `pgs_bless`（不走命令行，避免本地泄露）

## 5. 重启流程

1. 客户端发送 `register`
2. 服务端根据 `pid` 查询真实镜像路径，并与客户端提交路径比对
3. PGS 建立/更新守护条目
4. `monitorLoop` 周期检测进程句柄
5. 异常退出后按该 `guardId` 对应策略决定是否重启
6. 优先 `CreateProcessAsUserW`（目标会话）
7. 失败则 `CreateProcessW` fallback

## 5.2 服务自身重启后的恢复流程

新增的恢复路径是：

1. `initialize()` 先读取归档文件
2. 恢复 token hash 与 desired guard 集
3. `start()` 在开监听线程之前先做 guard restore
4. 对每个归档 guard：
   - 若 `lastKnownPid` 仍存在且路径一致，则重新接管
   - 若进程不存在，则按归档配置重启
5. 恢复完成后再进入正常监控循环

这样 SCM 把 `pgs_service` 拉起来之后，PGS 不会从“空白内存”重新开始，而是会尽量回到之前的守护现场。

这里的实现取舍是：

- 先追求“能回到正确用户会话”
- 再保证“即使会话恢复失败，后台任务也仍有 fallback 可拉起”

这也是为什么 `restartGuard()` 会先走 `restartGuardInSession()`，失败后再退回普通 `CreateProcessW`。

### 5.1 `bless-start` 的原子化思路

当前 `bless-start` 不是“先启动再赌注册成功”，而是：

1. CLI 用 `CREATE_SUSPENDED` 启动目标进程
2. 计算 hash、准备注册消息
3. 若服务端注册成功，则 `ResumeThread`
4. 若注册失败，则回滚并终止这个尚未恢复的子进程

这样做的目的，是避免出现“进程已经跑起来，但其实没有被守护”的半成品状态。

## 6. 哈希校验

`register` 可带哈希字段（SHA-256 hex）：

- 提供且匹配：通过
- 提供且不匹配：拒绝注册
- 不提供：按兼容模式注册

## 7. 图形控制端实现要点

### 7.1 Qt 桌面端

- 三 `QProcess` + 三页结构：
  - Bless 页调用 `pgs_bless.exe`
  - Service 页调用 `pgs_service.exe`
  - Guard Table 页调用 `pgs_bless list --json`
- Bless 页默认定位 `pgs_bless.exe`（`../pgs_bless.exe`）
- Service 页默认定位 `pgs_service.exe`（`../pgs_service.exe`）
- Bless 页支持 `ping/list/get/bless/bless-start/unbless/unbless-path/policy/intentional/token-set`
- Service 页支持 `install/status/start/stop/uninstall/run`，并提供 `reset service` 序列执行
- Guard Table 页将守护列表解析为表格字段：`PID/Path/Hash/Restarts/Max/Alive/Session/HashVerified`
- Guard Table 默认自动刷新为 `1000 ms`
- 自动刷新时不再每轮 `resizeColumnsToContents()`
- 表格 JSON 解析失败时保留旧表并在状态栏提示
- 输出能力：启动失败、退出码、stderr/stdout、分页面日志窗口
- 支持 `中文 / English` 界面切换

### 7.2 浏览器控制端

`pgs_admin_web` 采用独立进程方案：

- 自己提供 HTTP 路由与静态页面
- 浏览器只访问这个 Web 管理进程
- Web 后端再去调用现有 `pgs_bless.exe` / `pgs_service.exe`
- 第一阶段先复用成熟 CLI；下一阶段再抽公共 `PGSClient` 降低协议重复

这样做的目的是先把真正的浏览器控制台落地，同时不把 HTTP 层直接塞进 `PGS` 核心。

## 8. 服务自我守护的取舍

“让 PGS 自己守自己”这个想法直觉上合理，但如果是同一个服务进程内部自监控，它一旦崩溃就没有机会执行恢复代码，所以并不是真正可靠的自愈方案。

当前更推荐也更成熟的做法是：

- 进程内部继续负责“守护其它业务进程”
- Windows SCM 负责“守护 PGS 服务自己”

因此安装服务时会额外配置 SCM 的失败恢复动作，让系统在服务异常退出后自动重启它。这比在 PGS 里再塞一层自我监控逻辑更符合职责边界，也更贴近 Windows 原生服务模型。

## 9. `pgs_bless` 常用命令语义

```bash
./build/pgs_bless.exe ping
```
- 用于服务探活（PGS 是否在线）。

```bash
./build/pgs_bless.exe list
```
- 返回所有守护目标汇总信息。

```bash
./build/pgs_bless.exe bless --pid 1234 --max-restarts 3 --hash auto
```
- 注册守护目标，并设置最大重启次数；`--hash auto` 启用文件一致性校验上报。

```bash
./build/pgs_bless.exe bless-start --path "C:/程序/示例.exe" --start-args "--mode worker" --max-restarts 3 --hash auto
```
- 按路径启动并立即注册守护；内部使用宽字符路径启动，支持中文路径。
- 若未指定 `--restart-args`，默认将 `--start-args` 写入 PGS 作为后续重启参数。

```bash
./build/pgs_bless.exe bless-start --command "\"C:/程序/示例.exe\" --mode worker --safe" --max-restarts 3 --hash auto
```
- 按自定义完整命令启动并守护；会解析并提取参数写入 PGS（除非显式传 `--restart-args`）。

```bash
./build/pgs_bless.exe unbless-path --path "C:/程序/示例.exe"
```
- 按路径批量取消守护；适合 PID 频繁变化但可执行路径固定的场景。

```bash
./build/pgs_bless.exe policy --pid 1234 --max-restarts no
```
- 动态修改守护策略（这里是无限重启）。

```bash
./build/pgs_bless.exe unbless --pid 1234
```
- 取消守护注册。

```bash
./build/pgs_bless.exe get --pid 1234 --json
```
- 查询单个守护对象详情，JSON 便于自动化处理。

```bash
./build/pgs_bless.exe token-set --old-token old-token --new-token new-token --token old-token
```
- 在线更新 token，服务端会先校验旧 token，再切换新 token（仅当前进程内存生效）。

## 10. 构建附录（MSYS2 MinGW64）

### 8.1 C++ 构建命令

```bash
cd /c/Users/wtg/Desktop/other/MY-code/process_protect_need/Process_Guarding_Service
mkdir -p build

export PATH=/mingw64/bin:/usr/bin
hash -r

g++ -std=c++17 -Wall -Wextra -O2 -Iinclude -c src/common/PGLogger.cpp -o build/PGLogger.o
g++ -std=c++17 -Wall -Wextra -O2 -Iinclude -c src/service/PGS.cpp -o build/PGS.o
g++ -std=c++17 -Wall -Wextra -O2 -Iinclude -c src/service/pgs_service.cpp -o build/pgs_service.o
g++ -std=c++17 -Wall -Wextra -O2 -Iinclude -c src/modules/ModuleManager.cpp -o build/ModuleManager.o
g++ -std=c++17 -Wall -Wextra -O2 \
  build/PGLogger.o build/PGS.o build/ModuleManager.o build/pgs_service.o \
  -o build/pgs_service.exe \
  -lws2_32 -ladvapi32 -lwtsapi32 -luserenv

# PPL 模块（独立 DLL，放入 build/modules/ 供 PGS 启动自动加载）
mkdir -p build/modules
g++ -std=c++17 -Wall -Wextra -O2 -shared -o build/modules/pgs_ppl_module.dll modules/ppl/pgs_ppl_module.cpp -Iinclude -ladvapi32
cp -f modules/ppl/Sirius.sys build/modules/Sirius.sys

g++ -std=c++17 -Wall -Wextra -O2 -Iinclude tools/pgs_bless.cpp -o build/pgs_bless.exe -lws2_32
g++ -std=c++17 -Wall -Wextra -O2 -Iinclude examples/guard_example.cpp -o build/guard_example.exe -lws2_32
g++ -std=c++17 -Wall -Wextra -O2 -Iinclude examples/quick_start.cpp -o build/quick_start.exe -lws2_32
g++ -std=c++17 -Wall -Wextra -O2 -Iinclude examples/smoke_worker.cpp -o build/smoke_worker.exe -lws2_32

# 复制 MinGW 运行库到 C++ 可执行目录（build/）
cp -f /mingw64/bin/libstdc++-6.dll build/
cp -f /mingw64/bin/libgcc_s_seh-1.dll build/
cp -f /mingw64/bin/libwinpthread-1.dll build/
```

### 8.2 Qt 构建命令

```bash
cd /c/Users/wtg/Desktop/other/MY-code/process_protect_need/Process_Guarding_Service
rm -rf build/pgs_admin_qt

cmake -S qt/pgs_admin_qt -B build/pgs_admin_qt -G "MinGW Makefiles" \
  -DCMAKE_PREFIX_PATH=/mingw64 \
  -DCMAKE_CXX_COMPILER=/mingw64/bin/g++.exe

cmake --build build/pgs_admin_qt -j4

# Qt 依赖部署 + 复制 MinGW 运行库到 Qt 可执行目录
/mingw64/bin/windeployqt-qt6.exe build/pgs_admin_qt/pgs_admin_qt.exe
cp -f /mingw64/bin/libstdc++-6.dll build/pgs_admin_qt/
cp -f /mingw64/bin/libgcc_s_seh-1.dll build/pgs_admin_qt/
cp -f /mingw64/bin/libwinpthread-1.dll build/pgs_admin_qt/
```

### 8.3 运行时 DLL（建议）

核心运行库：

- `libstdc++-6.dll`
- `libgcc_s_seh-1.dll`
- `libwinpthread-1.dll`

Qt 程序建议：

```bash
/mingw64/bin/windeployqt-qt6.exe build/pgs_admin_qt/pgs_admin_qt.exe
cp -f /mingw64/bin/libstdc++-6.dll build/pgs_admin_qt/
cp -f /mingw64/bin/libgcc_s_seh-1.dll build/pgs_admin_qt/
cp -f /mingw64/bin/libwinpthread-1.dll build/pgs_admin_qt/
```


---

## 模块系统（插件）

PGS 内置可加载模块系统，能力以 DLL 插件形式叠加，不污染守护核心。PPL 模块是首个实例，复用 StarlightGUI 的 `Sirius.sys` 内核驱动设置进程 PPL。

- **ABI**：`PGModule.h` 定义 `extern "C"` 导出（Name/Version/Init/Shutdown/Invoke），请求/响应用 KV 文本，零依赖。
- **注册表**：`ModuleManager` 线程安全地扫描 `<exe>/modules/*.dll` 自动加载，并提供 `load/unload/list/invoke`。
- **协议接入**：`PGS::processMessage` 新增 `module list|load|unload|call` 与 `ppl set|get|clear` 命令，复用既有 token 认证信封。
- **CLI**：`pgs_bless` 的 `module` / `ppl` 子命令通过同一 TCP 协议调用。

详细架构、ABI 规格、如何编写新模块、排错与版权见 [`MODULE_SYSTEM.md`](MODULE_SYSTEM.md)。

---

## 11. 协议线格式与并发模型（补充）

**线格式**：纯文本、单行、UTF-8、`\n` 结束。

- 认证信封：`token <token> <command> <args>`（`stripAuthEnvelope` 剥离并校验 token 哈希）。
- 命令体：`<verb> <args>`，`verb` 与 `args` 以首个空格分隔；`args` 内部按命令约定用 `|` 或空格再切分。
- 路径/token 等二进制不安全字段用 base64 编码（`register` 的 path、`set-token` 的新旧 token、`module load` 的 DLL 路径）。
- 单条消息上限 `kMaxMessageSize = 64 KB`，超长直接拒绝，防止无界增长。

**并发模型**：

- 监听线程（`listenerLoop`）只 `accept`，把 socket 入队后立刻返回，绝不阻塞在单个客户端上。
- 固定 4 个 worker 线程（`kClientWorkerCount`）从队列取 socket，执行 `recv → processMessage → send`。
- socket 收发均设超时（`kSocketTimeoutMs = 3000`），一个卡死的客户端不会永久占用 worker。
- 响应发送走 `sendAll`，处理 partial send。
- `m_guards` / `m_persistedGuards` / `m_policyByGuardId` 由 `m_guardsMutex` 保护；`ModuleManager` 自带内部 mutex，模块调用可并发。

**为什么不用更重的网络框架**：PGS 是本机管理协议，流量是低频运维命令（ping/list/register/policy/module），目标是异常条件下稳定可诊断，而非高吞吐。

## 12. 模块系统内部（补充）

> 完整说明见 [`MODULE_SYSTEM.md`](MODULE_SYSTEM.md)，此处补架构视角。

- **加载时机**：`PGS::initialize()` 在置 `m_initialized=true` 前，扫描 `<pgs_service.exe 目录>\modules\*.dll` 自动加载。单个模块失败不中断整轮扫描。
- **调用链**：`processMessage` → `handleModuleCommand` / `handlePplCommand` → `ModuleManager::invoke` → 模块 `PG_Invoke`。`ppl` 命令是 `module call ppl` 的语法糖，PGS 内部构造 `op=...;pid=...` KV 再调 ppl 模块。
- **线程安全**：模块 `PG_Invoke` 必须可重入（worker 池并发调用）。模块自身共享状态自行加锁。
- **延迟初始化**：PPL 模块 `PG_Init` 不打开驱动（驱动可能尚未可加载），首次 `PG_Invoke` 才 `ensureDevice`，失败返回清晰错误而非拖垮模块加载。
- **卸载**：`module unload` 或服务退出时调 `PG_Shutdown` + `FreeLibrary`。

## 13. Web 控制端（pgs_admin_web）

独立进程方案，与 PGS 核心解耦：

- 自己提供 HTTP 路由 + 静态页面 + 会话鉴权；浏览器只访问这个 Web 进程。
- Web 后端调用现有 `pgs_bless.exe` / `pgs_service.exe`（第一阶段复用成熟 CLI），后续可抽公共 `PGSClient` 降低协议重复。
- PGS 核心不承担 HTTP/静态托管/自身恢复，职责不堆叠。
- 部署建议绑定 `127.0.0.1`，面向本机运维；PGS token 不暴露到前端，由 Web 后端服务端持有/转发。
- API 对外暴露 JSON（如 `GET /api/guards`、`POST /api/guards/bless`），浏览器不直接接触底层 `OK/ERR` 文本协议。

## 14. 运行时依赖与部署

**C++ 主线运行库**（MinGW 构建，需随 exe 分发）：

- `libstdc++-6.dll`
- `libgcc_s_seh-1.dll`
- `libwinpthread-1.dll`

**PPL 模块额外依赖**：

- `modules\pgs_ppl_module.dll`（与 `pgs_service.exe` 同进程加载）
- `modules\Sirius.sys`（内核驱动，复用自 StarlightGUI）
- 加载 `Sirius.sys` 需：管理员/SYSTEM 权限 + 测试签名模式（`bcdedit /set testsigning on`）或驱动已具备有效签名。

**状态/日志位置**（服务模式默认）：

- 日志：`C:\ProgramData\ProcessGuard\logs\pgs_service.log`
- 归档：`C:\ProgramData\ProcessGuard\state\pgs_guard_state.db`

## 15. Release 打包布局

`release\` 目录面向开箱即用，结构如下：

```
release\
├─ pgs_service.exe          守护服务宿主（控制台 run / SCM install）
├─ pgs_bless.exe            命令行运维工具
├─ libgcc_s_seh-1.dll       MinGW 运行库
├─ libstdc++-6.dll
├─ libwinpthread-1.dll
├─ modules\
│  ├─ pgs_ppl_module.dll    PPL 模块（启动自动加载）
│  └─ Sirius.sys            内核驱动（PPL 模块加载）
├─ examples\                示例（可选）
│  ├─ guard_example.exe
│  ├─ quick_start.exe
│  └─ smoke_worker.exe
├─ README.md                使用说明
├─ NOTICE                   第三方署名
└─ LICENSE                  Apache 2.0
```

运行：以管理员开终端，`pgs_service.exe run --token <你的token>`，另开终端 `pgs_bless.exe ping --token <你的token>`。
## 8. CI 与验证

- GitHub Actions 会在 windows-latest 上用 MSYS2 MinGW64 构建 C++ 主线并跑 smoke test。
- Qt Web 端也会单独构建，确保共享 PGSClient 没有破坏 Web 管理端。
- 需要管理员权限才能完整验证 ProgramData 下的持久化恢复（见鲁棒性文档）。

## 7.2 CI 备注

- GitHub Actions 现在走 Windows runner + MSYS2 的方式；`actions/checkout@v4` 的 Node 20 警告是 runner 侧提示，不是本项目失败原因。