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

- **加载时机**：`PGS::initialize()` 总是创建/加固 `<pgs_service.exe 目录>\modules` 根目录并设置 ABI v2 services；
  默认不自动扫描加载模块。PPL/module opt-in 时才递归加固 modules tree 并扫描加载；显式 `module load`
  会先读取 `modules.allow`，再按同一白名单/签名/哈希链路加载单个 DLL。
- **调用链**：`processMessage` → `handleModuleCommand` / `handlePplCommand` → `ModuleManager::invoke` → 模块 `PG_Invoke`。`ppl` 命令是 `module call ppl` 的语法糖，PGS 内部构造 `op=...;pid=...` KV 再调 ppl 模块。
- **线程安全**：模块 `PG_Invoke` 必须可重入（worker 池并发调用）。模块自身共享状态自行加锁。
- **延迟初始化**：PPL 模块 `PG_Init` 不打开驱动（驱动可能尚未可加载），首次 `PG_Invoke` 才 `ensureDevice`，失败返回清晰错误而非拖垮模块加载。
- **卸载**：`module unload` 或服务退出时调 `PG_Shutdown` + `FreeLibrary`。

## 13. Web 控制端（pgs_admin_web）

独立进程方案，与 PGS 核心解耦：

- 自己提供 HTTP 路由 + 静态页面 + 会话鉴权；浏览器只访问这个 Web 进程。
- Web 后端直连 `PGSClient` 处理高频 `ping/list/get/policy/token` 等 PGS 协议请求；
  服务生命周期等操作仍可复用 `pgs_service.exe`。
- PGS 核心不承担 HTTP/静态托管/自身恢复，职责不堆叠。
- 本地模式绑定回环，页面嵌入进程内 API token，API 同时校验 `Host`/`Origin`。
- remote 模式 fail-closed：TLS + Basic RBAC + users file + audit log 缺一不可；远程页面不嵌入
  PGS 管理 token，由 Web 后端持有/转发。
- remote 变更类 API 要求 JSON + `X-PGS-CSRF` + 同源 `Origin`/`Referer`/`Sec-Fetch-Site`，
  避免浏览器缓存 Basic 凭据后被跨站表单触发管理动作。
- API 对外暴露 JSON（如 `GET /api/guards`、`POST /api/bless`），浏览器不直接接触底层 `OK/ERR` 文本协议。

## 13.1 集群监控面板（pgs_cluster_web）

`pgs_cluster_web` 是独立聚合器，按 5s cadence 轮询多个 remote gateway：

- 节点 registry 新保存格式为 `name;https://host:port;dpapi:<protected user:pass>`；旧 `name;https://host:port;user:pass` 兼容读取并会在下次保存时迁移。API 不回显第三列 credentials。
- 节点 URL 必须为 HTTPS，且拒绝 `user:pass@host`、query、fragment，避免凭据从 list/summary 或前端泄漏。
- 默认只监听 `127.0.0.1` 并生成本次运行 API token 嵌入本地页面；非回环监听必须提供显式
  `--api-token --tls-cert --tls-key`。
- 对节点证书默认严格校验；私有 CA 通过 `--node-ca-cert` 加入信任，`--node-insecure-tls` 才退回
  `VerifyNone`（实验环境用）。
- 轮询缓存用 node generation + request serial 校验，删除/重加同名节点或旧响应晚返回时不会污染新节点状态。

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

- GitHub Actions 会在 Windows runner 上用 MSYS2 MinGW64 构建 C++ 主线，并把 core unit、sched cron unit、smoke test 拆成独立步骤。
- Qt Web 端通过 `tools/build_qt_web.sh` 单独构建，同时覆盖 `pgs_admin_web` 与 `pgs_cluster_web`，确保共享 PGSClient 没有破坏两个 Web 控制面。
- 需要管理员权限才能完整验证 ProgramData 下的持久化恢复（见鲁棒性文档）。

## 7.2 CI 备注

- GitHub Actions 现在走 Windows runner + MSYS2 的方式；unit / smoke / Qt Web 分步执行，失败时先看对应阶段日志。
## 16. v3 加固补充（Job Object / IOCP / WindowsApps / 归档 v3 / 模块白名单）

> 本节为 v3 加固引入的架构变更汇总，遇与上文不一致处以本节为准。策略语义详见 [`GUARD_POLICIES.md`](GUARD_POLICIES.md)，模块细节详见 [`MODULE_SYSTEM.md`](MODULE_SYSTEM.md)，服务身份详见 [`SERVICE_MODE_GUIDE.md`](SERVICE_MODE_GUIDE.md)。

### 16.1 数据结构（v3 字段）

`PGDefines.h` 新增 `AppKind { Win32 = 0, WinApp = 1 }`。以下结构全部向后兼容扩展，缺省即旧语义：

- **`GuardInfo`** 增：`appKind`、`aumid`（WindowsApps 的 ApplicationUserModelId）、`restartWindowSec`、`restartDelayMs`、`backoff`(bool)、`hangTimeoutMs`、`killOnExit`(bool)、`jobHandle`( HANDLE, 命名 Job)、`recentRestartMs`（向量，滑动窗口内重启时间戳）。
- **`RestartPolicyState`** 按 `guardId` 持有 `maxRestarts`、`restartCount` 与 `recentRestartMs`。
  `window>0` 时 `restartCount` 由窗口内 `recentRestartMs` 裁剪后长度得出；`window=0` 时退化为生命周期累计，兼容旧 `maxRestarts` 语义。
- **`PersistedGuardState`** 增：`appKind`、`aumid`、`restartWindowSec`、`restartDelayMs`、`backoff`、`hangTimeoutMs`、`killOnExit`。

`fileHash` 字段注释更正：实际为 **SHA-256 hex（经 CNG/BCrypt 计算）**，而非早先文档误写的 FNV-1a。

### 16.2 Job Object 全级联监控

每个 guard 持有一个**命名 Job** `Global\PGS-Job-<guardId>`（`CreateJobObjectW` 带 `lpName`）。默认**不**置 `JOB_OBJECT_LIMIT_BREAKAWAY_OK`，故子进程/孙进程自动留挂在此 job 内，可被统一观测与级联清场。

监控由原先 200ms 轮询改为 **IOCP 完成端口**：

- `start()` 用 `CreateIoCompletionPort` 建一个完成端口，经 `JOBOBJECT_ASSOCIATE_COMPLETION_PORT` 绑定到每个 guard 的 Job。
- `monitorLoop` 改为 `GetQueuedCompletionStatus` 等待 `JOB_OBJECT_MSG_EXIT_PROCESS` / `NEW_PROCESS` / `ACTIVE_PROCESS` / `PROCESS_MEMORY` 等通知；**进程退出即时触发**重启判断，异常拖尾从 ≤200ms 降到个位数毫秒。
- `--monitor-interval`（默认 200ms）退化为「hang 体检周期」与「IOCP 兜底超时」。

级联语义：`restart` / `unregister` / `intentional` 触发 `TerminateJobObject(hJob)` 清掉整族孙进程后再重拉，实现「重启一并清场」。服务自重启后若原进程仍活，`OpenJobObject` 取回命名 Job 并 `AssignProcessToJobObject` 重新挂接（Win8+ nested job 允许跨 PGS 进程复接管），不重启它。

**`KILL_ON_JOB_CLOSE` 默认关闭**：保证 PGS 自身崩溃时守护对象仍存活，归档复接管才成立。`--kill-on-exit` 在注册时打开该标志，用户显式选择「PGS 退出时连守护对象一起死」。理由写在 `createGuardJob()` 注释里。

### 16.3 WindowsApps（UWP/Store）守护

新增 `--aumid <ApplicationUserModelId>` 与 `--winapp`（强制标记 WinApp、跳过探测）。

**自动探测**：注册 path 命中 `...\WindowsApps\<PackageFullName>\` 模式时，读其 `<PackageRoot>\AppxManifest.xml`，解析 `<Identity Name= Publisher= Version= ProcessorArchitecture=/>` 与首个 `<Application Id=/>`；用 BCrypt(SHA-256) 实现微软文档化的 publisher hash 算法生成 `PackageFamilyName = Name_M4Hash`，再得 `AUMID = PackageFamilyName!ApplicationId`。**不引入 WinRT**。解析失败/非 WindowsApps 路径则要求显式 `--aumid`。

**激活**：`restartGuard()` 按 `appKind` 分支——Win32 走原 `restartGuardInSession`/`CreateProcessW`；WinApp 走 `restartAppGuard()`：复用 `queryUserTokenForSession` impersonate 目标会话 token → `CoInitializeEx` → `CoCreateInstance(CLSID_ApplicationActivationManager)` → `IApplicationActivationManager::ActivateApplication(aumid, args, AO_NONE, &pid)`；失败回退 `ShellExecuteW("shell:AppsFolder\<AUMID>")`。纯 BCrypt+COM，无 WinRT 头依赖。

**持久化**：WinApp guard 的 `path` 存其原始可执行路径（用于 hash/人读），`restartArgs` 存激活参数，`aumid` 单独归档（见 16.4）。

### 16.4 归档 schema v2 → v3

`kStateFileVersion = 3`。`GUARD` 行 tab 字段在旧 9 字段后追加 6 个，缺省填 `-`（向后兼容旧 9 字段记录）：

```
GUARD\t<guardId>\t<lastKnownPid>\t<sessionId>\t<maxRestartsLabel>\t<pathB64>\t<restartArgsB64>\t<fileHash>\t<intentional>\t<hashVerified>\t<appKind(win32|winapp)>\t<aumidB64(->)>>\t<restartWindowSec>\t<restartDelayMs>\t<backoff(0|1)>\t<hangTimeoutMs>\t<killOnExit(0|1)>
```

另新增（可选行）：

- `RESTART\t<guardId>\t<epochMs>`：记录窗口内各次重启时间戳，归档前裁剪到窗口内；`loadPersistedState` 据此重建 `recentRestartMs`。
- `RESTART_COUNT\t<guardId>\t<count>`：记录生命周期累计重启次数；窗口模式下也会写出当前计数，
  但加载后以裁剪后的 `RESTART` 时间戳数量为准。
- `SERVER_PORT\t<port>`：恢复监听端口；缺省 12345。
- `MODULES_PERMISSIVE\t1`：恢复 `--allow-all-modules` 宽松开关。

恢复语义：若归档 PID 仍活且路径匹配，则复接管且不消耗预算；若缺失进程需要重新拉起，则这次 restore restart
也计入 `restartCount`/窗口。例外是 delayed/backoff restart 已经在进入 pending 队列前记账并把
`lastKnownPid=0` 持久化；若服务在 delay 期间重启，restore 会完成这次已记账的 relaunch，不再二次扣预算。
达到上限或 restore relaunch 失败的 guard 会从归档删除，避免服务下次启动再次复活。

**迁移**：`version==2` 走保持迁移（老记录字段补默认：Win32/无 aumid/window=0=生命周期累计/delay=0/no backoff/hang=0/killOnExit=0），日志提示一次升级；`version<2` 沿用现有 v1→v2 重置 token 哈希的迁移链。旧客户端协议动词（register/unregister/...）保持不变，`bless`/`unbless`/`bless-start` 作为协议层别名加入，消除「CLI 用 bless、协议用 register」的认知分叉。

### 16.5 协议版本与 stats

- 新增 `version` 命令返回 `OK protocol=3 min=2`；`ping`/`stats` 响应追加 `protocol=3`。
- `stats` 升级为：`OK guards=<N> active=<N> totalRestarts=<N> restartsInWindow=<N> uptime=<S>`。
- `stats` / `list --json` / `get` 均补 `appKind`/`aumid`/`restartWindow`/`recentRestarts`。

### 16.6 模块白名单 + Authenticode（架构视角）

`ModuleManager::load` 校验链：命中白名单 → （签名要求开启时）`WinVerifyTrust` 验 Authenticode → 哈希校验 → 全过才 `LoadLibrary`。白名单文件 `<exe>\modules\modules.allow`，逐行 `name[|sha256Hex[|signed]]`。**默认 fail-closed**：白名单缺失即拒绝加载任何模块并告警；`--allow-all-modules`（持久化于 `MODULES_PERMISSIVE\t1`）开启旧宽松行为用于开发。PPL opt-in 时会递归加固 modules tree 的子目录和文件 ACL，任一失败即拒绝加载 PPL 模块。详见 `MODULE_SYSTEM.md`。

### 16.7 `--port` 与服务身份

`pgs_service` 的 `run`/`install` 新增 `--port <port>`；`install` 写入服务 binPath `--service --port <p>`；`PGS::initialize` 接受外部端口，优先于 `kServerPort`(12345)，并经归档 `SERVER_PORT` 行恢复。服务身份默认仍 LocalSystem（跨会话 `restartGuardInSession` 依赖），`--service-account`/`--service-password` 可选低权账号但风险见 `SERVICE_MODE_GUIDE.md`。

### 16.8 节流说明

本轮 token 仍走环境变量 `PGS_AUTH_TOKEN`（继承风险与后续 named-pipe 演进建议记录于 `SERVICE_MODE_GUIDE.md`，本轮不重设计）。
