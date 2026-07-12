# Process_Guarding_Service
一个利用AI-Codeing的windows进程守护小工具
本项目由qwp-look和AI一同开发

## 普通用户快速开始

推荐优先使用安装包：以管理员身份运行 `pgs_setup_3.1.0.exe`，按向导安装。默认会把程序装到 `Program Files\ProcessGuard`，可选安装并启动 PGS Windows 服务、启用 Sirius PPL 驱动所需的测试签名模式、添加远程网关防火墙规则。安装完成后可启动 **PGS 管理端（Qt）**，填写当前 token 后添加、查看、取消守护进程。

首次安装服务后，如果没有旧状态归档，PGS 会自动生成随机 token，明文只写入受限目录下的 `C:\ProgramData\ProcessGuard\state\pgs_initial_token.txt`，token hash 会随状态归档持久化。卸载时安装器会删除安装目录、停止并卸载 PGS 服务、移除防火墙规则；`C:\ProgramData\ProcessGuard` 默认保留，便于重装后恢复守护列表和 token hash，卸载过程会询问是否删除。

如果使用便携包，解压后在管理员终端执行：

```bat
pgs_service.exe install
pgs_service.exe start
pgs_admin_qt.exe
```

普通运维只需要这些文档：

- 服务安装、token、常用命令：[`docs/SERVICE_MODE_GUIDE.md`](docs/SERVICE_MODE_GUIDE.md)
- 模块与 PPL 驱动：[`docs/MODULE_SYSTEM.md`](docs/MODULE_SYSTEM.md)
- 远程 Web 网关：[`docs/REMOTE_GATEWAY.md`](docs/REMOTE_GATEWAY.md)
- 集群监控面板：[`docs/CLUSTER_DASHBOARD.md`](docs/CLUSTER_DASHBOARD.md)

## 开发者构建入口

开发环境推荐 MSYS2 MinGW64。脚本默认使用 `C:\msys64\mingw64`，也支持通过环境变量改路径：

```bat
set MINGW_ROOT=C:\msys64\mingw64
set CXX=%MINGW_ROOT%\bin\g++.exe
set CMAKE=%MINGW_ROOT%\bin\cmake.exe
set MSYS2_BASH=C:\msys64\usr\bin\bash.exe
tools\verify.bat
```

```bash
export MINGW_ROOT=/mingw64
export GXX=$MINGW_ROOT/bin/g++.exe
export CMAKE=$MINGW_ROOT/bin/cmake.exe
./tools/verify_pgs.sh
```

Qt 桌面管理端继续保留 Qt Widgets 是合理的；Web/Cluster 后端若后续要进一步轻量化，可以把 HTTP/JSON/TLS 聚合层逐步迁移到 Boost.Asio/Beast + Boost.JSON，减少 QtHttpServer 类型依赖。但这属于中期架构重构，不建议在当前交付里贸然替换桌面端 Qt。

# ProcessGuard（PGS 服务主线）

本仓库已统一为一条实现主线：

- `PGS`：进程守护服务核心（监听注册、监控、重启、策略）
- `pgs_service`：Windows 服务宿主（安装/启动/停止/卸载）
- `pgs_bless`：命令行运维工具（注册、查询、撤销、改策略）
- `pgs_admin_qt`：Qt 图形管理端（调用 `pgs_bless`）
- `pgs_admin_web`：浏览器控制端（独立 Web 管理进程）

> **新增：模块系统 + PPL 模块**
> PGS 现支持可加载模块（插件）：把功能写成 DLL 放入 `<exe>/modules/`，启动自动加载，通过 `pgs_bless` 的 `module` / `ppl` 子命令调用。首个模块 **pgs_ppl_module** 复用 StarlightGUI 的 `Sirius.sys` 内核驱动，对进程设置/查询/清除 PPL 保护。
> 详见 [`docs/MODULE_SYSTEM.md`](docs/MODULE_SYSTEM.md)。

## 1. 环境要求

建议只使用 `MSYS2 MinGW64` 工具链：

- `C:\msys64\mingw64\bin\g++.exe`
- `C:\msys64\mingw64\bin\cmake.exe`
- Qt 6.8+（`/mingw64` 下的 Qt CMake 包；MSYS2 当前 Qt 6.11 可用）

附带脚本：

- `tools/build_pgs.sh`：使用原生 `MSYS2 MinGW64` 构建 C++ 主线
- `tools/verify_pgs.sh`：使用原生 `MSYS2 MinGW64` 做文件检查 + C++/Qt/Web 实际编译验证
- `tools/smoke_test_pgs.sh`：控制台 `run` 模式烟测，覆盖 token 持久化与守护恢复
- `tools/verify.bat`：Windows 入口，内部转调 `MSYS2 bash` 执行 `tools/verify_pgs.sh`
- `src/common/PGSClient.cpp`：共享 TCP 行协议客户端（CLI / Web 复用）
- `src/service/PGSProtocol.cpp`：协议分发与命令处理，和核心生命周期逻辑分离

## 2. MSYS2 MinGW64 手动编译（C++ 部分）

在 `MSYS2 MinGW64` 终端执行：

```bash
cd /c/Users/wtg/Desktop/other/MY-code/Process_Guarding_Service
mkdir -p build

# 可选：固定 PATH，避免串库
export PATH=/mingw64/bin:/usr/bin
hash -r

g++ -std=c++17 -Wall -Wextra -O2 -Iinclude -c src/common/PGLogger.cpp -o build/PGLogger.o
g++ -std=c++17 -Wall -Wextra -O2 -Iinclude -c src/service/PGS.cpp -o build/PGS.o
g++ -std=c++17 -Wall -Wextra -O2 -Iinclude -c src/service/pgs_service.cpp -o build/pgs_service.o
g++ -std=c++17 -Wall -Wextra -O2 \
  build/PGLogger.o build/PGS.o build/pgs_service.o \
  -o build/pgs_service.exe \
  -lws2_32 -ladvapi32 -lwtsapi32 -luserenv

g++ -std=c++17 -Wall -Wextra -O2 -Iinclude tools/pgs_bless.cpp -o build/pgs_bless.exe -lws2_32
g++ -std=c++17 -Wall -Wextra -O2 -Iinclude examples/guard_example.cpp -o build/guard_example.exe -lws2_32
g++ -std=c++17 -Wall -Wextra -O2 -Iinclude examples/quick_start.cpp -o build/quick_start.exe -lws2_32
g++ -std=c++17 -Wall -Wextra -O2 -Iinclude examples/smoke_worker.cpp -o build/smoke_worker.exe -lws2_32

# 复制 MinGW 运行库到 C++ 可执行目录（build/）
cp -f /mingw64/bin/libstdc++-6.dll build/
cp -f /mingw64/bin/libgcc_s_seh-1.dll build/
cp -f /mingw64/bin/libwinpthread-1.dll build/
```

生成：

- `build/pgs_service.exe`
- `build/pgs_bless.exe`
- `build/guard_example.exe`
- `build/quick_start.exe`
- `build/smoke_worker.exe`

示例程序连接 PGS 时也需要 token（与服务当前 token 一致）：

```bash
./build/guard_example.exe --token your-secret-token --max-restarts 3
./build/quick_start.exe --logic --token your-secret-token --max-restarts 3
```

## 3. MSYS2 MinGW64 手动编译（Qt 桌面端）

在 `MSYS2 MinGW64` 终端执行：

```bash
cd /c/Users/wtg/Desktop/other/MY-code/Process_Guarding_Service
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

Qt 产物：

- `build/pgs_admin_qt/pgs_admin_qt.exe`

> **release 打包注意（干净机器可运行）**：`windeployqt6` 只部署 Qt 自带 DLL，但 `Qt6Core/Qt6Gui/Qt6Network` 还传递依赖一批 MSYS2 MinGW 第三方运行库（ICU `libicu*78.dll`、`libharfbuzz-0.dll`、`libfreetype-6.dll`、`libpcre2-16-0.dll`、`libzstd.dll`、`zlib1.dll`、`libssl-3-x64.dll`、`libcrypto-3-x64.dll` 等）。开发机上因 `mingw64/bin` 在 `PATH` 里能跑，但**干净机器上缺这些 DLL 会让 Qt 可执行报 `0xC0000135`（STATUS_DLL_NOT_FOUND）**。一键完整打包（构建 + windeployqt6 + OpenSSL TLS plugin + 补齐这些 DLL + per-folder 模块 + `pgs_admin_web.exe` / `pgs_cluster_web.exe`）用：
>
> ```bat
> tools\package_release.bat
> ```

## 3.1 MSYS2 MinGW64 手动编译（网页控制端）

在 `MSYS2 MinGW64` 终端执行：

```bash
cd /c/Users/wtg/Desktop/other/MY-code/Process_Guarding_Service
rm -rf build/pgs_admin_web

cmake -S qt/pgs_admin_web -B build/pgs_admin_web -G "MinGW Makefiles" \
  -DCMAKE_PREFIX_PATH=/mingw64 \
  -DCMAKE_CXX_COMPILER=/mingw64/bin/g++.exe

cmake --build build/pgs_admin_web -j4
```

网页控制端产物：

- `build/pgs_admin_web/pgs_admin_web.exe`

运行示例：

```bash
./build/pgs_admin_web/pgs_admin_web.exe --bind 127.0.0.1 --http-port 18080 --pgs-token your-secret-token
```

随后在浏览器里打开：

```text
http://127.0.0.1:18080
```

远程 Web 管理必须显式开启 `--remote`，并配置 TLS、RBAC users 文件和 audit log：

```bat
./build/pgs_admin_web/pgs_admin_web.exe ^
  --remote ^
  --bind 0.0.0.0 ^
  --http-port 18443 ^
  --pgs-token your-secret-token ^
  --tls-cert cert.pem ^
  --tls-key key.pem ^
  --users-file users.txt ^
  --audit-log pgs_admin_audit.log
```

remote 模式下首页和 API 都走 Basic RBAC；变更类 API 还要求同源 CSRF 头。详见
[`docs/REMOTE_GATEWAY.md`](docs/REMOTE_GATEWAY.md)。

## 3.2 MSYS2 MinGW64 手动编译（集群面板）

```bash
cd /c/Users/wtg/Desktop/other/MY-code/Process_Guarding_Service
rm -rf build/pgs_cluster_web

cmake -S qt/pgs_cluster_web -B build/pgs_cluster_web -G "MinGW Makefiles" \
  -DCMAKE_PREFIX_PATH=/mingw64 \
  -DCMAKE_CXX_COMPILER=/mingw64/bin/g++.exe

cmake --build build/pgs_cluster_web -j4
```

本地运行：

```bash
./build/pgs_cluster_web/pgs_cluster_web.exe --listen-port 19090 --nodes-file pgs_cluster_nodes.txt
```

本地模式会生成本次运行 API token 并嵌入回环页面；`/api/cluster/*` 仍需 token，避免浏览器跨站写入节点注册表。

非回环监听必须同时提供 HTTPS 证书和 dashboard API token：

```bat
./build/pgs_cluster_web/pgs_cluster_web.exe ^
  --listen-address 0.0.0.0 ^
  --listen-port 19090 ^
  --nodes-file pgs_cluster_nodes.txt ^
  --api-token dashboard-token ^
  --tls-cert cert.pem ^
  --tls-key key.pem
```

节点 URL 必须是 `https://host[:port]`，不允许 `user:pass@host`。详见
[`docs/CLUSTER_DASHBOARD.md`](docs/CLUSTER_DASHBOARD.md)。
节点 TLS 默认严格校验证书；私有 CA 用 `--node-ca-cert <ca.pem>`，隔离实验环境才用
`--node-insecure-tls`。

## 4. 运行时 DLL（重要）

为避免 `nanosleep64/clock_gettime64` 等入口点错误，运行时请优先使用 `/mingw64/bin` 同版本 DLL。

至少需要：

- `libstdc++-6.dll`
- `libgcc_s_seh-1.dll`
- `libwinpthread-1.dll`

Qt 程序建议额外执行：

```bash
/mingw64/bin/windeployqt-qt6.exe build/pgs_admin_qt/pgs_admin_qt.exe
cp -f /mingw64/bin/libstdc++-6.dll build/pgs_admin_qt/
cp -f /mingw64/bin/libgcc_s_seh-1.dll build/pgs_admin_qt/
cp -f /mingw64/bin/libwinpthread-1.dll build/pgs_admin_qt/
```

## 5. 文档

- 服务使用说明：`docs/SERVICE_MODE_GUIDE.md`
- 技术架构说明：`docs/TECHNICAL_ARCHITECTURE.md`
- 鲁棒性与测试说明：`docs/ROBUSTNESS_AND_TESTING.md`
- 远程 Web 网关：`docs/REMOTE_GATEWAY.md`
- 集群监控面板：`docs/CLUSTER_DASHBOARD.md`
- 模块系统与 PPL：`docs/MODULE_SYSTEM.md`

## 5.1 Token 鉴权使用（重点）

当前实现改为：

- `PGS` 默认始终开启 token 鉴权（包括服务模式和非服务模式），**永不接受空 token**
- token 哈希采用 SHA-256（BCrypt），仅以哈希形式持久化，不保存 token 明文
- token hash 会跟随守护归档一起落盘并在服务重启后恢复（前提是服务进程有权限写入 `ProgramData\ProcessGuard`；非管理员环境下请用管理员 VM 验证）
- 若本次启动未显式提供 token，则优先从归档恢复 token hash；归档也没有时，自动生成随机 64 位十六进制 token，将其 SHA-256 写入归档，明文写入 `<stateDir>/pgs_initial_token.txt`（`state` 目录 DACL 仅授予 SYSTEM + Administrators）。查看该文件获取初始 token

### A) Windows 服务模式

安装与启动：

```bash
./build/pgs_service.exe install
./build/pgs_service.exe start
```

服务安装后由 SCM 负责异常恢复；服务进程被系统重新拉起后，会先读守护归档与 token hash，再继续恢复守护对象。
如果这是第一次启动且此前没有归档，服务会自动生成随机 token 并写入 `pgs_initial_token.txt`（位置见上文）；若要改为自定义 token，请使用 `token-set`（见下）。

### B) 非服务模式（控制台）

启动时推荐用环境变量指定当前进程 token，避免明文出现在进程命令行：

```bash
PGS_SERVICE_TOKEN=your-secret-token ./build/pgs_service.exe run
```

`--token your-secret-token` 仍保留为兼容参数。若不传 token，则会优先尝试从归档恢复 token hash；归档也没有时自动生成随机 token（明文写入 `pgs_initial_token.txt`）。

### B.1) 归档文件位置

- 默认状态归档由日志根目录推导。
- 使用当前 `pgs_service` 安装方式时，通常会落在 `C:\ProgramData\ProcessGuard\state\pgs_guard_state.db`。
- 归档中保存的是“仍应继续守护的逻辑对象”和 token hash，不保存 token 明文。

### C) 客户端如何带 token

`pgs_bless`：

```bash
./build/pgs_bless.exe ping --token your-secret-token
./build/pgs_bless.exe list --token your-secret-token
```

Qt 管理端：

- 在界面 `token` 输入框填写 token；GUI 通过环境变量 `PGS_AUTH_TOKEN` 传递给 `pgs_bless`（不走命令行，避免本地其他用户可见）。
- 在界面 `新 token` 输入框填写新值，点击 `更新 Token`，会执行 `token-set`。

### D) 更新 Token（先校验旧 token）

```bash
./build/pgs_bless.exe token-set --old-token old-token --new-token new-token --token old-token
```

说明：

- 服务端会先验证 `old-token` 是否与当前 token 一致
- 验证通过才会切换到 `new-token`
- 只持久化 token hash，不保存 token 明文
- 服务被 SCM 拉起或手动重启后，会从归档里恢复 token hash

### E) 快速验证

```bash
./build/pgs_bless.exe ping --token your-secret-token
# token 正确时：OK pong

./build/pgs_bless.exe ping --token wrong-token
# token 错误时：ERR auth failed or token missing
```

## 6. pgs_bless 常用命令说明

```bash
./build/pgs_bless.exe ping
```
- 作用：探测 PGS 服务是否在线、协议是否可达。

```bash
./build/pgs_bless.exe list
```
- 作用：列出当前所有已注册的守护目标及其状态（PID、路径、重启计数、hash 等）。

```bash
./build/pgs_bless.exe bless --pid 1234 --max-restarts 3 --hash auto
```
- 作用：将 PID=1234 注册到 PGS，最大异常重启 3 次，并自动计算并提交可执行文件 hash。

```bash
./build/pgs_bless.exe policy --pid 1234 --max-restarts no
```
- 作用：动态修改该进程策略为“不限制重启次数”。

```bash
./build/pgs_bless.exe unbless --pid 1234
```
- 作用：取消该进程的守护注册，PGS 不再监控/重启它。

```bash
./build/pgs_bless.exe get --pid 1234 --json
```
- 作用：查询单个进程的详细守护信息，并以 JSON 输出（方便脚本处理）。

```bash
./build/pgs_bless.exe bless-start --path "C:/程序/示例.exe" --start-args "--mode worker" --max-restarts 3 --hash auto
```
- 作用：按路径启动程序并立刻注册守护（一步完成“启动 + 保护”）。
- 中文路径说明：已使用宽字符启动链路（`CreateProcessW`），支持中文路径。
- 重启参数写入规则：若未显式传 `--restart-args`，会自动把 `--start-args` 记录到 PGS，后续重启沿用这些参数。

```bash
./build/pgs_bless.exe bless-start --command "\"C:/程序/示例.exe\" --profile default --safe-mode" --max-restarts 3 --hash auto
```
- 作用：用“自定义完整命令”启动并守护（含可执行路径和启动参数）。
- 重启参数写入规则：若未显式传 `--restart-args`，会自动把该命令中的参数部分写入 PGS 用于后续重启。

```bash
./build/pgs_bless.exe unbless-path --path "C:/程序/示例.exe"
```
- 作用：按路径批量取消守护（会把该路径下所有匹配 PID 全部取消）。

```bash
./build/pgs_bless.exe token-set --old-token old-token --new-token new-token --token old-token
```
- 作用：在服务端先校验旧 token，再切换到新 token（只持久化 hash，不保存明文）。

## 7. 图形控制端

### 7.1 Qt 桌面端

- 四界面（Tab）：
  - `守护管理 / Bless Console`：专门调用 `pgs_bless.exe`
  - `服务管理 / Service Console`：专门调用 `pgs_service.exe`
  - `守护表格 / Guard Table`：调用 `pgs_bless list --json` 并表格化显示
  - 模块管理 / Module Management：扫描 <pgs_service 目录>/modules 子目录，每个模块一个动态子页面（QTextBrowser 渲染该模块的 module.html），可执行 module call 与 ppl set/get/clear。
- 守护管理页支持：`Ping/List/Get/Bless/Bless-Start/Unbless/Policy/Intentional/Token-Set`。
- 服务管理页支持：`Install/Status/Start/Stop/Uninstall/Run Console`。
- 服务管理页支持：`Stop Console`（终止当前 `run` 控制台进程）。
- 服务管理页新增 `Reset Service`：顺序执行 `stop -> uninstall -> install -> start`。
- `install` 现在会同时配置 Windows SCM 故障恢复动作，服务异常退出时由系统负责自动重启。
- 两个页面各自独立日志输出，并支持单独 `Clear Log`。
- 表格页展示字段：PID、路径、hash、已重启次数、最大重启次数、存活状态、会话、hash校验状态。
- 表格页默认自动刷新降为 `1000 ms`，自动刷新时不再每轮重排列表宽；刷新失败时保留旧表格并在状态栏提示。
- 语言切换：支持 `中文 / English`。

### 7.2 浏览器控制端

- `pgs_admin_web` 是独立 Web 管理进程，不把 HTTP 逻辑塞进 `PGS` 核心。
- 浏览器访问它提供的页面；后端直连 `PGSClient` 处理高频 PGS 查询，必要时仍复用
  `pgs_bless.exe` / `pgs_service.exe`。
- 当前版本提供：守护列表、Ping、Bless、Bless-Start、Policy、Unbless、Intentional、Token 更新、服务安装/启动/停止/卸载/状态查询。
- 它默认面向本机运维，建议只绑定 `127.0.0.1`。
- Web 后端已直连 `PGSClient`，把最频繁的 `ping/list/get` 轮询从 `QProcess` 中拿掉，减少进程创建和 stdout JSON 解析开销。
- remote 模式强制 TLS + RBAC + audit log；变更类 API 额外要求同源 CSRF 头。
- 详细说明见 `docs/REMOTE_GATEWAY.md`。

## 8. `pgs_bless` 参数说明（完整）

通用参数：

- `--host <ip>`：PGS 地址，默认 `127.0.0.1`
- `--port <port>`：PGS 端口，默认 `12345`
- `--token <value>`：鉴权 token（服务端默认始终开启鉴权，建议显式传）
- `--old-token <value>`：用于 `token-set`，旧 token（不传时默认取 `--token`）
- `--new-token <value>`：用于 `token-set`，新 token
- `--json`：用于 `list/get`，JSON 输出

`bless`/`bless-start` 相关：

- `--pid <pid>`：目标 PID（用于 `bless`）
- `--path <exe>`：可执行路径（`bless-start` 必填，`bless` 可选覆盖）
- `--start-args "..."`：仅 `bless-start`，启动时附带参数
- `--command "..."`：仅 `bless-start`，完整启动命令（与 `--path` 互斥）
- `--max-restarts N|no`：最大重启次数，`no` 表示无限
- `--restart-args "..."`：PGS 重启目标进程时使用的参数
- `--hash auto|none|HEX`：文件哈希策略  
  `auto`=自动计算；`none`=不提交；`HEX`=提交指定值

其它命令参数：

- `policy`：必须 `--pid` + `--max-restarts`，可选 `--restart-args`
- `unbless`：必须 `--pid`
- `unbless-path`：必须 `--path`
- `intentional`：必须 `--pid`
- `get`：必须 `--pid`

# 声明
本项目中借鉴使用了部分StarlightGUI的代码  
仓库链接 github.com/OpenStarlight/StarlightGUI  
开发者： Stars  
许可证：Apache 2.0 许可证 |OSI 认证  
版权归 © 2026 年 Starlight 所有。  


---

## 模块系统与 PPL 模块（快速上手）

```bash
# 构建（产物含 build/modules/ppl/pgs_ppl_module.dll + Sirius.sys + module.html，per-folder 布局）
tools\build_pgs.bat

# 以管理员运行服务（需测试签名模式以加载 Sirius.sys）
set PGS_SERVICE_TOKEN=<your-token>
pgs_service.exe run

# 模块与 PPL 操作
pgs_bless.exe module list
pgs_bless.exe ppl get --pid <pid>
pgs_bless.exe ppl set --pid <pid> --signer Antimalware
pgs_bless.exe ppl clear --pid <pid>
```

完整说明（ABI、如何写新模块、排错、版权）见 [`docs/MODULE_SYSTEM.md`](docs/MODULE_SYSTEM.md)。
## 9. CI 与验证

- GitHub Actions 使用 MSYS2 MinGW64，按阶段执行 C++ 主线构建、core unit、sched cron unit、smoke test 和 Qt Web console 构建。
- 本地 unit test 可单独跑：`tools/test_core_units.sh`、`tools/test_sched_cron.sh`；`tools/run_unit_tests.sh` 保留为聚合入口。
- Qt Web console 可单独跑：`tools/build_qt_web.sh`，同时构建 `pgs_admin_web` 与 `pgs_cluster_web`。
- 本地 smoke test 的“服务重启后恢复持久化 token / 守护集”步骤需要管理员权限；在非管理员沙盒里会因为 `ProgramData\ProcessGuard` 的 ACL 受限而失败。
- 如果你要我补完整验证，开一个管理员 VM 最稳。
---

## v3 hardening 速览

- **守护监控**：Job Object 全级联 + IOCP 即时退出通知（取代纯轮询），重启清场整族进程。
- **重启策略**：`--restart-window`/`--restart-delay`/`--restart-backoff`/`--hang-timeout`/`--kill-on-exit`
  详见 [`docs/GUARD_POLICIES.md`](docs/GUARD_POLICIES.md)。
- **WindowsApps**：`--winapp --aumid <id>` 或自动探测 `WindowsApps\` 路径，经 AUMID 激活重启。
- **模块安全**：`modules.allow` 白名单 + 可选 Authenticode；默认 fail-closed，
  `pgs_service run --allow-all-modules` 为开发逃生阀，见 [`docs/MODULE_SYSTEM.md`](docs/MODULE_SYSTEM.md)。
- **Web/Cluster 远程暴露**：`pgs_admin_web --remote` 必须 TLS + RBAC + audit；
  `pgs_cluster_web` 非回环监听必须 TLS + 显式 `--api-token`，节点 TLS 默认校验。
- **端口可配**：`pgs_service run|install --port <p>`，归档 `SERVER_PORT` 自动恢复。
- **协议**：`version` 返回 `protocol=3 min=2`；`ping`/`stats` 带 `protocol=3`；新增 `bless`/`unbless`
  作为 `register`/`unregister` 别名。文件 hash 为 **SHA-256**（旧的注释里写的 FNV-1a 是笔误）。
- **归档**：`v2 → v3` 平滑迁移，旧档新字段补默认值。
