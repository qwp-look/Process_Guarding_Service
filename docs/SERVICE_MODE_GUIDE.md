# PGS 服务模式使用说明

## 1. 作用范围

本仓库仅保留 `PGS + pgs_service` 主线：

- 服务核心：`src/service/PGS.cpp`
- 服务入口：`src/service/pgs_service.cpp`
- 运维工具：`tools/pgs_bless.cpp`
- Qt 管理端：`qt/pgs_admin_qt`
- 浏览器控制端：`qt/pgs_admin_web`

## 2. MSYS2 MinGW64 编译命令（C++）

在 `MSYS2 MinGW64` 终端执行：

```bash
cd /c/Users/wtg/Desktop/other/MY-code/process_protect
mkdir -p build

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

也可以直接执行仓库脚本：

```bash
./tools/build_pgs.sh
```

## 3. MSYS2 MinGW64 编译命令（Qt）

在 `MSYS2 MinGW64` 终端执行：

```bash
cd /c/Users/wtg/Desktop/other/MY-code/process_protect
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

`pgs_admin_web` 与 `pgs_cluster_web` 使用 Qt 6.8+ 的 `QTcpServer` / `QHttpHeaders` /
`QSslServer` API，并通过仓库内的轻量 HTTP/1.1 分发层承载浏览器 API；由于响应对象仍使用
`QHttpServerResponse`/`QHttpHeaders`，构建环境仍需安装 Qt6 HttpServer 组件。MSYS2 当前 Qt 6.11 可直接构建：

```bash
cmake -S qt/pgs_admin_web -B build/pgs_admin_web -G "MinGW Makefiles" \
  -DCMAKE_PREFIX_PATH=/mingw64 \
  -DCMAKE_CXX_COMPILER=/mingw64/bin/g++.exe
cmake --build build/pgs_admin_web -j4

cmake -S qt/pgs_cluster_web -B build/pgs_cluster_web -G "MinGW Makefiles" \
  -DCMAKE_PREFIX_PATH=/mingw64 \
  -DCMAKE_CXX_COMPILER=/mingw64/bin/g++.exe
cmake --build build/pgs_cluster_web -j4
```

## 3.1 编译验证与烟测

推荐优先使用：

```bash
./tools/verify_pgs.sh
```

这个脚本会顺序执行：

- 主线文件存在性检查
- C++ 主线编译
- 控制台 `run` 模式烟测
- Qt 桌面端配置与编译
- 浏览器控制端配置与编译

如果当前机器已有其它 PGS 占用默认端口，只想跳过烟测，可使用：

```bash
PGS_SKIP_SMOKE=1 ./tools/verify_pgs.sh
```

## 4. 服务管理命令（管理员权限）

```bash
./build/pgs_service.exe install
./build/pgs_service.exe start
./build/pgs_service.exe status
./build/pgs_service.exe stop
./build/pgs_service.exe uninstall
```

说明：

- `install` 现在不只是创建服务项，也会同时配置 Windows SCM 的失败恢复动作。
- 如果服务因为崩溃或异常退出而失败，SCM 会按预设延迟自动尝试重启它。
- 这属于系统级“守护服务自身”的方案，比在同一进程里自监控更可靠。
- PGS 还会把守护集合和 token hash 一起归档，服务被恢复后会先读档再重建守护状态。

### 示例程序连接说明

`guard_example` 和 `quick_start` 现在支持 `--token`。当 PGS 不是空 token 时，示例程序也必须带同一 token：

```bash
./build/guard_example.exe --token your-secret-token --max-restarts 3
./build/quick_start.exe --logic --token your-secret-token --max-restarts 3
```

## 4.1 Token 鉴权配置（包含 Windows 服务模式）

PGS 当前 token 规则：

- 默认始终开启鉴权（服务模式/非服务模式一致）
- **空 token 不再被接受**：若本次启动未显式提供 token、且无持久化 token，服务会用密码学随机数生成一个 token，其 **SHA-256** 哈希存入内存与持久化，明文写入受限目录（仅 SYSTEM/Administrators 可读）下的 pgs_initial_token.txt 并在日志记录路径。
- token 仅以 **SHA-256** 哈希形式持久化（状态文件版本 2），不保存明文；旧版（v1）FNV 哈希在迁移时被丢弃并强制重生成 token。
- state/logs 目录以受限 ACL 创建（仅 SYSTEM + Administrators），避免本地其他用户读取 token 哈希。
- token hash 会跟随守护归档一起恢复
- **token 不走命令行**：Qt 管理端与 Web 控制台通过环境变量 PGS_AUTH_TOKEN 把 token 传给 pgs_bless，避免被本地其他用户经进程命令行查询泄露。

### 控制台运行模式

可在启动时设置/更新 token：

```bash
./build/pgs_service.exe run --token your-secret-token
```

若当前启动显式指定了 token，它会覆盖归档里的旧 token hash；若本次启动没有显式指定，则会优先尝试从归档恢复。

当前控制台 `run` 模式也补上了 `Ctrl+C / CTRL_CLOSE_EVENT` 的优雅停服处理，方便本地调试和烟测收尾。

### Windows 服务模式

安装并启动服务：

```bash
./build/pgs_service.exe install
./build/pgs_service.exe start
```

服务由 SCM 恢复后，会先读取守护归档和 token hash 再恢复现场。只有首次启动且此前没有旧归档时，服务会自动生成随机 token 并写入 `pgs_initial_token.txt`（目录 ACL 仅 SYSTEM+Administrators）。要切换 token，使用 `token-set` 命令。

### 客户端携带 token

方式 1：显式参数

```bash
./build/pgs_bless.exe ping --token your-secret-token
./build/pgs_bless.exe list --token your-secret-token
```

Qt 管理端：

- 在 token 输入框填写 token，界面会通过环境变量 `PGS_AUTH_TOKEN` 传给 `pgs_bless`（不再出现在命令行）。
- 在“新 token”输入框填写新值，点击“更新 Token”会执行 `token-set`。

方式 2：环境变量（推荐，避免命令行泄露）

```bash
export PGS_AUTH_TOKEN=your-secret-token
./build/pgs_bless.exe ping
```

### 更新 token（先验证旧 token）

```bash
./build/pgs_bless.exe token-set --old-token old-token --new-token new-token --token old-token
```

说明：

- 只有旧 token 验证通过，才会更新为新 token
- 只保存 token hash，不保存 token 明文
- 服务重启后会从归档恢复当前 token hash
- 当前默认归档位置通常是 `C:\ProgramData\ProcessGuard\state\pgs_guard_state.db`

### 生效验证

```bash
./build/pgs_bless.exe ping
# 未带 token 会返回 ERR auth failed（空 token 不再被接受）

./build/pgs_bless.exe ping --token your-secret-token
# 应成功：OK pong
```

## 5. 常用运维命令

```bash
./build/pgs_bless.exe ping
./build/pgs_bless.exe list
./build/pgs_bless.exe bless --pid 1234 --max-restarts 3 --hash auto
./build/pgs_bless.exe bless-start --path "C:/程序/示例.exe" --start-args "--mode worker" --max-restarts 3 --hash auto
./build/pgs_bless.exe bless-start --command "\"C:/程序/示例.exe\" --mode worker --safe" --max-restarts 3 --hash auto
./build/pgs_bless.exe unbless-path --path "C:/程序/示例.exe"
./build/pgs_bless.exe token-set --old-token old-token --new-token new-token --token old-token
./build/pgs_bless.exe policy --pid 1234 --max-restarts no
./build/pgs_bless.exe unbless --pid 1234
./build/pgs_bless.exe get --pid 1234 --json
```

这些命令的用途如下：

- `./build/pgs_bless.exe ping`  
  用于检查 PGS 服务是否在线、端口与协议是否可达。

- `./build/pgs_bless.exe list`  
  列出所有已注册守护目标，包含 PID、路径、重启策略、重启计数、hash 信息等。

- `./build/pgs_bless.exe bless --pid 1234 --max-restarts 3 --hash auto`  
  将目标进程注册为守护对象；当进程异常退出时，最多自动重启 3 次；`--hash auto` 会自动计算并上报文件 hash 用于一致性校验。

- `./build/pgs_bless.exe bless-start --path "C:/程序/示例.exe" --start-args "--mode worker" --max-restarts 3 --hash auto`  
  按路径直接启动程序并自动注册守护；适合第三方进程未先运行时的一键接管场景。  
  该命令使用宽字符启动路径处理，支持中文路径。
  当前实现会先“挂起启动”，待 PGS 注册成功后再恢复主线程，从而尽量避免“进程已启动但未纳管”的窗口。  
  如果未显式指定 `--restart-args`，默认会把 `--start-args` 写入 PGS，后续重启沿用。

- `./build/pgs_bless.exe bless-start --command "\"C:/程序/示例.exe\" --mode worker --safe" --max-restarts 3 --hash auto`  
  按“自定义完整命令”启动并自动注册守护。  
  如果未显式指定 `--restart-args`，默认会把该命令中的参数部分写入 PGS，后续重启沿用。

- `./build/pgs_bless.exe policy --pid 1234 --max-restarts no`  
  在线更新指定进程的重启策略，这里表示“无限重启”。

- `./build/pgs_bless.exe unbless --pid 1234`  
  取消该 PID 的守护，PGS 后续不再监控和拉起该进程。

- `./build/pgs_bless.exe get --pid 1234 --json`  
  查询单个守护目标详情，并以 JSON 输出，适合自动化脚本或外部系统解析。

- `./build/pgs_bless.exe unbless-path --path "C:/程序/示例.exe"`  
  按路径取消守护。若同一路径有多个被守护 PID，会批量取消。

- `./build/pgs_bless.exe token-set --old-token old-token --new-token new-token --token old-token`  
  先校验旧 token，再更新为新 token，并立即把 token hash 写回归档。

## 5.1 Qt 管理端对应功能

`pgs_admin_qt` 已提供下列 GUI 操作：

- 三标签页结构：
  - `守护管理 / Bless Console`：调用 `pgs_bless.exe`
  - `服务管理 / Service Console`：调用 `pgs_service.exe`
  - `守护表格 / Guard Table`：调用 `pgs_bless list --json` 并展示为表格
- 守护管理页：
  - `路径启动并守护`（`Start + Bless`）：对应 `bless-start`。
    可填“启动路径 + 启动参数”，也可直接填“自定义启动命令”。
  - `按 PID 守护`（`Bless PID`）：对应 `bless --pid ...`。
  - `取消守护`（`Unbless`）：当“启动路径”不为空时按路径取消（`unbless-path`）；否则按 PID 取消（`unbless --pid`）。
  - `更新 Token`（`Set Token`）：对应 `token-set`。
- 服务管理页：
  - `Install/Status/Start/Stop/Uninstall/Run Console`：分别对应 `pgs_service` 同名命令。
  - `Reset Service`：顺序执行 `stop -> uninstall -> install -> start`。
- 守护表格页：
  - `Refresh`：拉取最新守护列表并表格展示。
  - 字段包含：`PID/Path/Hash/Restarts/Max/Alive/Session/HashVerified`。
  - 自动刷新默认改为 `1000 ms`，并且自动刷新时不再每轮重排列表宽。
- 两页日志窗口独立，均支持 `Clear Log`。
- `语言切换`：可在 `中文 / English` 之间切换界面文案。

补充说明：

- Qt 桌面端现在只保留本地运维壳层职责。
- 真正的浏览器控制端由 `pgs_admin_web` 单独承担，见 `docs/WEB_CONTROL_CONSOLE_PLAN.md`。

## 5.2 浏览器控制端

`pgs_admin_web` 是独立 Web 管理进程，不直接嵌在 Qt 桌面端里。

手动编译：

```bash
cmake -S qt/pgs_admin_web -B build/pgs_admin_web -G "MinGW Makefiles" \
  -DCMAKE_PREFIX_PATH=/mingw64 \
  -DCMAKE_CXX_COMPILER=/mingw64/bin/g++.exe

cmake --build build/pgs_admin_web -j4
```

运行示例：

```bash
./build/pgs_admin_web/pgs_admin_web.exe --bind 127.0.0.1 --http-port 18080 --pgs-token your-secret-token
```

特点：

- 浏览器访问 `http://127.0.0.1:18080`
- Web 后端直连 `PGSClient` 处理高频 `ping/list/get`，必要时仍复用 `pgs_bless.exe` / `pgs_service.exe`
- 当前提供守护列表、守护操作、token 更新、服务管理等能力
- 默认本地模式只允许回环绑定，页面内嵌一次性 API token，API 同时校验 Host/Origin。
- remote 模式使用 `--remote --tls-cert --tls-key --users-file --audit-log`，强制 TLS + Basic RBAC + 审计。
  remote 页面不嵌入 PGS 管理 token；变更类 API 额外要求同源 `X-PGS-CSRF`。

远程模式示例：

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

## 5.3 集群监控面板

本地模式：

```bash
./build/pgs_cluster_web/pgs_cluster_web.exe --listen-port 19090 --nodes-file pgs_cluster_nodes.txt
```

非回环监听必须使用 HTTPS + dashboard API token：

```bat
./build/pgs_cluster_web/pgs_cluster_web.exe ^
  --listen-address 0.0.0.0 ^
  --listen-port 19090 ^
  --nodes-file pgs_cluster_nodes.txt ^
  --api-token dashboard-token ^
  --tls-cert cert.pem ^
  --tls-key key.pem
```

节点文件格式为 `name;https://host:port;user:pass`。URL 不允许嵌入 `user:pass@host`，
API 也不会回显第三列凭据；但文件本身仍是明文，生产部署请限制 ACL。

## 5.4 `pgs_bless` 参数详解

通用参数：

- `--host <ip>`：PGS 地址，默认 `127.0.0.1`
- `--port <port>`：PGS 端口，默认 `12345`
- `--token <value>`：鉴权 token（服务端始终开启鉴权，客户端建议显式传）
- `--old-token <value>`：仅 `token-set`，旧 token（不传时默认等于 `--token`）
- `--new-token <value>`：仅 `token-set`，新 token
- `--json`：`list/get` 输出 JSON

守护注册参数：

- `--pid <pid>`：`bless` 目标 PID
- `--path <exe>`：`bless-start` 必需；`bless` 中可覆盖自动探测路径
- `--start-args "..."`：仅 `bless-start`，用于首次启动参数
- `--command "..."`：仅 `bless-start`，完整启动命令（与 `--path` 互斥）
- `--max-restarts N|no`：最大异常重启次数；`no` 表示无限重启
- `--restart-args "..."`：PGS 重启时使用的参数
- `--hash auto|none|HEX`：文件 hash 策略（自动、关闭、自定义）

命令与必需参数对照：

- `bless`：`--pid`
- `bless-start`：`--path`
- `bless-start`：`--path` 或 `--command`（二选一）
- `policy`：`--pid --max-restarts`
- `unbless`：`--pid`
- `unbless-path`：`--path`
- `intentional`：`--pid`
- `get`：`--pid`

## 6. 运行时 DLL 要求

请优先使用 `/mingw64/bin` 同版本运行库，核心 DLL：

- `libstdc++-6.dll`
- `libgcc_s_seh-1.dll`
- `libwinpthread-1.dll`

Qt 程序建议部署：

```bash
/mingw64/bin/windeployqt-qt6.exe build/pgs_admin_qt/pgs_admin_qt.exe
cp -f /mingw64/bin/libstdc++-6.dll build/pgs_admin_qt/
cp -f /mingw64/bin/libgcc_s_seh-1.dll build/pgs_admin_qt/
cp -f /mingw64/bin/libwinpthread-1.dll build/pgs_admin_qt/
```

## 7. 安全运行建议

### 默认权限面（LocalSystem）

`pgs_service` 以 Windows 服务方式安装后默认运行在 `LocalSystem` 账户下，具备 `SeTcbPrivilege`、加载驱动等高特权。叠加 PPL 模块（可加载内核驱动、对任意进程设 PPL）后，能触及的能力面非常大。请仅在受信任的单机上、且确实需要 PPL 能力时才启用相关功能。

### 最小权限运行建议

- **默认不启用 PPL/驱动**：PPL 模块（`modules/ppl`）与 `Sirius.sys` 内核驱动默认**不加载**。仅当设置环境变量 `PGS_ENABLE_PPL=1` 或向 `pgs_service` 传入 `--enable-ppl` 时才加载。非 opt-in 部署下，`ppl set/get/clear` 不可达，内核驱动也不会被引入。
- **token 鉴权强制开启**：空 token 不再被接受；未配置 token 时服务自动生成随机 token 并写入受限目录下的 `pgs_initial_token.txt`（仅 SYSTEM/Administrators 可读）。token 哈希为 SHA-256，state/logs 目录以受限 ACL 创建。
- **token 不走命令行**：Qt 管理端与 Web 控制台通过环境变量 `PGS_AUTH_TOKEN` 传 token 给 `pgs_bless`，避免被本地其他用户经进程命令行查询泄露。
- **`module load` 路径白名单**：服务端只允许加载位于模块目录之内的 DLL，`..`/UNC/盘外绝对路径一律拒绝，避免任意 DLL 被加载进 SYSTEM 级服务进程。
- **绑定回环**：PGS 管理端口默认绑定 `127.0.0.1`；Web 控制台默认绑定 `127.0.0.1` 并要求 `X-PGS-Token` 头 + `Host`/`Origin` 校验（防 DNS rebinding 与跨站 CSRF）。远程 Web 控制台必须显式 `--remote`，并配置 TLS、RBAC users 文件和 audit log。
- **cluster 远程监听强制 TLS+token**：`pgs_cluster_web` 默认只监听回环；非回环监听必须提供 `--api-token --tls-cert --tls-key`。
- **不要在不受信任的主机启用 PPL**：`Sirius.sys` 一旦加载常驻并暴露 `\\.\Sirius` 设备，具备 ARK 级内核能力（终止/隐藏/注入/改 token/读写内存/关 PatchGuard/关 DSE 等），任何能打开该设备的本地主体都获得完整内核级能力；用户态无法修改驱动设备 DACL。

### 进一步收敛（按需）

- 若不需要 PPL，可从构建产物中移除 `modules/ppl` 目录，使即便误设 `PGS_ENABLE_PPL=1` 也无模块可加载。
- 考虑以自定义低权限服务账户运行 `pgs_service`（需评估守护目标进程所需的访问权），以缩小 LocalSystem 特权面。

## 8. v3 加固补充（LocalSystem 取舍 / 服务账号 / 端口 / token 风险）

> 本节为 v3 引入的服务身份与端口相关变更，遇与上文不一致处以本节为准。

### 8.1 为什么默认仍是 LocalSystem

PGS 的核心能力之一是**跨会话重启守护对象**：用户在 Session 1/2 登录，PGS 需在目标会话内 `CreateProcessAsUserW`/`ActivateApplication` 拉起进程。这要求服务进程具备 `SE_TCB_NAME` 与对其它会话 token 的访问权，**LocalSystem 天然满足**，是跨会话守护的最稳路径。

### 8.2 `--service-account` / `--service-password`（可选低权账号）

`install` 新增可选 `--service-account <name> --service-password <pw>`，透传 `CreateServiceA` 的 `lpServiceStartName`/`lpPassword`，默认仍 LocalSystem。

**显式警告**：换用低权服务账号后——

- **丧失跨会话 `restartGuardInSession` 能力**：低权账号通常无 `SE_TCB_NAME`，无法 impersonate 目标会话 token，重启将在 Session 0 起控制台进程，GUI 守护对象可能拉不起来或拉到错误会话。
- **WindowsApps 激活受限**：`ActivateApplication` 依赖会话 token impersonation，低权账号下回退到 `ShellExecuteW` 也可能失败。
- 仅在你**明确知道代价**且守护对象本身不需要跨会话 GUI 时才考虑，并自负由此导致的守护失败。

### 8.3 `--port <port>` 配置

`run`/`install` 新增 `--port`；`install` 写入服务 binPath `--service --port <p>`，`PGS::initialize` 接受外部端口并优先于内置默认 `kServerPort`(12345)，归档 `SERVER_PORT` 行在服务恢复时还原端口。`pgs_bless`/Qt/Web 客户端需用相同端口连接。

### 8.4 Token 继承风险与后续演进

本轮 token 仍经环境变量 `PGS_AUTH_TOKEN` 传递：

- 环境变量可被子进程继承，存在**通过同会话子进程窃取 token** 的风险面。
- 本轮**不**重设计为 named-pipe/Kerberos 方案，作为独立跟踪项后续推进；当前缓解：服务专有 DACL 限制可读、`pgs_initial_token.txt` 已限权、token 仅存哈希不存明文。
- 部署于多用户/不可信本机环境时，请额外评估此风险面或等待 named-pipe 方案落地。
