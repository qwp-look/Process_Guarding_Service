# 当前存在的安全问题及解决方案

> 文档版本：2026-07-27  
> 适用版本：PGS 0.1.0-beta.1  
> 阅读对象：项目维护者、安全审查人员

---

## 一、背景

PGS 作为 Windows 服务以 SYSTEM 或管理员权限运行，持有目标进程的生命周期控制权，并通过 TCP 端口暴露管理 API。攻击面集中于：管理协议认证边界、模块加载链路、文件系统权限、持久化数据、UI 层凭据处理和高风险模块的执行边界。

本文基于源码评审和已有安全交接文档，系统梳理各类安全风险，并给出明确的修复思路和实施建议。

---

## 二、风险分类总览

| 类别 | 风险等级 | 是否阻塞功能版发行 |
|------|---------|-----------------|
| 管理协议认证（本地 TCP + token） | 高 | 否，阻塞安全版 |
| 代码签名缺失 | 高 | 否，阻塞公开发行 |
| 模块加载链路（allowlist / ACL） | 高 | 否，阻塞安全版 |
| bootstrap token 文件权限 | 中（核心已完成） | 否；提升权限/VM 专项验证延期，不阻塞功能版 |
| 输入校验（命令参数/JSON 解析） | 中 | 否 |
| Web 层凭据与 CSRF | 中（已部分修复） | 否 |
| 高风险模块执行边界 | 中 | 否，阻塞生产声明 |
| 审计日志完整性 | 中 | 否 |
| 路径处理与目录遍历 | 中 | 否 |
| 依赖安全 | 低 | 否 |

---

## 三、各类安全问题详述

### 3.1 管理协议认证：裸 loopback TCP + token

**现状**

管理协议通过 `127.0.0.1:12345` 监听，客户端发送 `token <base64-token> <command>` 信封。服务端存储 token 的 SHA-256 哈希，不存明文。

**风险**

- token 一旦泄露（日志、命令行历史、内存转储），同机任意用户即可调用全部管理 API。
- TCP 协议无法表达 Windows 用户身份，无法区分"本机管理员"与"同机普通用户"。
- 相关入口：`src/common/PGSClient.cpp`（连接逻辑）、`src/service/PGS.cpp` 的 `createListenSocket()` 和 `stripAuthEnvelope()`。

**攻击场景**

1. 普通用户进程读取管理员进程的命令行历史或环境变量，获得 token。
2. 直接 `telnet 127.0.0.1 12345` 发送已知 token，执行任意管理命令。

**修复方案**

**短期**（不改协议）：
- 确认 `pgs_guard_state.db`（含 token hash）的 DACL 严格为 `SYSTEM + Administrators`，拒绝其他用户读取。
- 在 token 旋转逻辑中增加频率限制，防止暴力猜解（虽然概率低，但成本不高）。

**中期**（推荐）：增加 Windows Named Pipe 传输层：

```cpp
// 推荐 pipe 路径
\\.\pipe\ProcessGuardService

// DACL 示例（伪代码）
EXPLICIT_ACCESS ea[2];
BuildExplicitAccessWithSid(&ea[0], pAdminSid, GENERIC_ALL, SET_ACCESS, NO_INHERITANCE);
BuildExplicitAccessWithSid(&ea[1], pSystemSid, GENERIC_ALL, SET_ACCESS, NO_INHERITANCE);
SetEntriesInAcl(2, ea, NULL, &pAcl);
```

- `PGSClient` 优先尝试 pipe 连接，回退到 TCP（兼容旧版本）。
- 协议层命令格式不变，只换 I/O 底层。
- pipe 连接后，服务端可通过 `ImpersonateNamedPipeClient()` + `OpenThreadToken()` 验证调用方是否属于 Administrators 组，实现 OS 级身份校验。

**长期**：TCP 管理端口仅保留给 remote Web gateway（TLS + 用户文件 + 审计），本地管理统一走 pipe。

---

### 3.2 代码签名缺失

**现状**

`installer/pgs_installer.iss` 生成 installer，`build_installer.bat` 生成 installer/portable zip/SBOM/SHA256SUMS，但没有代码签名步骤。所有 `.exe`、`.dll`、`.sys` 均未签名。

**风险**

- Windows SmartScreen 对未签名 installer 显示"未知发布者"警告，用户需要手动绕过，阻碍安装。
- 用户无法验证下载物来源，中间人替换 installer 无法被检测。
- `Sirius.sys`（PPL 驱动）未签名，在实际系统中无法加载（Windows 内核强制要求驱动签名）。
- `modules.lock` 中的 SHA-256 只能防止本地篡改，不能证明 DLL 来自可信发布者。
- 相关入口：`tools/build_installer.bat`、`.github/workflows/publish-release.yml`、`installer/pgs_installer.iss`。

**修复方案**

1. **申请代码签名证书**：个人开发者可使用 SignPath.io 或 Certum Open Source Code Signing（收费较低）；企业使用 DigiCert/Sectigo EV 证书（SmartScreen 信誉建立更快）。

2. **在 CI 中集成签名步骤**（publish workflow）：

```yaml
# .github/workflows/publish-release.yml 新增步骤
- name: Sign executables
  run: |
    signtool sign /f cert.pfx /p ${{ secrets.SIGN_PASSWORD }} `
      /tr http://timestamp.digicert.com /td sha256 /fd sha256 `
      build\pgs_service.exe build\pgs_bless.exe `
      build\modules\**\*.dll
```

3. **驱动签名**：`Sirius.sys` 需要 EV 证书 + Microsoft WHQL 提交（或测试签名 + 开启测试模式），在开放 PPL 功能前必须完成。

4. **发布后验证**：在 `tools/release_smoke.ps1` 中增加 `Get-AuthenticodeSignature` 检查，确认签名有效。

---

### 3.3 模块加载链路安全

**现状**

`ModuleManager` 优先读取 `modules.lock`（含 SHA-256），`modules.lock` 存在但损坏时 fail-closed（已修复）。`modules.allow` 作为无 lock 情况下的 legacy 兼容。相关入口：`src/modules/ModuleManager.cpp`、`cmake/WriteBundledModulesLock.cmake`。

**残余风险**

**风险 A：模块目录 ACL 未做递归 fail-closed 验证**

> 2026-08-01 验收修正已落地：真递归枚举、启动只 audit 不自动 repair、显式 `repair-modules-acl` 同时修 owner+DACL；嵌套路径单测与 smoke 显式 repair 已覆盖。剩余安装态/VM 非管理员负例。

**历史风险**

服务启动时若未系统检查 `modules/` 任意深度目录树的 owner 和 DACL，普通用户获得写权限后可替换深层 DLL/manifest；若同时能改 `modules.lock`，hash 钉扎也会被一起伪造。启动路径若先自动 repair 再 audit，会掩盖本应 fail-closed 的不安全安装态。

```
攻击路径：
1. 普通用户写入 modules/sched/nested/evil.dll 或替换 module.manifest.json
2. 重新生成 modules.lock（如果有写权限）
3. 服务加载恶意 DLL，以 SYSTEM 权限执行任意代码
```

**修复方案（已实现）**：

```cpp
// PGUtil: recursive enumerateModulesAclPaths / auditModulesAcl / secureModulesAclTree
// PGS::initialize(): audit only -> 生产失败则跳过 loadFromDirectory（不自动 secure）
// PGSProtocol module load: 非 permissive 时 audit 失败直接 ERR module.acl-insecure
// pgs_bless doctor repair-modules-acl: owner=Administrators + protected DACL，再 re-audit
```

**风险 B：`--allow-all-modules` 持久化后无视 lock**

`MODULES_PERMISSIVE=1` 写入状态文件后，后续启动均跳过 lock 校验。攻击者若能写 state 文件，可一次性关闭整个模块安全边界。

**修复方案**：
- state 文件 DACL 必须为 SYSTEM + Administrators（P0-04 的扩展）。
- permissive 模式写入审计事件（已完成），在 doctor 中标红并说明风险。
- 生产 release smoke 明确断言 `MODULES_PERMISSIVE` 为 0。

---

### 3.4 Bootstrap Token 文件权限

**现状（2026-08-01：P0-04 核心实现已完成）**

服务首次启动时，若无归档 token，会生成随机 token 并写入 `C:\ProgramData\ProcessGuard\state\pgs_initial_token.txt`。State 目录仍用 SYSTEM + Administrators + 当前运行身份 ACL；**token 文件**使用专用边界：尽量 `OWNER=Administrators`，DACL 为 **SY+BA only**（无交互用户 ACE），经 `secureBootstrapTokenAcl` 应用。

写入路径 fail-closed（2026-07-28 起）：写入前无法保护 state 目录 ACL 会拒绝启动；写入后无法保护 token 文件 ACL 会删除 token 并拒绝启动。Doctor 对既有文件做只读 owner/DACL 诊断（`bootstrap_token_acl`）；`repair-state-acl` 会修复既有 token 文件 ACL 并 re-audit。相关入口：`PGUtil.h`、`PGS.cpp` 的 `writeInitialTokenFile()` / `initialize()`、`pgs_bless.cpp` doctor/repair。

**风险**

初始 token 若落入宽权限目录，普通用户可读取管理 token。服务写入、doctor 诊断与 repair 核心路径已收口；剩余主要是提升权限 ProgramData/icacls E2E、异常 ProgramData/备份还原场景的 VM 专项验证。

**修复方案**

1. 已完成：写入文件前先保护 state 目录 DACL，失败则拒绝写入并停止服务。
2. 已完成：写入后经 `secureBootstrapTokenAcl` 保护 token 文件（SY+BA，无交互用户 ACE），失败则删除文件并停止服务。
3. 已完成：`doctor --json` 的 `bootstrap_token_acl` 只读诊断；Users/Everyone 等读或写 → `error`；无法读 SD → `warn`（不假报 `ok`）。
4. 已完成：`repair-state-acl` 修复既有 `pgs_initial_token.txt` ACL（不创建、不改写 token 内容）并 re-audit。
5. 已完成：`test_pgs_core` 单测证据 `163 checks, 0 failures`；`tools/test_bootstrap_token_acl.ps1` 为提升权限延期专项。
6. 延期：提升权限下的 ProgramData 负例 / VM 验收。

```cpp
// 当前 writeInitialTokenFile 语义：
// - secureCreateDirectory(stateDir) 失败 -> return false
// - secureBootstrapTokenAcl(tokenFilePath) 失败 -> DeleteFile + return false
// 调用方 initialize() 会清空临时 auth hash 并停止启动。
// doctor: auditBootstrapTokenAcl；repair-state-acl: secureBootstrapTokenAcl + re-audit
```

---

### 3.5 输入校验与命令注入

**现状**

管理协议是文本行协议，命令参数通过 `|` 分隔（wire format）或 JSON 传递。大部分参数经过基础校验，但存在以下待加强场景。

**风险 A：base64 路径未做路径遍历检查**

`register` 命令的 `encodedPath` 是 base64 编码的文件路径，服务端解码后直接用于 `CreateProcessW`。若客户端恶意传入 `..\..\Windows\system32\cmd.exe` 的编码，且服务端不校验，可能启动非预期进程。

**修复方案**：

```cpp
// PGS::handleRegister 中
std::string decodedPath = base64Decode(encodedPath);
// 规范化路径，检查不包含 ../ 或 ..\
if (!isAbsolutePath(decodedPath) || containsTraversal(decodedPath)) {
    return "ERR invalid path";
}
```

**风险 B：`eventlog --source` 参数注入**

`eventlog recent --source <name>` 中已有对分号、控制字符的过滤，但需要确认是否覆盖了所有注入向量（如零宽字符、Unicode 规范化攻击）。

**修复方案**：用白名单而非黑名单——source 名只允许 `[A-Za-z0-9\-_. ]`，超出字符集直接拒绝。

**风险 C：JSON 解析未全面迁移**

`ModuleManager` 和 `PGSProtocol` 中仍有部分旧的 `jsonStringValue()` 轻量字符串查找路径（P2-15）。社区模块上传恶意构造的 `module.manifest.json`（重复字段、嵌套对象、超大 JSON）可能导致解析歧义，错误放行或拒绝模块。

**修复方案**：
- 全面迁移到 `nlohmann/json`（已 vendor），manifest 和 lockfile 使用 `json::parse()` + `try/catch`。
- 对 manifest 关键字段（`name`、`abi`、`sha256`、`risk`、`capabilities`）增加 schema 校验，拒绝类型错误、缺失或重复字段。

---

### 3.6 Web 层凭据与 CSRF

**现状（已部分修复）**

本地 Web 控制台已切换为 HttpOnly `pgs_local_session` cookie + `X-PGS-CSRF` nonce，页面不再嵌入 `window.PGS_API_TOKEN`。相关入口：`qt/pgs_admin_web/src/WebServer.cpp`。

**残余风险**

**风险 A：真实浏览器环境未验证**

HttpOnly cookie + CSRF 实现是否正确需要在真实浏览器中验证：无 cookie 请求返回 401、跨 Origin POST 失败、CSRF token 不匹配拒绝。目前只有 `vm_acceptance.ps1` 的 PowerShell HTTP 验证，缺少浏览器 DOM smoke。

**修复方案**：引入 Playwright 或 Puppeteer，对以下路径做自动化验证：
- 无 cookie 直接调 `/api/guards` → 401
- 正确 cookie 但缺 `X-PGS-CSRF` header → 403
- 跨 Origin POST → 被 CORS 拦截
- 正常登录 → 控制台可用，页面源码不含任何 token 字符串

**风险 B：Cluster 节点凭据编辑无审计事件**

Cluster Dashboard 的 add/edit/test/remove 操作受 API token 保护，但没有写本地审计日志。恶意管理员可修改节点目标后删除操作记录。

**修复方案**：为 `ClusterServer.cpp` 中的每个 mutation 操作写 Windows Event Log 或 append-only 审计文件，事件包含操作类型、节点 URL（脱敏）、时间戳、调用方 IP。

**风险 C：Remote Web gateway 未在受控环境验证**

Web remote 模式（TLS + users file + audit log）的实现声明了安全要求，但未经过真实多节点联调。特别是 TLS 配置错误（如接受自签名证书）可能导致中间人攻击。

**修复方案**：在内网环境搭建两节点测试，验证：TLS 证书链验证不可绕过、用户文件权限（DACL）为管理员只读、audit log 写入不中断。

---

### 3.7 高风险模块执行边界

**现状**

`dump`、`script_runner`、`service_guard` 是高风险模块，已有初步边界控制。

**风险 A：dump 模块的敏感内存泄露**

`dump collect --pid <pid> --confirm` 可采集任意进程（包括其他服务进程）的 minidump，写入 ArtifactStore。minidump 可能含有业务敏感数据、其他进程的 token、密钥材料。

- ArtifactStore 默认 TTL 为 24 小时，dump artifact 已裁剪到 6 小时，标记 `sensitive=high`。
- 但 Web/Qt 下载前缺乏"高敏感内容"的显著警告。
- 对受保护系统进程（SYSTEM/lsass.exe）的 dump 尝试应记录专项安全事件。

**修复方案**：
1. Web/Qt 下载 sensitive artifact 前显示二次确认对话框（含 sensitivity 级别和文件大小）。
2. 对系统进程（SID 为 SYSTEM 的进程）的 dump 请求，记录 `security.high_risk_dump_attempt` 事件，无论是否成功。
3. 考虑将 dump 能力限定为只能 dump 当前被 PGS 守护的进程（而非任意 PID），最小化攻击面。

**风险 B：script_runner 路径限制基础修复已落地，剩余签名/ACL/RBAC**

`script_runner` 只允许注册 `modules\script_runner\scripts\` 目录下的脚本。早期实现依赖字符串前缀匹配，Windows 路径的短路径名、UNC/device 前缀、junction/symlink 或多余斜杠可能绕过该检查。

```
正常路径: C:\ProgramData\ProcessGuard\state\modules\script_runner\scripts\myscript.ps1
绕过尝试: C:\PROGRA~3\PROCES~1\state\modules\...（8.3 短路径）
         \\?\C:\ProgramData\ProcessGuard\...（扩展路径前缀）
```

**当前修复**：
- 2026-07-28 已改为打开 scripts 目录和脚本文件句柄，通过 `GetFinalPathNameByHandleW()` 比较最终路径，并要求目录边界匹配，避免短路径/扩展前缀/链接目标绕过。
- 注册时记录脚本 SHA-256；执行前再次解析 final path 并重新 hash，内容变化会以 `ERR script hash mismatch` fail-closed。
- `script_runner.config/add/run-denied/run-attempt/run/run-failed` 写入 PGS 事件，run 事件带脚本 id、脚本 hash、args hash 和 caller。

**剩余方案**：
- 增加脚本签名或 publisher policy。
- doctor 深检脚本目录 ACL 和旧无 hash 条目。
- Web/remote RBAC 默认禁止 run，结构化 UI 高风险标红。

**风险 C：service_guard allow policy 基础边界已补，生产 UI/RBAC 仍需收口**

`service_guard` 原先可以 start/stop 任意 Windows SCM 服务（需 `confirm=1`），但没有 allow/deny policy 限制可操作的服务名单。2026-07-28 已补基础生产边界：mutation 仍必须 `confirm=1`；默认拒绝 `WinDefend`、`MpsSvc`、`EventLog`、`Schedule`、`RpcSs` 等受保护服务；`service-guard policy --allow <list> --confirm` 可写入持久化 allowlist，配置 allowlist 后 mutation 只允许列表内服务；受保护服务还需要额外 `--allow-protected` 且显式在 allowlist 内。mutation deny/attempt/success/failure 和 policy 更新都会写 PGS 事件。

**剩余方案**：
- Web/Qt 专用页面要把服务 mutation 标为高风险，并默认不给远程 viewer/operator 暴露 start/stop/ensure。
- 事件目前仍在核心内存环里，后续需要落到 append-only/hash-chain 审计或 Windows Event Log 专项事件，避免服务重启后丢失。
- 允许生产环境按 operator role 或服务标签配置更细粒度 allow/deny，而不只是模块本地 allowlist。

---

### 3.8 审计日志完整性

**现状**

- PGS 核心事件是内存环（`m_events`，最多 512 条），服务重启后丢失。
- Web remote audit 是 append 文本文件，无哈希链，可被本地管理员篡改。
- 相关入口：`PGS::recordEvent()`、`WebServer::audit()`。

**风险**

1. 服务崩溃或被 SCM 重启后，发生在重启前的关键安全事件（模块加载失败、token 变更、隔离事件）不可追溯。
2. 审计文件被篡改后无法检测，无法满足合规要求（如等保 2.0 对审计日志完整性的要求）。

**修复方案**

**短期**：
- 将关键安全事件（token 变更、模块 load/unload、permissive 模式开关、guard quarantine、dump collect、script run）同步写入 Windows Application Event Log（source: `ProcessGuardService`）。Windows Event Log 本身有 ACL 保护，普通用户不可删除/篡改。

**中期**：
- 将 PGS 内存事件环改为持久化追加写（文件 + 定期 flush），服务重启后事件不丢失。
- 为 Web remote audit 文件增加简单哈希链：每条记录末尾追加前 N 条记录的 SHA-256，篡改后验证失败。

**长期**：
- 考虑将审计事件写入独立 SQLite 数据库（与状态文件分离），支持按时间范围查询和导出。
- 关键事件实现 append-only 语义（文件权限 + 代码层拒绝 seek 覆写）。

---

### 3.9 路径处理与目录遍历

**现状**

多处代码接收外部传入的路径，通过 base64 或 JSON 传递，服务端解码后直接使用。

**典型风险点**

| 入口 | 参数 | 当前校验 | 风险 |
|------|------|---------|------|
| `handleRegister()` | `encodedPath`（base64） | 无显式遍历检查 | `..` 路径注册非预期进程 |
| `module load` | DLL 路径 | 检查是否在 modules 目录内 | 短路径绕过 |
| `script_runner add/run` | 脚本路径 | 文件句柄 final-path 检查 + 目录边界匹配 + SHA-256 pin/run 前重验 | 仍需签名 policy、脚本目录 ACL doctor 和远程 RBAC |
| `file_watch add` | 监视文件路径 | 本机绝对盘符路径、64 条规则上限、默认拒绝 UNC/device/ADS/Windows 系统目录/System Volume Information/Recycle Bin | 仍可能监视业务敏感文件，需要后续可配置 allow/deny |
| `update verify` | release manifest 路径 | 读取 manifest 并验证 hash | manifest 注入恶意 `release_root` |

**统一修复方案**

1. 所有接收外部路径的入口，统一先调用 `GetFullPathNameW()` 规范化，再做策略检查。
2. 建立路径校验工具函数 `PGUtil::isPathUnder(base, candidate)` 使用 Windows API（而非字符串比较）实现，在所有模块加载和脚本注册路径复用。
3. `file_watch` 已增加基础 deny 策略，默认拒绝监视系统敏感路径（`%WINDIR%\*`、System Volume Information、Recycle Bin）、UNC/device/ADS 路径，并限制最多 64 条规则；后续再做 operator 可配置 allow/deny。

---

### 3.10 依赖安全

**现状**

- `nlohmann/json.hpp`（vendor 单头文件）：已知版本无重大安全漏洞，但没有记录具体版本号。
- Qt6：通过 MSYS2 pacman 安装，版本在 CI 缓存 key `v5` 处隐式锁定，没有显式版本记录。
- MinGW/GCC：同 Qt6。
- `Sirius.sys`（预编译 PPL 驱动）：无来源说明文件，无 hash 校验，无签名。

**风险**

1. `nlohmann/json.hpp` 版本不明确，若上游修复安全漏洞，无法评估是否需要更新。
2. `Sirius.sys` 是预编译二进制，无法验证来源和完整性，是高价值攻击目标（驱动以内核权限运行）。
3. Qt 和 MinGW 的隐式版本锁定可能导致不同开发者使用不同版本，引入隐蔽的行为差异。

**修复方案**

1. 在 `third_party/` 目录下为每个 vendor 依赖增加版本说明文件：

```
third_party/
├── nlohmann_json/
│   ├── json.hpp
│   └── VERSION        # "3.11.3 - https://github.com/nlohmann/json/releases/..."
└── sqlite3/           # 未来新增
    ├── sqlite3.h
    ├── sqlite3.c
    └── VERSION
```

2. 创建 `tools/TOOLCHAIN_VERSIONS.txt`，明确记录 Qt 和 MinGW 版本，CI 缓存 key 从此文件的 SHA-256 推导。

3. `Sirius.sys` 必须记录来源（源码仓库 URL、commit hash 或预编译包 URL）、文件 SHA-256，并在 `modules.lock` 中锁定。在代码签名就绪前，驱动不应在生产环境加载。

---

## 四、安全改进实施路线图

### 第一轮（阻塞公开发行）

| 编号 | 任务 | 对应章节 |
|------|------|---------|
| S-01 | 申请代码签名证书，签名 exe/dll | 3.2 |
| S-02 | 驱动签名（PPL 模块） | 3.2 |
| S-03 | bootstrap token ACL 核心已完成；延期 elevated/VM 专项验证 | 3.4 |
| S-04 | 模块目录 ACL 递归验证 + fail-closed | 3.3 |

### 第二轮（安全版本专项）

| 编号 | 任务 | 对应章节 |
|------|------|---------|
| S-05 | Named Pipe 传输层（本地管理推荐通道） | 3.1 |
| S-06 | 关键安全事件写 Windows Event Log | 3.8 |
| S-07 | 路径遍历统一规范化（`PGUtil::isPathUnder`） | 3.9 |
| S-08 | JSON 解析全面迁移到 nlohmann/json | 3.5 |
| S-09 | Web/Qt 敏感 artifact 下载前二次确认 | 3.7 |
| S-10 | Web Playwright smoke（cookie/CSRF/token 泄露） | 3.6 |

### 第三轮（加固与合规）

| 编号 | 任务 | 对应章节 |
|------|------|---------|
| S-11 | 审计日志持久化 + 哈希链 | 3.8 |
| S-12 | service_guard allow policy 基础版已落地，剩余 UI/RBAC/持久化审计 | 3.7 |
| S-13 | script_runner final-path/hash-on-run 基础版已落地，剩余签名/ACL/RBAC | 3.7 |
| S-14 | 依赖版本显式记录（`third_party/*/VERSION`） | 3.10 |
| S-15 | capability policy 端到端运行时鉴权 | 整体 |

---

## 五、总结

PGS 的安全意识整体处于较高水平：高风险操作有 `--confirm` 门槛，Web 层 token 嵌入问题已修复，ArtifactStore 有 TTL 和敏感分类，模块 lock 损坏时 fail-closed。当前最紧迫的安全缺口是**代码签名缺失**（阻塞公开发行）和**本地 TCP 管理协议的用户身份边界**（Named Pipe 是更彻底的解法）。其余问题已有明确的修复路径，可以按轮次分批完成，不需要架构级重构。
