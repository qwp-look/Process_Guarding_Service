# PGS 安全收口交接文档

本文档专门交接后续安全专项。当前主线优先完成“功能可用版”，只修功能正确性必需的权限/校验问题；下面条目仍需作为独立安全收口任务继续做。每条都包含影响组件、当前行为、风险、建议修复、入口、验证方式、优先级和是否阻塞功能版 release。

优先级定义：P0 = 应尽快修，可能造成本机提权或远程未授权操作；P1 = release 后安全专项第一批；P2 = 加固/审计完善。

2026-07-18 审查补充：`tools\verify.bat`、顶层 CMake 构建和 CTest 均通过；下面新增/修正的是安全边界、发布链路和文档状态漂移问题，不代表当前功能不可用。

2026-07-19 功能收口补充：WindowsApps AUMID 推导和 `bless-start --winapp` 已实现但仍需真实 Store/UWP E2E；OperationStore/ArtifactStore 已实现，CLI artifact 下载会核对 size/SHA-256，服务端 artifact chunk 会重新计算 size/SHA-256 后再返回；`metrics`、`backup`、`eventlog`、`notify` 已 bundled；Web/Qt 已补主要功能入口。下面安全项只更新剩余风险，不把功能未验证等同于代码未实现。

2026-07-19 模块扩展补充：`dump`、`service_guard`、`file_watch`、`policy`、`remote_agent`、`update`、`script_runner` 已完成 bundled 首版并通过 build/smoke/release/installer 验证。安全文档按“首版可用但生产需加固”处理：dump 和 script_runner 为高风险，service_guard/file_watch/policy/remote_agent/update 为中风险；通知模块仍只使用 Windows 本机 Event Log/可选弹窗，不接聊天软件、webhook、邮件或远程 messenger。

2026-07-19 Web/模块锁安全收口补充：本地 Web 控制台已改为 HttpOnly `pgs_local_session` cookie + `X-PGS-CSRF`，页面不再嵌入可读 bearer token；`modules.lock` 现在在存在但损坏时会 fail-closed，不再退回 name-only allowlist。

2026-07-28 Artifact/file_watch 安全补充：ArtifactStore policy 已支持受限可配置 `max_artifact_bytes` / `max_total_bytes`，默认仍为 16MB/256MB，允许范围分别为 64KB..64MB 和 1MB..1GB，且总量必须不小于单 artifact 上限；CLI/Web/Qt policy 入口和 smoke 已同步覆盖。`file_watch` 现已限制最多 64 条规则，只接受本机绝对盘符路径，并默认拒绝 UNC/device/ADS/Windows 系统目录/System Volume Information/Recycle Bin 路径；doctor 暴露 `file_watch` 状态和路径策略，smoke 覆盖敏感路径拒绝。Guard 状态已到 v5，`last_failure_code` 已进入 `list/get --json`；Qt 守护表格已补隔离/失败码/健康字段和 retry/clear-quarantine 操作。剩余是失败码分类、failure history、处理建议和专项负例。

2026-07-20 Qt 可见性补充：Qt 已新增 Doctor / Repair 页，直接渲染 CLI doctor JSON，并暴露 state ACL、modules ACL、modules.lock 修复按钮；Qt 守护表格已显示隔离、失败码、健康状态并可对选中 guard 执行 retry / clear-quarantine。安全剩余项调整为 failure taxonomy、failure history、专项负例和 repair schema 完整性，而不是 Qt 完全缺入口。

2026-07-20 Qt Health / Cluster/Web 交互补充：Qt 守护表格页已补 Health policy 表单，可配置 process/tcp/http 探针并执行 health-check set/get/clear；Web 已补 Structured Result 区域，结构化渲染 module/scheduler/report/artifact 等响应且首页 smoke 确认不含 `window.PGS_API_TOKEN`；Cluster Dashboard 已补节点 edit/test、凭据替换/清空和 guard 隔离/健康/失败码详情。TCP closed、TCP DNS failure、HTTP unexpected status 和 HTTP timeout 已进入 smoke 负例；Cluster add/list/edit/test/clear/remove 已进入本地 HTTP API smoke 和 VM acceptance 扩展，且覆盖凭据不回显/不明文落盘断言。安全剩余项调整为真实 remote gateway 验收、Cluster mutation 审计策略、浏览器 DOM/UI 自动化覆盖以及 health failure action 审计/处理建议。

## P0-01 Web 本地页面嵌入 API token

> 2026-07-19 更新：实现已完成。本地 Web 控制台已切换为 HttpOnly `pgs_local_session` cookie + 页面可读 CSRF nonce，页面不再嵌入 `window.PGS_API_TOKEN`；`tools/vm_acceptance.ps1` 已改为验证无 token 泄露、HttpOnly cookie 和无 cookie 401。下面旧条目的风险描述作为历史背景保留，剩余工作是 VM/真实浏览器验收。
- 影响组件：`pgs_admin_web`
- 当前行为：loopback 模式下首页将每进程 Web API token 嵌入 `window.PGS_API_TOKEN`，浏览器 JS 用它调用 `/api/*`。该值不是 PGS 后端管理 token，但 Web 后端持有 PGS token 并代为执行管理命令，所以它仍等价于本地 Web 控制台能力凭据。
- 风险/攻击面：本机同用户浏览器扩展、调试工具、恶意本地页面利用浏览器状态或读取页面内容后，可复用该 token 调本地 Web 管理 API。当前已有 Host/Origin/CSRF 检查，但 bearer 能力仍在页面 JS 内。
- 建议修复：改为 HttpOnly SameSite cookie + per-request CSRF；或把 loopback 也切到一次性 session cookie，不再把 bearer token 暴露给 JS。保留 remote 模式 Basic/RBAC/TLS，不混用 PGS 管理 token。
- 涉及入口：`qt/pgs_admin_web/src/WebServer.cpp` 的 `handleIndexHtml()`、`isRequestAuthorized()`、前端 `api()`。
- 验证方式：浏览器页面源码不包含 token；无 cookie/无 CSRF 请求失败；跨 Origin POST 失败；loopback 正常 UI 仍可操作。
- 是否阻塞功能版 release：否。阻塞安全版 release。

## P0-02 模块 allowlist 仍可退回名称放行

> 2026-07-19 更新：核心实现已收口。`ModuleManager` 现在检测到 `modules.lock` 存在但为空、损坏、缺少 `modules` 字段或包含无效/缺失 SHA-256 条目时，会保持空 allowlist 并 fail-closed，不再回退到 name-only `modules.allow`；`modules.allow` 只保留给没有 lock 的 legacy/dev 树。剩余工作是发布/VM 负例验证和后续签名强制。
- 影响组件：`ModuleManager`、`modules.allow`、`modules.lock`
- 当前行为：构建脚本和 CMake 会生成带 SHA-256 的 `modules.lock`，`ModuleManager` 优先读取它；但仓库仍保留 name-only `modules.allow` 兼容回退，且生产模式没有强制“缺失/损坏 modules.lock 即拒绝加载 bundled 模块”。
- 风险/攻击面：如果 release 目录丢失或损坏 `modules.lock`，loader 会退回 `modules.allow` 的名称放行；若攻击者还能写入 modules 目录并替换同名 DLL，名称 allowlist 不足以阻止加载。当前模块目录 ACL 已有加固，但安全版不应依赖单一 ACL 边界。
- 建议修复：生产/安全模式强制使用 `modules.lock` 的 hash；缺失、解析失败、少于 bundled 模块数、hash 非 64 hex 时 fail-closed；签名可用后增加 `require_signed=true`；为 `pgs_bless module trust` 增加批量生成/校验 release allowlist 的命令。
- 涉及入口：`tools/build_pgs.*`、`cmake/WriteBundledModulesLock.cmake`、`tools/package_release.bat`、`src/modules/ModuleManager.cpp`、`docs/MODULE_SYSTEM.md`。
- 验证方式：删除/篡改 `modules.lock` 后生产模式模块加载失败；篡改 bundled DLL 后 `module load` 失败并记录 hash mismatch；未篡改 release 模块可加载；`module verify` / `module info --json` 显示 lock/hash satisfied。
- 是否阻塞功能版 release：否。阻塞生产安全版 release。

## P0-03 模块目录 ACL 需要 fail-closed 递归验证

> 2026-08-01 验收修正已落地；补充 fail-closed 枚举：
> 1) `enumerateModulesAclPaths` 真递归，返回 `ModulesAclEnumerateResult{paths,ok,reason,errorPath}`；**禁止** `skip_permission_denied`，构造/类型查询/increment 任一步 `ec` 都记失败（`modules-tree-enumeration-failed` / `modules-entry-unreadable`）；
> 2) `auditModulesAcl` / `secureModulesAclTree` 在枚举失败时必须 `ok=false` / 返回 false，不得静默跳过不可读子树后报 ok；
> 3) `PGS::initialize()` **只 audit、不自动修复**；生产失败拒绝加载并记 `module.acl-insecure`；permissive 可降级 warning；
> 4) 仅 `doctor repair-modules-acl` 修 owner+DACL 再 re-audit；`test_modules_acl.ps1` 用 `icacls /grant *S-1-5-32-545:(W)` 制造 Users 写权限负例。
- 影响组件：PGS 服务启动、模块加载、PPL opt-in、doctor/repair
- 当前行为：启动 audit-only fail-closed；显式 repair 修 owner+DACL；doctor 暴露 `modules_acl_recursive`。
- 风险/攻击面（历史）：模块目录或深层子路径可被非管理员写入时，模块加载边界失效。
- 建议修复：核心语义已收口。剩余是安装态/VM 非管理员负例与 release 安装包默认 ACL 断言。
- 涉及入口：`include/Process_Guard/PGUtil.h`、`src/service/PGS.cpp`、`src/service/PGSProtocol.cpp`、`tools/pgs_bless.cpp`。
- 验证方式：嵌套 `evil.dll` Users 写权限 → audit/doctor 失败且 `module load` 拒绝；`repair-modules-acl` 后 ok；启动路径不得静默自愈 ACL。
- 是否阻塞功能版 release：否。阻塞安全版 release 的剩余项转为安装态/VM 验证。

## P0-04 bootstrap token 文件 ACL fail-closed（核心已完成）

> 2026-08-01 更新：**P0-04 核心实现已完成**。
> 1) 服务首次写入：`writeInitialTokenFile` 经 `secureBootstrapTokenAcl` 保护 token 文件；ACL 失败则删除 token 并拒绝启动（state 目录仍用 `secureCreateDirectory`）。
> 2) Token 专用边界：`OWNER` 尽量为 Administrators，DACL 为 **SY+BA only**（`secureBootstrapTokenDaclSddl`），**不**注入交互/doctor 用户 ACE（避免 repair 加宽 LocalSystem 写出的 secret）。
> 3) Doctor：`doctor --json` 增加 `bootstrap_token_acl` 只读 owner/DACL 诊断；缺失 → `info`（`missing/not-generated`）；Users/Everyone 等读或写 → `error`（如 `non-admin-token-access-ace`）；无法读 SD → `warn`（`acl-read-access-denied`），不假报 `ok`。
> 4) Repair：`doctor repair-state-acl` 在修 state 目录后对既有 `pgs_initial_token.txt` 调用 `secureBootstrapTokenAcl` 再 re-audit；不创建、不改写 token 内容。
> 5) 单测：`test_pgs_core` 覆盖 missing / Users 读/写 / SY+BA-only / 坏 owner fail-closed / 幂等 repair（`163 checks, 0 failures`）；`tools/test_bootstrap_token_acl.ps1` 为提升权限 ProgramData 负例脚本。
> 剩余延期：提升权限下的 ProgramData/icacls 专项 E2E、异常 ProgramData 权限与备份还原场景的 VM 验证。
- 影响组件：服务首次启动 token 生成、doctor/repair
- 当前行为：写入路径 fail-closed + token 专用 SY+BA ACL；doctor 诊断既有文件；`repair-state-acl` 修复既有 token 文件 ACL 并 re-audit。
- 风险/攻击面（历史）：初始 token 若落入宽权限目录，普通本机用户可读取管理 token。核心路径已收口；剩余是提升权限/安装态专项验证。
- 建议修复：核心语义已收口。保留 `pgs_bless doctor repair-state-acl` 作为管理员修复入口；延期项为 elevated `test_bootstrap_token_acl.ps1` / VM 验收。
- 涉及入口：`include/Process_Guard/PGUtil.h`（`auditBootstrapTokenAcl` / `secureBootstrapTokenAcl`）、`src/service/PGS.cpp`（`writeInitialTokenFile` / `initialize`）、`tools/pgs_bless.cpp`（doctor / `repair-state-acl`）、`tools/test_bootstrap_token_acl.ps1`。
- 验证方式：单测 163/0；非管理员 doctor 对不可读 SD 报 `warn` 而非 `ok`；提升权限下 Users:(R) → doctor `error`，repair 后 `ok`；服务 ACL 失败仍删 token 并拒启动。
- 是否阻塞功能版 release：否。阻塞安全版 release 的剩余项转为提升权限/VM 专项验证。

## P1-05 `--allow-all-modules` 生命周期和撤销

- 影响组件：服务宿主、状态归档、模块加载
- 当前行为：`--allow-all-modules` 可写入 SCM binPath，并持久化 `MODULES_PERMISSIVE\t1`，用于开发逃生；2026-07-26 已新增 `pgs_bless module permissive status|on|off`，`on` 需要 `--confirm`，`off` 会更新运行态 ModuleManager、写回状态归档并记录审计事件。`pgs_service` 也接受 `--no-allow-all-modules` 作为显式安装/运行参数。
- 风险/攻击面：一次调试开启后可能长期保留，等价于关闭模块边界。
- 建议修复：已完成 CLI/服务端运行时开关和审计。剩余是 Qt/Web 对 permissive 状态标红、生产 release smoke 默认关闭检查，以及已安装 SCM binPath 的自动重写/修复入口。
- 涉及入口：`src/service/pgs_service.cpp`、`src/service/PGS.cpp`、`docs/MODULE_SYSTEM.md`。
- 验证方式：2026-07-26 MSYS smoke 覆盖 `module permissive status`、无确认开启失败、确认开启成功、关闭成功；后续仍需真实 SCM binPath 修复验证。
- 是否阻塞功能版 release：否。

## P1-06 命名管道或 OS 级本地认证替代裸 TCP token

- 影响组件：PGS 管理协议、CLI/Qt/Web
- 当前行为：本地管理协议是 loopback TCP + token 信封。
- 风险/攻击面：token 泄露后同机任意用户可调用管理 API；TCP 无法直接表达 Windows 用户身份/管理员组。
- 建议修复：迁移或新增 Windows named pipe transport；使用 pipe security descriptor 限制 Administrators/SYSTEM；协议层可继续复用当前命令语义。
- 涉及入口：`src/common/PGSClient.cpp`、`src/service/PGS.cpp` socket listener、Qt/Web CLI 调用路径。
- 验证方式：非管理员用户无法连接 pipe；管理员可连接；旧 TCP 在兼容期可关闭或仅 loopback+token。
- 是否阻塞功能版 release：否。

## P1-07 restart 失败导致持久 guard 退休的策略需审计

- 影响组件：重启策略、持久归档
- 当前行为：2026-07-20 已完成第二阶段可见性修复。自动重启失败、延迟重启失败、restore 重启失败、重启次数用尽都会保留持久 guard 并进入 `quarantined` 状态；状态版本已到 v5；`list/get --json` 输出 `guard_id`、`status`、`quarantined`、`last_failure`、`last_failure_code`、`next_retry_ms`、`failure_count`；CLI 增加 `guard retry --id <guard-id>` 和 `guard clear-quarantine --id <guard-id>`。intentional exit 仍按主动退保护处理，不进入隔离。
- 剩余风险/攻击面：已有 `restart.hash_mismatch`、`restart.create_process`、`restart.session_token`、`winapp.activate_failed` 等初步稳定 reason code，Web/Qt/CLI 也都有隔离态操作入口；但 taxonomy 仍不完整，failure history 还没有持久化时间线，Web/Qt 还缺按 failure code 分组的处理建议。
- 建议修复：继续补全 failure code taxonomy / failure history；UI 增加“需要人工处理”视图；对可恢复与不可恢复失败给出不同 retry-after 策略；专项负例固定 hash mismatch / file missing / access denied / Session token / WinApp activation 失败。
- 涉及入口：`src/service/PGS.cpp` 的 restore/restart failure 分支、`src/service/PGSProtocol.cpp` 的 guard summary/guard retry、`tools/pgs_bless.cpp`。
- 验证方式：已用显式 MSYS2/MinGW 环境变量运行 `tools\build_pgs.bat`、`tools\test_core_units.bat` 和 `tools\smoke_test_pgs.sh`，smoke 覆盖重启窗口耗尽后 quarantine 可见与 clear-quarantine。后续还需 hash mismatch / access denied / Session 失败专项负例。
- 2026-07-28 追加验证：`tools\smoke_test_pgs.sh` 已覆盖 TCP closed、TCP DNS resolve failed、HTTP 500 unexpected status、HTTP timeout 的 health negative smoke，并新增 health action `restart` / `quarantine` E2E；后续仍需 failure action 审计和按 failure code 分组的 UI 处理建议。
- 是否阻塞功能版 release：否。隔离保留和初步 failure code 已缓解主风险，剩余是安全可观测性增强。

## P1-08 Job Object 权限/竞态的完整安全审计

- 影响组件：Job Object / IOCP / restart family cleanup
- 当前行为：功能版已改为优先打开 `PROCESS_SET_QUOTA | PROCESS_TERMINATE` 并在 survivor job 上重新绑定 IOCP；IOCP 仍作为 wake hint，最终以 handle poll 判定。
- 风险/攻击面：目标已在不兼容 Job 中、权限不足、或 pre-resume assignment 失败时，级联保护退化为单进程监控。
- 建议修复：`bless-start` 支持服务端 pre-resume register 或明确返回“未进入 Job”；状态中增加 `JOB_ASSIGNED` 字段；无法 assignment 时 UI 标红。
- 涉及入口：`src/service/PGS.cpp` 的 `assignGuardToJob()`、`attachGuardJob()`、`tools/pgs_bless.cpp` bless-start。
- 验证方式：创建 child process worker，父进程退出/崩溃时确认 family cleanup；权限不足时状态可见。
- 是否阻塞功能版 release：否。功能版已做最小修复。

## P1-09 WindowsApps AUMID 校验和 manifest 自动推导

- 影响组件：WinApp guard、CLI/Qt/Web
- 当前行为：CLI 已实现 WindowsApps 路径解析 `AppxManifest.xml` 自动推导 AUMID，显式 AUMID 与 manifest 不一致会拒绝；`bless-start --winapp --aumid` 已通过 Windows AUMID activation 启动并注册返回 PID；Web 入口也允许 WinApp AUMID-only bless-start。
- 风险/攻击面：真实 Store/UWP 环境差异尚未完整验证；publisher hash、manifest 不可读、错误 AUMID、ShellExecute fallback、激活后路径查询失败等场景需要更多负例；服务端仍主要信任 CLI 做 path/AUMID 关联校验。
- 建议修复：把 `tools/verify_winapp.ps1` 纳入 VM acceptance/release notes；补错误 AUMID/manifest/path 负例；评估服务端是否需要对 WinApp path/AUMID 再做一次 package 归属校验。
- 涉及入口：`include/Process_Guard/PGUtil.h` PFN helpers、`tools/pgs_bless.cpp`、`src/service/PGS.cpp` `restartAppGuard()`。
- 验证方式：manifest fixture 单元测试已存在；仍需 `tools/verify_winapp.ps1` 真实环境、错误 AUMID/manifest/path 负例和 Web bless-start WinApp 手工验证。
- 是否阻塞功能版 release：否。阻塞安全版/生产版 WindowsApps 声明。

## P1-10 发布签名、哈希和供应链完整性

- 影响组件：installer、portable zip、modules、driver、GitHub Actions release workflow
- 当前行为：release smoke 检查产物存在和可运行；根层 `VERSION` 已作为本地 build_installer 和 publish workflow 的版本源；`build_installer.bat` 已实际通过，生成 installer、portable zip、`SHA256SUMS.txt`、`release-manifest.json`、`sbom.spdx.json`。本轮生成的 manifest 记录 167 个 release tree 文件和 16 个 bundled module lock entries。publish workflow 会上传这些元数据并请求 GitHub artifact attestation。尚未签名 installer/exe/dll/sys，且 attestation/资产上传仍需 live GitHub Release 验证。
- 风险/攻击面：用户无法验证下载物来源；驱动和模块替换难以及时发现；README/用户文档示例版本若不随 `VERSION` 更新，仍可能制造追溯混乱。
- 建议修复：接入代码签名；跑一次 live publish workflow 验证 metadata/provenance；installer 校验 bundled 文件；模块 allowlist 与 release 哈希同源生成并 fail-closed；发布前检查文档下载文件名与 `VERSION` 一致。
- 涉及入口：`tools/build_installer.bat`、`tools/package_release.bat`、`installer/pgs_installer.iss`、`.github/workflows/publish-release.yml`。
- 验证方式：workflow 生成的文件名与 `PGS_VERSION` 一致；签名验证通过；篡改 zip/installer 后校验失败；release 页面包含 installer、portable zip、checksums、manifest、SBOM，并可在 GitHub UI/CLI 中看到 artifact attestation。
- 是否阻塞功能版 release：否。阻塞公开生产发行。

## P2-11 审计日志完整性和留存

- 影响组件：PGS in-memory events、Web remote audit
- 当前行为：PGS events 是内存环；Web remote audit 是 append 文本文件。
- 风险/攻击面：服务重启丢失核心事件；本地管理员或同账号可改 audit 文件；无法证明事件未被删改。
- 建议修复：落盘事件日志；加 hash chain；rotate/retention；关键安全事件写 Windows Event Log。
- 涉及入口：`PGS::recordEvent()`、`WebServer::audit()`。
- 验证方式：重启后事件仍可查询；篡改 audit chain 可检测；日志轮转不丢最近事件。
- 是否阻塞功能版 release：否。

## P2-12 capability policy 尚未端到端强制

- 影响组件：模块 manifest/capabilities、ModuleManager、Web RBAC
- 当前行为：manifest capabilities 已用于模块回调 PGS 核心命令时的能力检查；但外部管理员直接 `module call` / `module invoke`、Web RBAC 与模块 method/capability 之间还没有完整统一的最小权限策略。
- 风险/攻击面：受信任模块一旦加载，管理员入口可以调用其公开方法；远程 Web 若授权过粗，会把模块能力整体暴露给有登录权限的用户。
- 建议修复：定义统一 capability allow policy；模块 load 时校验 manifest capability；`module call`/`module invoke` 前按调用来源、角色、method risk 和 capability 检查。
- 涉及入口：`include/Process_Guard/PGModule.h`、`src/modules/ModuleManager.cpp`、Web RBAC。
- 验证方式：未授权 capability 的模块加载或调用失败；授权后成功；remote viewer/operator/admin 角色对模块 method 的权限不同且可测试。
- 是否阻塞功能版 release：否。

## P2-12a Cluster 节点凭据编辑与审计

- 影响组件：`pgs_cluster_web`、节点注册文件、remote Web gateway 凭据。
- 当前行为：2026-07-20 已新增节点 edit/test；详情页可替换或清空凭据，列表/summary/API 不回显保存的凭据，落盘仍复用现有 DPAPI 保护路径。测试连接可使用已保存凭据或临时输入凭据调用 `/api/cluster/health`。`tools/cluster_api_smoke.ps1` 和 VM acceptance 已覆盖无 token 401、add/list/edit/test/clear/remove、凭据不回显和注册文件不明文保存。
- 风险/攻击面：Cluster 本身是集中化节点视图，管理员误配置或恶意本地管理员仍可修改节点目标；edit/test 这类 mutation 目前只受 Cluster API token/本地页面限制，HTTP API 自动化已补，但仍缺单独审计事件、真实 remote gateway 双节点验收和浏览器 DOM/UI 自动化验证。
- 建议修复：为 add/edit/test/remove 写本地审计日志或 Windows Event Log；补 remote gateway 双节点联调；浏览器/DOM smoke 覆盖凭据不回显、保留原凭据、清空凭据、错误 URL、TLS 失败、401 等路径。
- 涉及入口：`qt/pgs_cluster_web/src/ClusterServer.cpp`。
- 验证方式：`cmake --build build\pgs_cluster_web --config Release` 已通过；本地 `tools/cluster_api_smoke.ps1` 已通过；后续用真实 remote Web node 跑 add/edit/test/remove，并补浏览器 DOM/UI smoke。
- 是否阻塞功能版 release：否。阻塞 Cluster 生产化安全声明。

## P2-13 模块运行态状态迁移后的安装态验证

- 影响组件：`profile` / `sched` 模块、release smoke、安装目录 ACL
- 当前行为：`profile` / `sched` 已在 `PG_Init` 中读取 ABI v3 `get_data_dir()`，默认写入服务 state 根下 `modules\profile\pgs_profiles.db` 和 `modules\sched\pgs_sched.db`；旧模块目录 DB 会 copy-only 迁移。release smoke / installer 继续阻断 DB 泄漏进发布包。
- 风险/攻击面：旧 DB copy-only 不会自动删除，管理员仍需确认是否清理；低权限/只读安装目录真实安装态尚未验证；如果服务数据目录 ACL 异常，模块运行态仍可能落入不理想权限边界。
- 建议修复：release smoke 增加只读安装目录场景；doctor 增加模块数据目录 ACL/迁移状态检查；文档说明旧 DB 由管理员确认后清理。
- 涉及入口：`include/Process_Guard/PGModule.h`、`modules/profile/pgs_profile_module.cpp`、`modules/sched/pgs_sched_module.cpp`、`tools/release_smoke.ps1`。
- 验证方式：安装目录对普通用户只读时 profile/sched 仍可 set/list；release tree 和 zip/installer 不包含 `pgs_profiles.db` / `pgs_sched.db`；ProgramData 状态目录 ACL 为 SYSTEM + Administrators。
- 是否阻塞功能版 release：否。阻塞安全版 release 的模块目录只读策略。

## P2-14 ArtifactStore 留存策略与审计

- 影响组件：`PGSProtocol` ArtifactStore、report 模块、CLI/Web/Qt artifact 下载。
- 当前行为：ArtifactStore 默认限制单 artifact 16MB、总量 256MB，并可通过 `module artifact policy --max-artifact-bytes N --max-total-bytes N` 在受限范围内调整；metadata 记录 size/SHA-256、`sensitive`、`sensitivity`；CLI `module artifact get --out` 下载后会核对 size、chunk total 和 SHA-256；服务端 `module artifact chunk` 返回前会重新计算落盘 size/SHA-256，不匹配则拒绝并记录 `artifact.integrity-failed`；chunk 下载还会记录 start/complete/expired/invalid 审计事件；`module artifact cleanup [--expired|--all] [--verify]`、`module artifact status [--verify]`、`module artifact policy` 已有 operator-facing 命令；Web/Qt 有基础 status/policy 控件；doctor JSON 已包含 `artifact_store` 检查和敏感计数。策略持久化到 state 目录下 `artifact_policy.cfg`，包含 `ttl_ms`、`auto_cleanup`、`verify_on_status`、`max_artifact_bytes`、`max_total_bytes`。metadata id 与请求 id 或 metadata 文件名 stem 不一致会按 corrupt/fail-closed 处理。health loop 会按 5 分钟节流执行过期清理。
- 风险/攻击面：本地管理员或磁盘损坏篡改 artifact 内容时，服务端和 CLI 均可发现，status/doctor 也能暴露基础健康状态；剩余风险是远程下载场景缺更严格访问审计，Web/Qt 下载前敏感提示还不够完整。
- 建议修复：已完成周期性 cleanup、下载审计、敏感分类、dump/report TTL 裁剪、doctor 敏感计数和受限配额策略。剩余是 Web/Qt 下载前显示 size/sha256 和敏感类型提示，以及远程访问审计策略。
- 涉及入口：`src/service/PGSProtocol.cpp`、`tools/pgs_bless.cpp`、`qt/pgs_admin_web/src/WebServer.cpp`、`qt/pgs_admin_qt/src/ModulePage.cpp`。
- 验证方式：2026-07-28 MSYS smoke 覆盖 policy/status JSON 中的 `max_artifact_bytes` / `max_total_bytes`；2026-07-26 MSYS smoke 覆盖 artifact metadata `sensitive/sensitivity`、status `sensitive` 计数、下载后 `artifact.download-complete` 事件；既有 smoke 覆盖下载 SHA-256、policy/status、cleanup。后续补远程下载审计专项。
- 是否阻塞功能版 release：否。建议在公开远程 artifact 下载前完成。

## P2-15 JSON/manifest/lockfile 解析需要结构化收口

- 影响组件：`ModuleManager`、`PGSProtocol`、模块 manifest、`modules.lock`、JSON-RPC envelope。
- 当前行为：多处 JSON 字段读取使用轻量字符串查找，例如 `jsonStringValue()` / `jsonArrayCsv()`；当前 bundled manifest 简单且测试通过，但并非完整 JSON parser。
- 风险/攻击面：社区模块和 manager 扩展增多后，转义、嵌套对象、字段顺序、重复字段或恶意构造 JSON 可能导致解析歧义；安全策略依赖的 `risk`、`capabilities`、`sha256`、`require_signed` 不应建立在脆弱解析上。
- 建议修复：引入小型 JSON 库或集中实现受限 JSON parser；对 manifest/lockfile 使用 schema 校验；拒绝重复关键字段和未知高风险格式；把当前“受限 JSON 子集”写入开发文档直到 parser 替换完成。
- 涉及入口：`src/modules/ModuleManager.cpp`、`src/service/PGSProtocol.cpp`、`docs/schemas/*.json`、`tests/test_module_manager.cpp`。
- 验证方式：增加转义字符串、嵌套字段、重复字段、缺失 hash、非法 bool、超大 JSON 的正负例；确保安全字段解析确定且 fail-closed。
- 是否阻塞功能版 release：否。建议在开放社区模块前完成。

## P1-16 Dump 模块的敏感内存与留存风险

- 影响组件：`modules/dump`、ArtifactStore、CLI/Web/Qt artifact 下载。
- 当前行为：`dump collect --pid <pid> --confirm` 可对本机进程采集 minidump，写入 ArtifactStore，单 artifact 限制 16MB，不向协议暴露临时文件路径。dump artifact 标记为 `sensitive=true` / `sensitivity=high`，TTL 裁剪到 6 小时。默认状态命令只报告能力，不采集。
- 风险/攻击面：minidump 可能包含目标进程内存、路径、命令行、环境片段或业务敏感数据；若 ArtifactStore 留存、下载审计或 ACL 有缺口，可能形成敏感数据泄露。
- 建议修复：更短默认 TTL、下载审计和 doctor 敏感 artifact 统计已完成。剩余是 Web/Qt 高风险提示、对受保护/系统进程失败给稳定 reason code，以及必要时为 `--type normal` 以外模式增加额外确认。
- 涉及入口：`modules/dump/pgs_dump_module.cpp`、`src/service/PGSProtocol.cpp` ArtifactStore、`tools/pgs_bless.cpp`。
- 验证方式：2026-07-26 MSYS smoke 覆盖无 `--confirm` 失败；后续仍需权限不足/进程不存在/超限 dump 专项。
- 是否阻塞功能版 release：否。阻塞生产环境默认推荐 dump collection。

## P1-17 Script runner 必须继续默认禁用并强化执行边界

- 影响组件：`modules/script_runner`、module capability policy、服务数据目录 ACL。
- 当前行为：`script_runner` 默认禁用；必须 `script-runner config --enable`，登记服务数据目录 `modules\script_runner\scripts` 下的脚本，且 `script-runner run --id <id> --confirm` 才会执行。模块不提供远程 shell，不接 webhook/chat，不联网。2026-07-28 已补 final-path 检查：登记和运行都会通过文件句柄解析最终路径，确认脚本真实落在 module data scripts 目录下；登记时记录 SHA-256，运行前重新 hash，不一致则 fail-closed；config/add/run deny/attempt/result 会发 `script_runner.*` 审计事件，事件包含 caller、脚本 id、hash 和 args hash。
- 风险/攻击面：一旦启用，本质上是本机命令执行能力；final-path、hash-on-run 和审计已降低路径绕过/篡改风险，但脚本目录 ACL、签名策略和远程 Web RBAC 仍决定生产安全边界。
- 建议修复：生产版保持禁用并在 UI 高风险标红；脚本登记继续增加签名/publisher policy；Web/remote RBAC 默认禁止 script run；doctor 后续检查脚本目录 ACL 和旧无 hash 条目；必要时用受限 token/job 执行脚本。
- 涉及入口：`modules/script_runner/pgs_script_runner_module.cpp`、`tools/pgs_bless.cpp`、Web RBAC。
- 验证方式：默认 run 失败；无 `--confirm` 失败；目录外脚本 add 失败；脚本篡改后 `run --confirm` 因 hash mismatch 失败并出现 `script_runner.run-denied` 事件；脚本目录宽 ACL 被 doctor 报告；remote viewer/operator 无权运行。
- 2026-07-26 验证补充：MSYS smoke 覆盖默认禁用 run 失败、目录外 add 失败、登记受限目录内脚本、启用后无 confirm run 失败。
- 2026-07-28 验证补充：MSYS smoke 覆盖 doctor/status 的 `path_policy=final-path-under-data-scripts`、`hash_on_run=1`、登记返回 `sha256`、篡改脚本后 run 拒绝和 `script_runner.run-denied` 审计事件。
- 是否阻塞功能版 release：否。阻塞任何“远程脚本执行”生产承诺。

## P1-18 Service guard / file watch / update 模块的生产化边界

- 影响组件：`modules/service_guard`、`modules/file_watch`、`modules/update`、notify/event pipeline。
- 当前行为：`service_guard` 本机 SCM mutation 需要 `confirm=1`，默认拒绝 `EventLog`、`WinDefend`、`MpsSvc`、`Schedule`、`RpcSs` 等受保护服务；可通过持久化 `service_guard` policy 配置 mutation allowlist，只有额外设置 `allow_protected=1` 且服务显式在 allowlist 内时才允许触碰受保护服务；mutation 和 policy 更新都会发 PGS 审计事件，doctor/status 会展示 `mutation_policy`、allowlist 状态和受保护服务数量。`file_watch` 是 demand-driven check，不开后台 watcher，最多 64 条规则，只允许本机绝对盘符路径，并拒绝 UNC/device/ADS/Windows 系统目录/System Volume Information/Recycle Bin 路径，doctor 会展示规则数、上限和路径策略；`update` 只验证本地 release manifest 的 `files` hash，不下载、不安装，并已修正为读取 manifest `release_root` 且忽略 artifacts 绝对路径。
- 风险/攻击面：服务 start/stop 仍是高影响操作；`service_guard` 已有确认门槛、受保护服务默认拒绝、allowlist 和内存审计，但 Web/Qt 专用 UI 与远程 RBAC 还需要按高风险操作处理。file_watch 已有基础路径策略和规则上限，但仍可能产生事件噪音或被配置到业务敏感文件；update 验证若未来扩展到下载/安装，必须先完成签名、回滚和 fail-closed。
- 建议修复：service_guard 后续补结构化 UI 风险提示、远程 RBAC 默认禁止 mutation、持久化/防篡改审计；file_watch 后续可增加更细的 operator allowlist/denylist 配置和 UI 风险提示；update 在代码签名和 release manifest 强制验证前不要实现网络更新或安装。
- 涉及入口：`modules/service_guard/pgs_service_guard_module.cpp`、`modules/file_watch/pgs_file_watch_module.cpp`、`modules/update/pgs_update_module.cpp`。
- 验证方式：2026-07-28 smoke 覆盖 doctor `service_guard`/`file_watch` 策略字段、`service-guard policy` 确认门槛、allowlist set/clear、带 confirm 操作 `EventLog` 被 `protected-service` 拒绝并出现 `service_guard.mutation-denied` 审计事件、`file-watch status` 的 `max_rules/path_policy` 和 Windows 系统路径拒绝；2026-07-26 MSYS smoke 覆盖服务 mutation 无 confirm 失败、file_watch unreadable add 失败、篡改 payload 后 `update verify` hash mismatch 失败；既有 smoke 覆盖 remove/check 正向和 `artifacts` 数组绝对路径不影响 release tree verify。
- 是否阻塞功能版 release：否。阻塞自动更新和远程服务控制生产化。
