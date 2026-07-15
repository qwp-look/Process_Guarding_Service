# PGS 安全收口交接文档

本文档专门交接后续安全专项。当前主线优先完成“功能可用版”，只修功能正确性必需的权限/校验问题；下面条目仍需作为独立安全收口任务继续做。每条都包含影响组件、当前行为、风险、建议修复、入口、验证方式、优先级和是否阻塞功能版 release。

优先级定义：P0 = 应尽快修，可能造成本机提权或远程未授权操作；P1 = release 后安全专项第一批；P2 = 加固/审计完善。

## P0-01 Web 本地页面嵌入 API token

- 影响组件：`pgs_admin_web`
- 当前行为：loopback 模式下首页将每进程 API token 嵌入 `window.PGS_API_TOKEN`，浏览器 JS 用它调用 `/api/*`。
- 风险/攻击面：本机同用户浏览器扩展、调试工具、恶意本地页面利用浏览器状态或读取页面内容后，可复用 token 调本地管理 API。当前已有 Host/Origin/CSRF 检查，但 token 仍在页面内。
- 建议修复：改为 HttpOnly SameSite cookie + per-request CSRF；或把 loopback 也切到一次性 session cookie，不再把 bearer token 暴露给 JS。保留 remote 模式 Basic/RBAC/TLS，不混用 PGS 管理 token。
- 涉及入口：`qt/pgs_admin_web/src/WebServer.cpp` 的 `handleIndexHtml()`、`isRequestAuthorized()`、前端 `api()`。
- 验证方式：浏览器页面源码不包含 token；无 cookie/无 CSRF 请求失败；跨 Origin POST 失败；loopback 正常 UI 仍可操作。
- 是否阻塞功能版 release：否。阻塞安全版 release。

## P0-02 模块 allowlist 仍可只按名称放行

- 影响组件：`ModuleManager`、`modules.allow`
- 当前行为：`modules.allow` 支持 `name`、`name|sha256`、`name|sha256|signed`。默认 bundled allowlist 只有名称，功能版 release 为方便 bundled 模块加载没有强制哈希。
- 风险/攻击面：若攻击者能写入 modules 目录并替换同名 DLL，名称 allowlist 不足以阻止加载。当前模块目录 ACL 已有加固，但仍属于“防御纵深不完整”。
- 建议修复：发布包生成时写入 bundled DLL 的 SHA-256；生产默认要求哈希匹配；签名可用后增加 `|signed`；为 `pgs_bless module trust` 增加批量生成 release allowlist 的命令。
- 涉及入口：`tools/build_pgs.*`、`tools/package_release.bat`、`src/modules/ModuleManager.cpp`、`docs/MODULE_SYSTEM.md`。
- 验证方式：篡改 bundled DLL 后 `module load` 失败并记录 hash mismatch；未篡改 release 模块可加载；`module info --json` 显示 allow entry satisfied。
- 是否阻塞功能版 release：否。阻塞生产安全版 release。

## P0-03 模块目录 ACL 需要 fail-closed 递归验证

- 影响组件：PGS 服务启动、模块加载、PPL opt-in
- 当前行为：PPL opt-in 时会递归加固 modules tree；部分 ACL 失败路径仍偏日志/告警，未形成统一的 release 前检查。
- 风险/攻击面：模块目录或子目录可被非管理员写入时，模块加载边界失效。
- 建议修复：启动时对 modules 根、子目录、DLL、manifest 做 owner/DACL 检查；生产模式任一失败则拒绝模块加载；添加 `pgs_bless module audit-acl` 或 release smoke ACL 检查。
- 涉及入口：`src/service/PGS.cpp` 的 `secureModulesTree()`、`ModuleManager::load()`、`tools/release_smoke.ps1`。
- 验证方式：给 Users 写权限后模块加载失败；修正 ACL 后恢复；日志包含具体路径和 ACE 诊断。
- 是否阻塞功能版 release：否。阻塞安全版 release。

## P0-04 bootstrap token 文件 ACL 仍需 fail-closed

- 影响组件：服务首次启动 token 生成
- 当前行为：首次无归档时生成 token 并写入 `pgs_initial_token.txt`，目录 ACL 设计为 SYSTEM + Administrators，但 ACL 写入失败时需要进一步确认是否严格失败。
- 风险/攻击面：初始 token 若落入宽权限目录，普通本机用户可读取管理 token。
- 建议修复：初始 token 文件写入前后检查 DACL；ACL 设置失败时服务拒绝启动并要求管理员修复目录；提供 `pgs_service repair-state-acl`。
- 涉及入口：`src/service/PGS.cpp` 的 `writeInitialTokenFile()`、`initialize()`，`docs/SERVICE_MODE_GUIDE.md`。
- 验证方式：模拟 ProgramData state 目录宽权限/ACL 设置失败，服务应 fail-closed；正常目录首次启动仍写 token。
- 是否阻塞功能版 release：否。阻塞安全版 release。

## P1-05 `--allow-all-modules` 生命周期和撤销

- 影响组件：服务宿主、状态归档、模块加载
- 当前行为：`--allow-all-modules` 可写入 SCM binPath，并持久化 `MODULES_PERMISSIVE\t1`，用于开发逃生。
- 风险/攻击面：一次调试开启后可能长期保留，等价于关闭模块边界。
- 建议修复：增加显式 `module permissive off` 或 `pgs_service install --no-allow-all-modules`；状态恢复时记录高危事件；Qt/Web 显示红色状态；生产 release smoke 检查默认关闭。
- 涉及入口：`src/service/pgs_service.cpp`、`src/service/PGS.cpp`、`docs/MODULE_SYSTEM.md`。
- 验证方式：开启后能显示/审计；关闭后归档和 SCM binPath 都移除；缺 allowlist 时模块加载重新 fail-closed。
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
- 当前行为：重启失败后会移除 policy 和 persisted guard，避免无限失败循环。
- 风险/攻击面：若失败由瞬时环境导致，守护目标会永久退出保护；若攻击者制造临时文件/权限失败，可能让持久守护失效。
- 建议修复：区分永久失败和临时失败；增加 retry-after / quarantine 状态；持久化失败原因；UI 显示“需要人工处理”而非直接消失。
- 涉及入口：`src/service/PGS.cpp` 的 restore/restart failure 分支、`docs/GUARD_POLICIES.md`。
- 验证方式：模拟缺文件、临时拒绝访问、hash mismatch；确认策略符合预期且可见。
- 是否阻塞功能版 release：否，但建议 P1。

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
- 当前行为：服务端和 CLI 已强制 `--winapp` 必须有 AUMID；尚未实现 WindowsApps 路径解析 `AppxManifest.xml` 自动推导；`bless-start --winapp` 明确拒绝。
- 风险/攻击面：错误 AUMID 会导致重启失败；未校验 AUMID 是否对应目标包/路径。
- 建议修复：解析 package manifest，推导 PackageFamilyName/AUMID；注册时校验 AUMID 与路径 package 匹配；实现 AUMID activation start path 或保持 attach-only 并在 UI 中禁用 start。
- 涉及入口：`include/Process_Guard/PGUtil.h` PFN helpers、`tools/pgs_bless.cpp`、`src/service/PGS.cpp` `restartAppGuard()`。
- 验证方式：`tools/verify_winapp.ps1` 覆盖显式 AUMID；新增 manifest fixture 单元测试；错误 AUMID 拒绝注册或重启失败可见。
- 是否阻塞功能版 release：否，写入未完成功能文档。

## P1-10 发布签名、哈希和供应链完整性

- 影响组件：installer、portable zip、modules、driver
- 当前行为：release smoke 检查产物存在和可运行；beta 发布会附带 `SHA256SUMS.txt`；尚未签名 installer/exe/dll/sys，也未发布 SBOM 或自动化 provenance。
- 风险/攻击面：用户无法验证下载物来源；驱动和模块替换难以及时发现。
- 建议修复：接入代码签名；生成 SHA-256SUMS；发布 SBOM；installer 校验 bundled 文件；模块 allowlist 与 release 哈希同源生成。
- 涉及入口：`tools/build_installer.bat`、`tools/package_release.bat`、`.github/workflows/publish-release.yml`。
- 验证方式：签名验证通过；篡改 zip/installer 后校验失败；release 页面包含 checksums。
- 是否阻塞功能版 release：否。阻塞公开生产发行。

## P2-11 审计日志完整性和留存

- 影响组件：PGS in-memory events、Web remote audit
- 当前行为：PGS events 是内存环；Web remote audit 是 append 文本文件。
- 风险/攻击面：服务重启丢失核心事件；本地管理员或同账号可改 audit 文件；无法证明事件未被删改。
- 建议修复：落盘事件日志；加 hash chain；rotate/retention；关键安全事件写 Windows Event Log。
- 涉及入口：`PGS::recordEvent()`、`WebServer::audit()`。
- 验证方式：重启后事件仍可查询；篡改 audit chain 可检测；日志轮转不丢最近事件。
- 是否阻塞功能版 release：否。

## P2-12 capability policy 尚未强制

- 影响组件：模块 manifest/capabilities、ModuleManager
- 当前行为：manifest capabilities 可展示/审计，但宿主没有按 capability 做运行时授权。
- 风险/攻击面：受信任模块一旦加载就可执行其全部 `PG_Invoke` 内部能力；缺少最小权限。
- 建议修复：定义 capability allow policy；模块 load 时校验 manifest capability；`module call` 前按 policy/role 检查。
- 涉及入口：`include/Process_Guard/PGModule.h`、`src/modules/ModuleManager.cpp`、Web RBAC。
- 验证方式：未授权 capability 的模块加载或调用失败；授权后成功。
- 是否阻塞功能版 release：否。

## P2-13 模块运行态状态不应写入模块目录

- 影响组件：`profile` / `sched` 模块、release smoke、安装目录 ACL
- 当前行为：`profile` 模块会在模块 DLL 同目录写 `pgs_profiles.db`；`sched` 模块也按模块目录设计 `pgs_sched.db`。本轮已在 release smoke / installer 打包前清理并阻断 profile DB 泄漏，但运行态位置尚未迁移。
- 风险/攻击面：生产安装目录应尽量只读和 ACL 加固；模块运行态写在同目录会迫使放宽写权限，削弱模块替换防护。
- 建议修复：扩展 ABI v2 services 或新增 ABI v3，向模块提供受保护的 ProgramData state dir；模块状态迁移到 `%ProgramData%\ProcessGuard\modules\<name>\`；保留旧 DB 单次迁移。
- 涉及入口：`include/Process_Guard/PGModule.h`、`modules/profile/pgs_profile_module.cpp`、`modules/sched/pgs_sched_module.cpp`、`tools/release_smoke.ps1`。
- 验证方式：安装目录对普通用户只读时 profile/sched 仍可 set/list；release tree 和 zip/installer 不包含 `pgs_profiles.db` / `pgs_sched.db`；ProgramData 状态目录 ACL 为 SYSTEM + Administrators。
- 是否阻塞功能版 release：否。阻塞安全版 release 的模块目录只读策略。
