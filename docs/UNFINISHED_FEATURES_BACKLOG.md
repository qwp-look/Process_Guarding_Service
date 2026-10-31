# PGS 未完成/未验证功能交接文档

本文档记录功能完成版之后仍未完成、只部分完成、需要特定环境验证，或本轮主动延期的事项。后续新对话可直接按本文件继续推进，不需要翻聊天记录。

优先级定义：P0 = 影响“功能完成版”可信度，应优先补；P1 = 下一轮功能增强；P2 = 中长期演进。

2026-07-18 审查补充：`tools\verify.bat`、顶层 CMake 构建和 CTest 均通过；新增条目主要是可靠性、诊断、通知、模块生态和 UI 深化方向。

2026-07-19 功能收口记录：

- WindowsApps：CLI 已支持从 WindowsApps exe 路径读取 `AppxManifest.xml` 推导 AUMID，并支持 `bless-start --winapp --aumid` 激活注册；AUMID 激活机制已抽取到 `winapp` launcher provider 模块（2026-10-31，provider 类默认 opt-in，需 `--enable-launchers`）。剩余是 `tools/verify_winapp.ps1` 的真实 Store/UWP E2E。
- Operation/Artifact：服务端已实现 `pgs.operation.*` 和 `pgs.artifact.*`，report 模块可输出 artifact，CLI `module artifact get --out` 下载后会校验 size 和 SHA-256，smoke 已覆盖。
- Web：已补 guard retry/clear-quarantine、health-check set/get/clear、notify status/config、report artifact、operation status、artifact meta/download/status/policy 控件和 API。
- Qt：模块页已补 scheduler add/list/enable/disable/remove、notify status/config、report snapshot/backup、operation status、artifact meta/download/status/policy 便捷控件。
- Notify：按操作者要求仅使用 Windows 本机能力，默认 Event Log，弹窗为显式 opt-in；不接聊天软件、webhook、邮件或远程 messenger。
- Metrics/Backup/Eventlog：低风险模块首版已 bundled。`metrics` 支持 summary/JSON/Prometheus，`backup` 支持本地状态快照和 artifact 输出，`eventlog` 支持本机 Application Event Log 读取与 source 过滤。
- Release metadata：`build_installer.bat` 会生成 `SHA256SUMS.txt`、`release-manifest.json`、`sbom.spdx.json`；publish workflow 会上传这三个元数据文件并请求 GitHub artifact attestation。
- 新增候选模块首版全部完成：`dump`、`service_guard`、`file_watch`、`policy`、`remote_agent`、`update`、`script_runner` 已进入 bundled build / `modules.lock` / release package / CLI wrapper / smoke 覆盖。高风险动作保留确认门槛，`script_runner` 默认禁用，`update` 只做本地 manifest 校验不联网不安装。
- 本轮已实际验证：Windows 主构建、MSYS shell 构建、core unit、运行 smoke、release packaging、release smoke、installer/zip/manifest/SBOM/checksum 生成均通过。

2026-07-20 Artifact/Doctor 收口记录：

- ArtifactStore：已补 `module artifact status [--verify]`、`module artifact policy`、Web `/api/artifact/status`、Web `/api/artifact/policy`、Qt report 区域 status/policy 控件和 `pgs_bless doctor` 的 `artifact_store` 检查。策略持久化到服务 state 目录下 `artifact_policy.cfg`，支持 `ttl_ms`、`auto_cleanup`、`verify_on_status`、`max_artifact_bytes`、`max_total_bytes`；TTL 范围限制为 60 秒到 7 天；artifact 单文件配额默认 16MB、允许 64KB..64MB，总量配额默认 256MB、允许 1MB..1GB，且总量不能小于单文件上限。2026-07-26 又补了后台过期清理、下载审计事件、敏感 artifact metadata/status/doctor 计数，以及 dump/report 默认敏感等级和 TTL 裁剪；2026-07-28 补了 CLI/Web/Qt 配额策略入口和 smoke 覆盖。
- Artifact integrity：metadata id 与请求 artifact id 不一致会 fail-closed；metadata 文件名 stem 与 metadata `id` 不一致会计为 corrupt；`cleanup --all` 或 `cleanup --verify` 会移除坏 metadata 并报告清理数量。
- Guard failure code：状态版本已到 v5，`list/get --json` 已输出 `last_failure_code`，并已有初步稳定失败码，例如 `restart.hash_mismatch`、`restart.create_process`、`restart.session_token`、`winapp.activate_failed`；Qt 守护表格已显示隔离/失败码/健康字段并可 retry/clear-quarantine。剩余问题是分类完整度、failure timeline、处理建议和专项负例覆盖。
- 验证：`cmake --build build_cmake --config Release`、Qt Web/Qt desktop build、`ctest --test-dir build_cmake --output-on-failure`、`tools\test_core_units.bat`、`tools\build_pgs.bat`、MSYS `tools/smoke_test_pgs.sh` 在 `build_cmake` 和传统 `build` 目录均通过。

2026-07-20 Qt Doctor/Guard 可见性补充：

- Qt Doctor：Qt 主窗口已新增 Doctor / Repair 专用页，直接调用 `pgs_bless doctor --json` 并用同一 JSON schema 渲染检查表；提供 `repair-state-acl`、`repair-modules-acl`、`repair-modules-lock` 操作按钮，模块目录可配置，repair 成功后会自动刷新 doctor 结果。
- Qt Guard Table：守护表格已扩展显示 `guard_id`、`status`、`quarantined`、`last_failure_code`、`failure_count`、`next_retry_ms`、`health_status`、`health_failure_count`、`last_failure` 等字段；隔离/失败行会高亮，并可对选中 guard 执行 retry / clear-quarantine。
- 验证：`cmake --build build\pgs_admin_qt --config Release` 已通过。

2026-07-20 Qt Health / Cluster 交互补充：

- Qt Health Policy：Qt 守护表格页已新增健康策略表单，选中 guard 会自动填充 PID；支持 `process`、`tcp`、`http` 类型，`enabled`、`interval_ms`、`timeout_ms`、`failures`、`action` 字段，以及 TCP host/port、HTTP url 专项字段；表单通过 `pgs_bless health-check set|get|clear` 复用既有协议，不新增服务端命令。
- Cluster Dashboard：Cluster Web 已新增 `PUT /api/cluster/nodes` 和 `POST /api/cluster/nodes/test`；详情页支持节点重命名、URL 编辑、凭据替换/清空和即时测试 `/api/cluster/health`。节点列表/summary 仍不回显凭据，保存后仍走现有 DPAPI 本地保护；测试接口可用空密码保留已保存凭据，也可用临时输入凭据测试。
- Cluster guard detail：Cluster 汇总 guard 行已补 `status`、`quarantined`、`health_status`、`last_failure_code` 字段，详情表可以直接看到隔离、健康和失败码。
- 验证：带显式 MSYS2/MinGW 环境变量运行 `cmake --build build\pgs_admin_qt --config Release`、`cmake --build build\pgs_cluster_web --config Release` 均通过；`git diff --check` 对相关 Qt/Cluster 文件仅有 LF->CRLF 提示。

2026-07-20 Health smoke 收口补充：

- Health negative smoke：`tools/smoke_test_pgs.sh` 已补 TCP closed、TCP DNS failure、HTTP unexpected status 和 HTTP timeout 负例；TCP 探针连本机空闲端口会进入 `unhealthy` 并返回 `tcp connect failed...`，TCP DNS 失败会返回 `tcp resolve failed...`，HTTP 探针连本机临时 500 响应服务且 `expected_status=200` 会进入 `unhealthy` 并返回 `http unexpected status=500`，HTTP timeout 会返回 `http request failed...`。
- Smoke 稳定性：smoke 默认端口改为动态空闲端口，仍可用 `PGS_SMOKE_PORT` 显式覆盖；artifact 流程前会清理旧 artifact，避免复用 `build/local_pd_smoke` 时因历史数据导致 `count` 断言误报。
- 验证：带显式 MSYS2/MinGW 环境变量运行 `PGS_BUILD_DIR=build ./tools/smoke_test_pgs.sh` 已通过完整 smoke。

2026-07-20 Cluster API smoke 收口补充：

- Cluster API automation：新增 `tools/cluster_api_smoke.ps1`，单独启动 `pgs_cluster_web` 并覆盖无 token 401、node add/list/edit/test/clear-credentials/remove、节点 API 不回显 `credentials` 字段、测试接口不回显保存凭据、节点注册文件不明文保存凭据。
- VM acceptance：`tools/vm_acceptance.ps1` 的 Cluster 段已从 add/remove 扩展为 add/list/test/update/clear/remove，并增加凭据不回显和注册文件不明文断言。
- 验证：带显式 MSYS2/MinGW 环境变量运行 `powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\cluster_api_smoke.ps1 -ClusterExe .\build\pgs_cluster_web\pgs_cluster_web.exe -WorkRoot .\build\cluster_api_smoke` 已通过；`cluster_api_smoke.ps1` 和 `vm_acceptance.ps1` 均通过 PowerShell scriptblock parse。

2026-07-20 Web 结构化响应收口补充：

- Web structured result：`pgs_admin_web` 首页已新增 `Structured Result` 区域，module list/call、metrics、backup、eventlog、notify、report、operation、artifact、schedule 操作会在保留 Activity Log 原始输出的同时渲染 key-value 或表格结果；report/backup stdout 中的 `operation_id` / `artifact_id` 会自动回填到对应输入框。
- 验证：带显式 MSYS2/MinGW 环境变量运行 `cmake --build build\pgs_admin_web --config Release` 已通过；本地启动 `pgs_admin_web` 抓取首页确认包含 `Structured Result` 且不包含 `window.PGS_API_TOKEN`。

## P0-01 WindowsApps 自动 AUMID 推导真实环境验证

- 预期行为：用户给出 `C:\Program Files\WindowsApps\...\App.exe` 时，CLI/服务可解析 `AppxManifest.xml`，推导 PackageFamilyName 和 AUMID。
- 当前状态：代码已实现。`PGUtil.h` 有 manifest/PFN/AUMID helper，`pgs_bless` 在 `--winapp` 且未传 `--aumid` 时会尝试从路径推导；显式 AUMID 与 manifest 推导不一致时拒绝。激活机制位于 `winapp` launcher provider 模块（2026-10-31）。
- 未完成原因：真实 WindowsApps/Store 环境、不同 publisher hash 兼容性、错误 manifest/错误路径负例仍需在管理员/交互会话里验证。
- 下一步方案：运行 `tools/verify_winapp.ps1`；增加错误 AUMID、manifest 不可读、package/path 不匹配的专项负例。
- 测试方式：manifest fixture unit；`tools/verify_winapp.ps1` 真实环境；错误 manifest/错误路径负例。
- 相关入口：`tools/pgs_bless.cpp`、`include/Process_Guard/PGUtil.h`、`src/service/PGS.cpp`
- 优先级：P0

## P0-02 `bless-start --winapp` AUMID 激活真实环境验证

- 预期行为：用户可直接 `bless-start --winapp --aumid ...` 激活 Store/UWP app 并注册返回的 PID。
- 当前状态：代码已实现。`pgs_bless bless-start --winapp --aumid <id>` 经 `winapp` launcher provider 模块激活，查询激活 PID/path，并确认激活出的进程 AUMID 与请求匹配后注册。Web `bless-start` 入口也允许 AUMID-only WinApp。
- 未完成原因：需要真实 Store/UWP 应用验证交互 session、错误 AUMID、ShellExecute fallback、无法查询路径等外部环境行为。
- 下一步方案：运行 `tools/verify_winapp.ps1 -RunWinApp` 或 VM acceptance 的 `-RunWinApp` 路径，保存日志到 release notes。
- 测试方式：真实 WindowsApps 环境；无交互 session、错误 AUMID、fallback ShellExecute 负例。
- 相关入口：`tools/pgs_bless.cpp`、`src/service/PGS.cpp`
- 优先级：P0

## P0-03 完整管理员 VM E2E 尚未在本轮运行

- 预期行为：在干净管理员 VM 中跑完 portable、SCM install/start/stop、installer、Web、Cluster、launcher provider opt-in、WindowsApps helper。
- 当前状态：`tools/vm_acceptance.ps1` 已扩展，支持 `-EnablePpl` 和 `-RunWinApp`，但本轮未在真实干净 VM 里执行。
- 未完成原因：需要管理员 VM、安装器、真实服务权限和可能的 WindowsApps 环境。
- 下一步方案：发布前在 VM 中执行 `powershell -File tools\vm_acceptance.ps1 -EnablePpl -RunWinApp`，保存日志到 release notes。
- 测试方式：脚本输出 `ACCEPTANCE_OK`；收集 `logs\*.log`。
- 相关入口：`tools/vm_acceptance.ps1`、`tools/verify_winapp.ps1`
- 优先级：P0

## P1-04 PPL 正向能力需要真实驱动环境验证

- 预期行为：启用 `--enable-ppl` 后 PPL 模块可加载，`ppl set/get/clear` 对测试进程生效。
- 当前状态：默认拒绝 PPL load 已覆盖；`vm_acceptance.ps1 -EnablePpl` 增加了 opt-in load，但未验证真实 signer 生效。
- 未完成原因：需要测试签名/驱动加载环境，且错误操作可能影响系统进程。
- 下一步方案：在 VM 中用专用 worker 验证 set/get/clear；失败时收集 SCM/driver error。
- 测试方式：`pgs_bless ppl set --pid <worker> --signer Antimalware` 后 `ppl get` 返回预期 signer，再 clear。
- 相关入口：`modules/ppl/pgs_ppl_module.cpp`、`tools/vm_acceptance.ps1`
- 优先级：P1

## P1-05 Web/Cluster 深层交互仍是轻量完成态

- 预期行为：Web 有完整模块管理、调度管理、高级策略表单；Cluster 有节点编辑、测试连接、凭据替换、丰富 guard 详情。
- 当前状态：Web 已有高级策略、guard 隔离恢复、health-check set/get/clear、notify status/config、Scheduler add/list/enable/disable/remove、report artifact、operation status、artifact meta/download/status/policy 基础入口；module/scheduler/report/artifact 等结果已进入 `Structured Result` 区域，支持 key-value/table 渲染并保留原始 Activity Log。Cluster 已有 add/remove/edit/test、凭据替换/清空、节点详情、guard 隔离/健康/失败码字段展示，并已有本地 HTTP API smoke 覆盖 add/list/edit/test/clear/remove 和凭据不回显/不明文落盘断言。
- 未完成原因：Web 主控台结构化结果区已补，但错误分组、跨操作持久状态和更深的浏览器 DOM 自动化仍未做；Cluster API 自动化已补，但仍缺真实 remote gateway 联调用例和浏览器 DOM/UI smoke。
- 下一步方案：Web 继续补错误分组、字段级校验和浏览器 DOM smoke；为 remote gateway 添加联调用例；artifact 下载审计和敏感 artifact 提示放入后续安全专项；补 Playwright/浏览器 DOM 覆盖 Cluster add/edit/test/remove。
- 测试方式：已构建验证 Web/Cluster Web；本地 `tools/cluster_api_smoke.ps1` 已通过；Web 首页 smoke 已确认 Structured Result 和无 token 泄露；后续 Playwright/浏览器 DOM smoke；Cluster 添加一个真实 remote Web node 并轮询成功。
- 相关入口：`qt/pgs_admin_web/src/WebServer.cpp`、`qt/pgs_cluster_web/src/ClusterServer.cpp`
- 优先级：P1

## P1-06 Qt 模块便捷页后续产品化

- 预期行为：Qt 模块页为常用 bundled modules 提供低摩擦操作，而不是只靠 generic invoke。
- 当前状态：已在 `ModulePage` 为 `sched` 增加类型/表达式/action/count/id 和 add/list/enable/disable/remove；为 `notify` 增加 status/config；为 `report` 增加 snapshot/backup、artifact、operation status、artifact meta/download/status/policy。7 个新增模块可通过通用 module invoke 入口操作，但还没有结构化专用页面。
- 未完成原因：仍是模块页内的便捷控件，不是完整独立页面；没有结构化表格渲染、校验提示和持久表单状态。
- 下一步方案：按使用频率决定是否把 Scheduler/Report/Notify 拆成独立 tab，增加结构化结果渲染和手工 UI smoke。
- 测试方式：Qt 构建；手工添加 interval schedule，list/remove 成功。
- 相关入口：`qt/pgs_admin_qt/src/ModulePage.cpp`、`tools/pgs_bless.cpp`
- 优先级：P1

## P1-07 长稳/压力测试结果基线未沉淀

- 预期行为：release 前有固定分钟数/迭代数的压力和长稳日志，能比较性能/稳定性回归。
- 当前状态：新增 `tools/pressure_pgs.ps1` 和 `tools/long_stability.ps1`；本轮已跑短压测 `-Iterations 3` 和 1 分钟长稳 smoke，但未完成长时间基线，也未定义合格阈值。
- 未完成原因：长稳耗时，且应在干净 VM 或固定环境运行。
- 下一步方案：夜间运行 `pressure_pgs.ps1 -Iterations 500` 和 `long_stability.ps1 -Minutes 240`；记录 CPU、内存、句柄数。
- 测试方式：脚本输出 `PRESSURE_OK` / `LONG_STABILITY_OK`，无服务崩溃、无句柄持续增长。
- 相关入口：`tools/pressure_pgs.ps1`、`tools/long_stability.ps1`
- 优先级：P1

## P1-08 Release 包完整性策略

- 预期行为：release tree、zip、installer 有完整 manifest/checksum/SBOM/provenance，发布前 release smoke 和 artifact 验证强制执行。
- 当前状态：2026-07-19 已新增仓库根层 `VERSION` 作为版本源；`tools/build_installer.bat` 默认读取 `VERSION`，通过 `/DPGSAppVersion` 传给 Inno Setup，并在 installer/zip 完成后生成 `SHA256SUMS.txt`、`release-manifest.json`、`sbom.spdx.json`。`.github/workflows/publish-release.yml` 从 `VERSION` 推导 tag、release name、installer/zip 文件名和 release body，发布 installer/zip/metadata，并请求 GitHub artifact attestation。发布产物仍上传到 GitHub Releases，不提交 `release\` 或 `installer\Output\`。代码签名仍未配置。
- 未完成原因：签名证书未配置；publish workflow 还需要真实 GitHub Release 运行来验证 attestation 权限和最终资产上传；README/用户文档仍保留当前 beta 文件名示例，需要随下一次正式改版同步为基于 `VERSION` 的说明或占位写法。
- 下一步方案：接入代码签名；跑一次 live publish workflow 并确认 installer/zip/checksum/manifest/SBOM/provenance 全部可见；文档中的下载文件名跟随 `VERSION` 更新。
- 测试方式：已用显式 MSYS2/MinGW 环境变量运行 `tools\build_pgs.bat`、Qt/Web 构建、`tools\test_core_units.bat`、`tools\smoke_test_pgs.sh` 通过；`tools\write_release_manifest.ps1` 已用临时 release 验证 PowerShell 5.1 兼容和多 artifact checksum。完整 installer/signing/live release 仍需在装有 Inno Setup 的环境或 CI 中跑一次。
- 相关入口：`tools/package_release.bat`、`tools/build_installer.bat`、`installer/pgs_installer.iss`、`.github/workflows/publish-release.yml`
- 优先级：P1

## P1-09 模块运行态状态迁移到 ProgramData

- 预期行为：模块 DLL/manifest 所在目录保持发布态、可只读；profile/scheduler 等运行态数据库写入 ProgramData 或服务状态目录。
- 当前状态：2026-07-18 已完成代码迁移。`profile` / `sched` 在 `PG_Init` 中读取 ABI v3 `get_data_dir()`，默认写入服务 state 根下的 `modules\profile\pgs_profiles.db` 和 `modules\sched\pgs_sched.db`；如果新位置不存在而旧模块目录 DB 存在，会进行一次兼容复制。`release_smoke.ps1` 和 `build_installer.bat` 继续防止 DB 泄漏进 zip/installer。
- 未完成原因：低权限/只读安装目录的真实安装态验证尚未跑；旧 DB 迁移当前为 copy-only，不主动删除旧文件，避免误删用户数据。
- 下一步方案：release smoke 增加只读安装目录场景；在文档中说明旧 DB 可由管理员确认后清理。
- 测试方式：已用显式 MSYS2/MinGW 环境变量运行 `tools\build_pgs.bat` 通过；`tools\test_core_units.bat` 通过。仍需 release smoke/安装态验证 ProgramData 写入路径。
- 相关入口：`include/Process_Guard/PGModule.h`、`modules/profile/pgs_profile_module.cpp`、`modules/sched/pgs_sched_module.cpp`、`tools/release_smoke.ps1`
- 优先级：P1

## P2-10 protobuf 协议迁移

- 预期行为：管理协议可迁移到 protobuf 或其他 schema-first 格式，并保留兼容期。
- 当前状态：继续使用文本行协议；新增 `version`/`stats` CLI 和 `tools/protocol_contract.ps1` 作为轻量契约测试。
- 未完成原因：当前流量低、协议简单；立即迁移会扩大兼容和测试成本。
- 下一步方案：先补 JSON schema/契约测试覆盖所有命令；只有当协议继续复杂化时再设计 protobuf v4。
- 测试方式：旧 CLI 与新服务兼容；contract tests 固定响应字段。
- 相关入口：`src/service/PGSProtocol.cpp`、`src/common/PGSClient.cpp`
- 优先级：P2

## P2-11 Web/Qt 自动化 UI 测试

- 预期行为：Web 和 Qt 至少有一套自动化冒烟，覆盖高级策略字段、模块、Scheduler、Cluster 节点管理。
- 当前状态：构建验证和 API smoke 已有；没有浏览器/GUI 自动化截图验证。
- 未完成原因：需要 Playwright/GUI runner 环境和稳定窗口管理。
- 下一步方案：Web 优先加 Playwright HTTP+DOM；Qt 可先保留 launch smoke，再评估 Squish/WinAppDriver。
- 测试方式：Web DOM 能 add schedule/call module；Cluster node add/remove 可见；Qt 启动不退出。
- 相关入口：`qt/pgs_admin_web`、`qt/pgs_cluster_web`、`qt/pgs_admin_qt`
- 优先级：P2

## P1-12 Guard quarantine 与失败可见性

- 预期行为：重启失败后 guard 不应直接从持久保护列表消失，而是进入 `quarantine` / `needs-attention` 状态，记录失败原因、失败次数、下次重试时间和人工处理建议。
- 当前状态：2026-07-20 已推进到 v5。状态文件包含 `QUARANTINED`、`LAST_FAILURE_B64`、`NEXT_RETRY_MS`、`FAILURE_COUNT`、`LAST_FAILURE_CODE`；自动重启失败、延迟重启失败、restore 重启失败、重启次数用尽都会进入隔离态并保留归档；`list/get` 输出 `guard_id/status/quarantined/last_failure/last_failure_code/next_retry_ms/failure_count`；CLI 新增 `guard retry --id <guard-id>` 和 `guard clear-quarantine --id <guard-id>`；Web 有 retry/clear 控件；Qt 守护表格已显示隔离/失败码/健康字段并提供选中 guard 的 retry / clear-quarantine 操作。intentional exit 仍按主动退保护清理。
- 未完成原因：Web/Qt/CLI 已能操作隔离态并展示初步稳定 `last_failure_code`；完整 failure timeline 尚未做，失败码 taxonomy 仍不完整，缺文件、access denied、hash mismatch、Session token 获取失败等专项负例尚未逐一自动化。
- 下一步方案：补全 failure code taxonomy 和 failure history；为 Web/Qt 增加按 failure code 分组的处理建议；把 hash mismatch / file missing / access denied / Session 失败加入独立契约测试。
- 测试方式：已用显式 MSYS2/MinGW 环境变量运行 `tools\build_pgs.bat`、`tools\test_core_units.bat`、`tools\smoke_test_pgs.sh` 通过；smoke 覆盖重启窗口耗尽后保留 quarantined 记录并可 clear-quarantine。
- 相关入口：`src/service/PGS.cpp`、`src/service/PGSProtocol.cpp`、`docs/GUARD_POLICIES.md`、Qt/Web guard 详情页。
- 优先级：P1

## P1-13 Health Check 执行引擎

- 预期行为：`health-check` 不只存配置，还能按策略执行探针；进程假活、HTTP/TCP 不健康、资源异常时触发重启或告警。
- 当前状态：2026-07-18 核心执行引擎已完成，2026-07-20 Qt 操作入口和关键负例 smoke 已补齐，2026-07-28 又补 timeout/DNS 负例。核心新增独立 `healthLoop`，不会占用 monitor 重启线程或 TCP client worker；支持 `process`、`tcp`、`http` 三类探针；配置支持 `enabled`、`type`、`interval_ms`/`interval_sec`、`timeout_ms`、`failures`、`action`。`action` 支持 `event`/`none`/`restart`/`quarantine`，其中告警型 `alert`/`notify` 会归一为 `event`，实际本机通知交给 Notify 模块。`list/get --json` 新增 `health_status`、`health_last_message`、`health_last_check`、`health_last_ok`、`health_last_failure`、`health_next_check`、`health_failure_count`。Web 已有 health JSON set/get/clear；Qt 守护表格页已新增健康策略表单，支持 process/tcp/http 配置、set/get/clear 和选中 guard 自动填 PID；smoke 已覆盖 `process` healthy、TCP closed/TCP DNS failure unhealthy、HTTP unexpected status/HTTP timeout unhealthy，以及 health action `restart` / `quarantine` E2E。
- 未完成原因：核心探针执行、Web/Qt 操作入口、TCP/HTTP 主要负例和 restart/quarantine 动作链路已完成；自定义脚本探针仍故意不开放，等权限模型、OperationStore 和审计留存成熟后再评估；UI 仍缺按 failure code 分组的处理建议。
- 下一步方案：后续补按 failure code 分组的 UI 处理建议和 failure action 审计说明。
- 测试方式：已用显式 MSYS2/MinGW 环境变量运行 `tools\build_pgs.bat`、`tools\test_core_units.bat`、`tools\smoke_test_pgs.sh` 通过；smoke 覆盖 `process` 探针进入 healthy、TCP closed 进入 unhealthy、TCP DNS resolve failed 进入 unhealthy、HTTP 500 unexpected status 进入 unhealthy、HTTP timeout 进入 unhealthy、health restart 触发新 pid、health quarantine 进入 `health.failed` 隔离态，以及隔离清理不被新字段破坏；Qt health policy UI 构建验证通过。
- 相关入口：`src/service/PGS.cpp`、`src/service/PGSProtocol.cpp`、`docs/GUARD_POLICIES.md`、Web/Qt guard policy 表单。
- 优先级：P1

## P1-14 Notify 告警模块

- 预期行为：关键事件推送到 Windows 本机能力。按操作者要求，不接入聊天软件、webhook、邮件或远程 messenger；默认使用 Windows Event Log，弹窗/MessageBox 只能显式开启。
- 当前状态：2026-07-18 第一阶段功能已完成。新增 bundled `notify` ABI v3 模块，默认写 Windows Application Event Log source `ProcessGuardService`；`popup=0` 默认关闭，可用 `pgs_bless notify config --popup` 显式开启本机 `MessageBoxTimeoutW` 弹窗。核心 `recordEvent()` 会把事件异步入队，由 `notifyLoop` 投递到模块，不阻塞 guard monitor、health worker 或 TCP client worker；通知失败写 `notify.delivery-failed`，且不会递归通知自身。CLI 新增 `notify status|config`。配置写入 ProgramData state 根下 `modules\notify\notify.cfg`。
- 未完成原因：Windows Toast 形式尚未做；Event Log source 目前是 best-effort，若系统未注册 message resource，事件查看器可能显示通用描述；Web/Qt 已有 notify status/config 控件，但 Event Log 读取验证尚未自动化。
- 下一步方案：增加可选 Toast/AUMID 支持；安装器注册 Event Log source/message DLL；增加 Event Log 查询验证脚本。
- 测试方式：已用显式 MSYS2/MinGW 环境变量运行 `tools\build_pgs.bat`、`tools\smoke_test_pgs.sh` 通过；smoke 以 `--enable-modules` 启动并验证 `notify status`。后续仍需管理员 VM 中读取 Event Log 验证。
- 相关入口：`PGS::recordEvent()`、`PGS::notifyLoop()`、`modules/notify/pgs_notify_module.cpp`、`tools/pgs_bless.cpp`。
- 优先级：P1

## P1-15 Doctor / Repair 中心

- 预期行为：CLI、Qt、Web 都能展示服务、token、端口、ACL、模块锁、Qt/OpenSSL runtime、ProgramData 状态目录、PPL gate 等诊断结果，并给出可执行修复。
- 当前状态：CLI 已有 `pgs_bless doctor [--json]` 和 `repair-state-acl|repair-modules-acl|repair-modules-lock`；doctor JSON 已包含 `artifact_store` 检查；Web 有只读 `/api/doctor` 展示；Qt 已新增 Doctor / Repair 专用页，直接渲染 CLI doctor JSON，并提供 state ACL、modules ACL、modules.lock repair 按钮。
- 未完成原因：Qt/Web/CLI 已共用 doctor JSON 展示；剩余是固定更完整的 doctor schema、把 repair 结果也统一为可描述 schema、增加更多 repair 动作；ArtifactStore 已有健康检查，但敏感 artifact 分类、下载审计和长期留存基线仍属于安全专项。
- 下一步方案：固定 doctor JSON schema；把 repair 结果纳入统一 schema；逐步增加 `clear-web-session`、模块数据目录 ACL、Event Log source 注册检查等修复动作。
- 测试方式：Qt 构建已通过；后续人为破坏 ACL、删除 modules.lock、占用端口、缺 runtime DLL；doctor 能定位且 repair 能恢复可恢复项。
- 相关入口：`tools/pgs_bless.cpp`、`src/service/pgs_service.cpp`、`qt/pgs_admin_web/src/WebServer.cpp`、`qt/pgs_admin_qt/src/MainWindow.cpp`。
- 优先级：P1

## P1-16 新增模块首版的产品化与负例验证

- 预期行为：新增 bundled modules 不仅能通过 CLI 调用，还要有结构化 UI、doctor 状态、负例测试和安全提示。
- 当前状态：2026-07-19 首版已完成，2026-07-20 已补 ArtifactStore status/policy/doctor 依赖能力，2026-07-26 已补一批本机安全负例 smoke，2026-07-28 又补 `service_guard`、`file_watch` 和 `script_runner` 生产边界。`dump` 可显式确认采集 minidump 到 ArtifactStore，dump artifact 标记高敏并裁剪 TTL；`service_guard` 可查询/确认 start-stop-ensure 本机 SCM 服务，现已默认拒绝受保护 SCM 服务、支持持久化 mutation allowlist、受保护服务额外 opt-in，并写 mutation/policy 审计事件；`file_watch` 可登记/检测文件变化并发本机事件，现已限制最多 64 条规则、只接受本机绝对盘符路径，并拒绝 UNC/device/ADS/Windows 系统目录/System Volume Information/Recycle Bin 路径，doctor 也会展示策略；`policy` 可保存/应用 guard policy 模板；`remote_agent` 暴露本机 heartbeat/guard metadata 且不开 listener；`update` 可验证本地 release manifest 的 `files` hash；`script_runner` 默认禁用且只允许登记服务数据目录下脚本，登记/运行都做 final-path 校验，登记时 pin SHA-256，run 前重验 hash，run 需 `confirm=1` 并写审计事件。Qt 可通过通用 module invoke 入口调用这些模块，Web 仍偏基础入口。
- 未完成原因：目前是首版功能面，Web/Qt 还没有为 7 个新模块做结构化专用页面；doctor 已有 ArtifactStore、service_guard、file_watch 和 script_runner 摘要，但还没有逐模块完整安全摘要；dump 权限失败/进程不存在/超限、script 目录 ACL/签名/remote RBAC 等生产化负例还没全部专项自动化。服务 mutation 无确认/受保护服务拒绝/allowlist set-clear、file-watch unreadable/系统路径拒绝、update hash tamper、script-runner 默认禁用/路径越界/无确认 run/hash tamper 已进入 smoke。
- 下一步方案：优先给 `service_guard`、`policy` 做结构化 UI 和高风险提示；给 `dump` 和 `script_runner` 保持高风险提示；`file_watch` 后续补 UI 风险提示和更细 allow/deny 配置；`update` 在代码签名前仍只保留 verify，不实现下载/安装。
- 测试方式：已覆盖 build、MSYS build、runtime smoke、release smoke 和 installer metadata；2026-07-28 smoke 增加 doctor `service_guard`/`file_watch`/`script_runner` 策略字段、`service-guard policy` 确认门槛和 set/clear、`EventLog` confirmed mutation protected-service 拒绝与 `service_guard.mutation-denied` 审计、file-watch status 策略字段和 Windows 系统路径拒绝、script-runner 登记返回 `sha256`、篡改后 run hash mismatch 和 `script_runner.run-denied` 审计；2026-07-26 smoke 增加 dump 无确认、service mutation 无确认、file-watch unreadable、update tamper、script-runner 禁用/路径/确认门槛。后续补每个模块的剩余负例脚本和 UI smoke。
- 相关入口：`modules/`、`docs/MODULE_ECOSYSTEM.md`、`docs/schemas/module.manifest.schema.json`。
- 优先级：P1

## P1-17 module install — 仓库模块下载安装

- **预期行为**：`pgs_bless module install <name>` 从 [PGS_Model](https://github.com/qwp-look/PGS_Model) 拉取 `registry.json`，解析模块条目，下载 DLL 到 `modules_staging/`，校验 SHA-256，写入 `modules.lock`，移入 `modules/<name>/`，最后执行 `module load`。
- **当前状态**：基础闭环已完成。PGS_Model 仓库结构（`registry.json`、schemas、文档）已建立；主仓库 CLI registry install 现在使用共享 `PGModulePolicy` helper 校验 registry/module/version 字段，限制 DLL/manifest 下载地址为 `https://raw.githubusercontent.com/...`，校验 SHA-256 和 `module.manifest.json`，并按 trust/risk 执行确认门槛；最终安装统一调用服务端 `module install <base64-dll-path> --confirm --load --source registry`，不再由 CLI 直接复制到 `modules/<name>/`。服务端 install 会强制 sidecar manifest、检查 name/ABI/risk、结构化更新 `modules.lock`、失败回滚，并在 install 成功后按请求 load。
- **信任模型**：
  - `official`：直接安装，无额外提示
  - `curated`：安装时提示 🟡，`risk: high/critical` 额外需要 `--confirm`
  - `community`：默认拒绝，需 `--trust-community` 显式 opt-in，并展示高风险警告要求用户输入 YES 确认
- **剩余收口**：
  1. 用真实 PGS_Model 非 bundled 模块跑一次 live registry 正例；当前 PGS_Model 主要还是 bundled 元数据。
  2. 增加 E2E 负例：hash mismatch、manifest/schema 缺字段、manifest 与 registry 不一致、community 未确认、high/critical 未确认、staging promote 失败、rollback 恢复。
  3. 继续把 OperationStore、ArtifactStore、Web/Qt result parsing 中的轻量字符串提取迁移到结构化 helper。
  4. 代码签名或 publisher policy 就绪后，为 curated/community 档增加更强信任策略。
- **不依赖代码签名**：install 可先实现 hash 校验版本；代码签名就绪后 community 档再放开默认限制
- **本轮验证**：已用显式 MSYS2/MinGW64 环境变量运行 `cmake -S . -B build_cmake -G "MinGW Makefiles" -DCMAKE_BUILD_TYPE=Release -DPGS_BUILD_TESTS=ON`、`cmake --build build_cmake --config Release`、`ctest --test-dir build_cmake --output-on-failure` 通过；`build_cmake\pgs_bless.exe module install sched` 已能从真实 PGS_Model `master` registry 拉取并识别 bundled 模块。
- **相关入口**：`tools/pgs_bless.cpp`、`src/modules/ModuleManager.cpp`、`docs/MODULE_ECOSYSTEM.md`、[PGS_Model/registry.json](https://github.com/qwp-look/PGS_Model/blob/master/registry.json)
- **优先级**：P1
