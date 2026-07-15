# PGS 未完成/未验证功能交接文档

本文档记录功能完成版之后仍未完成、只部分完成、需要特定环境验证，或本轮主动延期的事项。后续新对话可直接按本文件继续推进，不需要翻聊天记录。

优先级定义：P0 = 影响“功能完成版”可信度，应优先补；P1 = 下一轮功能增强；P2 = 中长期演进。

## P0-01 WindowsApps 自动 AUMID 推导

- 预期行为：用户给出 `C:\Program Files\WindowsApps\...\App.exe` 时，CLI/服务可解析 `AppxManifest.xml`，推导 PackageFamilyName 和 AUMID。
- 当前状态：只支持显式 `--winapp --aumid <id>`；服务端和 CLI 已强制 WinApp 需要 AUMID。
- 未完成原因：需要 manifest 解析、publisher hash 校验、路径与 package 归属校验，并需要真实 WindowsApps 环境验证。
- 下一步方案：在 `PGUtil.h` 或新 util 中实现 manifest parser；为 fixture manifest 加单元测试；CLI 在 `--winapp` 且未传 `--aumid` 时尝试推导，失败给出显式错误。
- 测试方式：manifest fixture unit；`tools/verify_winapp.ps1` 真实环境；错误 manifest/错误路径负例。
- 相关入口：`tools/pgs_bless.cpp`、`include/Process_Guard/PGUtil.h`、`src/service/PGS.cpp`
- 优先级：P0

## P0-02 `bless-start --winapp` AUMID 激活启动

- 预期行为：用户可直接 `bless-start --winapp --aumid ...` 激活 Store/UWP app 并注册返回的 PID。
- 当前状态：CLI 明确拒绝 `bless-start --winapp`，提示先启动 app 再 `bless --pid --winapp --aumid`。重启路径 `restartAppGuard()` 已可用。
- 未完成原因：现有 bless-start 是 `CreateProcessW(CREATE_SUSPENDED)`，不适用于 WindowsApps；需要 CLI 或服务端实现 COM `IApplicationActivationManager` 启动并拿 PID。
- 下一步方案：抽取 `restartAppGuard()` 的 AUMID activation 公共实现，供 CLI 或服务端 start-and-register 使用；注册前确认实际 PID/path/AUMID。
- 测试方式：真实 WindowsApps 环境；无交互 session、错误 AUMID、fallback ShellExecute 负例。
- 相关入口：`tools/pgs_bless.cpp`、`src/service/PGS.cpp`
- 优先级：P0

## P0-03 完整管理员 VM E2E 尚未在本轮运行

- 预期行为：在干净管理员 VM 中跑完 portable、SCM install/start/stop、installer、Web、Cluster、PPL opt-in、WindowsApps helper。
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
- 当前状态：Web 已有高级策略、模块 list/call、Scheduler add/list/enable/disable/remove 基础入口；Cluster 已有 add/remove 和高级字段展示。
- 未完成原因：没有做完整前端状态建模、表单校验、错误分组、节点编辑/测试连接 UX。
- 下一步方案：Web 将 module/scheduler 响应结构化渲染；Cluster 增加 edit/test endpoint；为 remote gateway 添加联调用例。
- 测试方式：Playwright 或 HTTP API smoke；Cluster 添加一个真实 remote Web node 并轮询成功。
- 相关入口：`qt/pgs_admin_web/src/WebServer.cpp`、`qt/pgs_cluster_web/src/ClusterServer.cpp`
- 优先级：P1

## P1-06 Qt Scheduler 专用页面

- 预期行为：Qt 像 Web 一样提供 Scheduler 的类型、表达式、action、count、enable/disable/remove 控件。
- 当前状态：Qt 模块页可通过 generic `module call` 调 sched；没有专用表单。
- 未完成原因：本轮优先补主 Bless 策略和 Web 基础入口，避免扩大 Qt UI 改动。
- 下一步方案：在 `ModulePage` 对 `sched` folder 增加专用控件，或新增 Scheduler tab，底层复用 `pgs_bless sched ...`。
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

- 预期行为：release tree、zip、installer 有完整 manifest/checksum，发布前 release smoke 和 artifact 验证强制执行。
- 当前状态：`package_release.bat` 已增加必需产物检查；`build_installer.bat` 默认跑 `release_smoke.ps1`；本轮已生成 `installer\Output\pgs_release_3.1.0.zip` 和 `pgs_setup_3.1.0.exe`，但签名、checksum、SBOM 未实现。
- 未完成原因：签名证书和发布流程未配置。
- 下一步方案：生成 `SHA256SUMS.txt`；接入代码签名；发布 workflow 上传校验文件。
- 测试方式：篡改文件后 checksum 失败；签名验证通过。
- 相关入口：`tools/package_release.bat`、`tools/build_installer.bat`、`.github/workflows/publish-release.yml`
- 优先级：P1

## P1-09 模块运行态状态迁移到 ProgramData

- 预期行为：模块 DLL/manifest 所在目录保持发布态、可只读；profile/scheduler 等运行态数据库写入 ProgramData 或服务状态目录。
- 当前状态：`profile` 模块仍会把 `pgs_profiles.db` 写在模块目录；`release_smoke.ps1` 和 `build_installer.bat` 已防止该 DB 泄漏进 zip/installer，但架构上尚未迁移。
- 未完成原因：当前 ABI v2 的 `PGS_Services` 只提供 callback/clock，没有提供模块状态目录；迁移需要 ABI 扩展或服务端注入配置。
- 下一步方案：扩展 `PGS_Services` 增加 `data_dir` 或 `get_data_dir()`；profile/sched 模块按模块名写入 `%ProgramData%\ProcessGuard\modules\<name>\`；保留旧 DB 迁移逻辑。
- 测试方式：release smoke 后 `release\modules` 不出现 `pgs_profiles.db`/`pgs_sched.db`；ProgramData 中出现状态文件；低权限安装目录下 profile/sched 可正常工作。
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
