# 功能概览

PGS 的功能分成普通用户常用能力和高级维护能力。普通用户只需要理解“守护谁、异常时怎么恢复、在哪里看状态”。

## 常用能力

- 进程守护：目标进程异常退出后自动重启。
- 守护恢复：PGS 服务重启后恢复守护列表。
- Qt 管理端：图形化添加、查看、取消守护。
- Web 管理端：本机浏览器管理，或高级配置后远程管理。
- Cluster 面板：集中查看多个节点。
- Scheduler：按 cron、一次性时间、固定间隔触发安全允许的 PGS 管理动作。

## 高级能力

- 重启窗口、重启延迟、指数退避。
- 假活检测和 process/TCP/HTTP 健康探针，可选择记录事件、重启或隔离。
- 进程族清理和重启失败隔离态。
- 模块系统：health、profile、report、sched、notify、metrics、backup、eventlog、dump、service_guard、file_watch、policy、remote_agent、update、script_runner、ppl。
- 报告 artifact 输出、operation status 查询和 SHA-256 校验下载。
- 指标输出：summary、JSON 和 Prometheus 文本。
- 本地状态备份：快照服务数据目录，并可保存到 ArtifactStore。
- 本机 Event Log 查询：读取 Application 日志并按 source 过滤。
- 本机诊断模块：显式确认采集 minidump、查询/管理本机 Windows 服务、检测本地文件变化、保存策略模板。
- Release 校验：本地校验 `release-manifest.json` 里的文件 hash，不执行下载或安装。
- 受限脚本执行：默认禁用，只允许运行服务数据目录中已登记脚本，执行需要显式确认。
- Windows 本机通知：默认 Event Log，按需开启本机弹窗。
- PPL opt-in：默认关闭，需要明确启用。
- 构建、发布和验证脚本，供维护者确认 release 是否可用。

## 功能文档

- [守护功能](FEATURE_GUARD.md)
- [界面与远程查看](FEATURE_UI.md)
- [Scheduler 功能](FEATURE_SCHEDULER.md)

高级维护和开发细节分别见：

- [维护者操作指南](../operator/OPERATOR_GUIDE.md)
- [开发者文档](../developer/ARCHITECTURE.md)
