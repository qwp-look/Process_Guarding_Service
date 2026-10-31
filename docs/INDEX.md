# PGS 文档目录

本文档按读者分组。建议从与你身份最接近的一组开始读，避免被不需要的实现细节打断。

## 普通用户

- [快速开始](user/QUICK_START.md)：安装包/便携版最短路径。
- [普通用户操作指南](user/USER_GUIDE.md)：安装、token、Qt 管理端、基础守护。
- [功能概览](user/FEATURES.md)：PGS 能做什么，哪些功能适合普通用户。
- [守护功能](user/FEATURE_GUARD.md)：进程守护、重启策略、WindowsApps/AUMID 用法。
- [界面与远程查看](user/FEATURE_UI.md)：Qt、Web、Cluster 的定位。
- [Scheduler 功能](user/FEATURE_SCHEDULER.md)：普通用户如何理解和使用定时任务。
- [常见问题](user/FAQ.md)：token、权限、服务、launcher provider、WindowsApps 常见疑问。

## 高级用户 / 维护者

- [维护者操作指南](operator/OPERATOR_GUIDE.md)：服务、token、端口、模块、远程管理。
- [发布与打包指南](operator/RELEASE_GUIDE.md)：release tree、installer、zip、release smoke。
- [排障指南](operator/TROUBLESHOOTING.md)：服务起不来、连接失败、模块失败、Qt/Web 问题。

## 开发者

- [技术架构](developer/ARCHITECTURE.md)：服务核心、协议、Job/IOCP、UI、模块边界。
- [构建指南](developer/BUILD.md)：MSYS2、Qt、构建目录、打包脚本。
- [协议与契约](developer/PROTOCOL.md)：CLI/API/module action 的线协议和兼容性。
- [模块系统](developer/MODULE_SYSTEM.md)：模块 ABI、allowlist、bundled modules、风险能力和常用 CLI。
- [模块生态基础](MODULE_ECOSYSTEM.md)：module manifest、lockfile、manager extension、JSON-RPC 风格调用。
- [测试与验证](developer/TESTING.md)：verify、smoke、contract、pressure、VM acceptance。

## 交接文档

这三份是后续专项交接材料，刻意写得详细，不作为普通用户指南阅读：

- [安全收口交接](SECURITY_HARDENING_BACKLOG.md)：安全版 release 前需要关闭的边界、供应链和审计问题。
- [未完成/未验证功能交接](UNFINISHED_FEATURES_BACKLOG.md)：仍未实现、未验证或需要继续产品化的功能清单。
- [剩余升级计划](REMAINING_UPGRADE_PLAN.md)：按工作流组织的后续实现顺序、验收标准和模块路线图。

## 旧入口说明

仓库根层的旧文档名仍保留为兼容入口，例如 `SERVICE_MODE_GUIDE.md`、`MODULE_SYSTEM.md`、`TECHNICAL_ARCHITECTURE.md`。它们现在只负责指向新的分组文档，不再维护重复长内容。
