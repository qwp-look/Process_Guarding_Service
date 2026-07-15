# Scheduler 功能

Scheduler 是 bundled 模块之一，用来按时间触发 PGS 管理动作。

## 它能做什么

- cron 表达式：按分钟、小时、日期规则触发。
- once：在指定时间触发一次。
- interval：每隔固定秒数触发，可限制次数。

Scheduler 适合定时启用/禁用守护、按时间切换策略、周期性查看状态等安全允许的 PGS 管理动作。

## 普通用户建议

如果只是希望程序崩溃后自动恢复，不需要 Scheduler。

如果你需要“每天某个时间做一件 PGS 管理动作”，再启用 Scheduler。

## 安全限制

Scheduler 不允许执行所有命令。危险或不适合定时触发的动作会被拒绝，例如 token 修改、服务安装/卸载、模块 load/unload、PPL 操作等。

开发者协议细节见 [协议与契约](../developer/PROTOCOL.md)。
