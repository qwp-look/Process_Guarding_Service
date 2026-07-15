# 测试与验证

## 日常验证

```bat
tools\verify.bat
```

覆盖：

- 文件存在性检查。
- core / CLI / examples / bundled modules 构建。
- core、ModuleManager、Scheduler unit tests。
- console smoke。
- Qt 管理端构建。
- Web 管理端和 Cluster 面板构建。

## 单项测试

```bash
./tools/run_unit_tests.sh
./tools/test_core_units.sh
./tools/test_module_manager.sh
./tools/test_sched_cron.sh
```

## 协议契约

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tools\protocol_contract.ps1 -Release build_verify
```

当前固定 `ping`、`version`、`stats`、`list --json` 的基础契约。更多命令契约可以继续扩展。

## Release smoke

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tools\release_smoke.ps1 -Release release -Fresh
```

验证便携 release 的核心 happy path，包含模块加载、PPL gate 和 guard 生命周期。

## 压力与长稳

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tools\pressure_pgs.ps1 -Release build_verify -Iterations 50
powershell -NoProfile -ExecutionPolicy Bypass -File tools\long_stability.ps1 -Release build_verify -Minutes 30
```

本轮已跑过短压测和 1 分钟长稳 smoke。正式 release 基线仍需在固定环境中沉淀。

## VM acceptance

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tools\vm_acceptance.ps1 -EnablePpl -RunWinApp
```

需要管理员 VM、安装器、真实服务权限和可选 WindowsApps 环境。该项没有纳入普通 verify。
