# 发布与打包指南

本文面向维护者。开发构建细节见 [构建指南](../developer/BUILD.md)。

## 一键打包 release 目录

```bat
tools\package_release.bat
```

脚本会：

- 使用 `build_release\` 作为隔离构建目录。
- 构建 core、CLI、examples、bundled modules。
- 构建 Qt 管理端、Web 管理端、Cluster 面板。
- 重新生成 `release\`。
- 复制 docs、modules、examples、Qt/MinGW 运行库。
- 验证必须产物存在。

不要直接发布仓库中旧的 `release\`。`release\` 是本地生成目录，已被 Git 忽略；发布包应上传到 GitHub Releases。

## 生成 zip 和安装器

```bat
tools\build_installer.bat
```

脚本会先调用 `tools\package_release.bat`，再运行 release smoke，最后生成：

- `installer\Output\pgs_release_<version>.zip`
- `installer\Output\pgs_setup_<version>.exe`
- `installer\Output\SHA256SUMS.txt`
- `installer\Output\release-manifest.json`
- `installer\Output\sbom.spdx.json`

`installer\Output\` 也是本地生成目录，不能提交到仓库。文件名和发布版本现在都从仓库根层 `VERSION` 单源读取。

`SHA256SUMS.txt` 覆盖 installer 和 portable zip；`release-manifest.json` 记录 release tree 文件、hash、source commit、toolchain 版本和 `modules.lock`；`sbom.spdx.json` 是由当前 release tree 生成的首版 SPDX 元数据。publish workflow 会把这三个文件和 installer/zip 一起上传到 GitHub Release，并对这些产物请求 GitHub artifact attestation。

release smoke 会验证：

- PGS 便携运行可启动。
- `ping` 可用。
- sched/health/profile/report/notify/metrics/backup/eventlog/dump/service_guard/file_watch/policy/remote_agent/update/script_runner 模块可加载和基础调用。
- PPL 默认 gate 生效。
- 基础 guard 生命周期可用。

## 运行态文件不应进包

发布包不应包含模块运行态数据库，例如：

- `pgs_profiles.db`
- `pgs_sched.db`

`release_smoke.ps1` 和 `build_installer.bat` 会继续检查这些运行态 DB 不泄漏进发布包；模块运行态现在已迁移到服务数据目录，仍需在真实安装态做一次只读目录验证。

## 当前还没做的发布安全项

以下内容未在功能完成版中实现：

- 代码签名证书和签名验证。
- live GitHub Release 上的 metadata/provenance 资产确认。
- release allowlist fail-closed 和签名策略强制。
- 新增高风险模块的生产化安全策略：dump artifact 留存/审计、script_runner 签名/ACL/远程 RBAC、service_guard mutation 审计、update 自动安装前的签名和回滚。

这些属于安全专项，见 [安全收口交接](../SECURITY_HARDENING_BACKLOG.md)。
