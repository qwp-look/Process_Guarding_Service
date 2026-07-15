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

- `installer\Output\pgs_release_0.1.0-beta.1.zip`
- `installer\Output\pgs_setup_0.1.0-beta.1.exe`
- `installer\Output\SHA256SUMS.txt`

`installer\Output\` 也是本地生成目录，不能提交到仓库。

release smoke 会验证：

- PGS 便携运行可启动。
- `ping` 可用。
- sched/health/profile/report 模块可加载和调用。
- PPL 默认 gate 生效。
- 基础 guard 生命周期可用。

## 运行态文件不应进包

发布包不应包含模块运行态数据库，例如：

- `pgs_profiles.db`
- `pgs_sched.db`

`release_smoke.ps1` 和 `build_installer.bat` 已做清理/检查。模块状态迁移到 ProgramData 是后续项，见未完成功能交接文档。

## 当前还没做的发布安全项

以下内容未在功能完成版中实现：

- 代码签名。
- SBOM。
- release allowlist 自动写入模块哈希。

这些属于安全专项，见 [安全收口交接](../SECURITY_HARDENING_BACKLOG.md)。
