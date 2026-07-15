# 快速开始

本页面向普通用户，只保留最短路径。想了解原理或维护细节，请从 [文档目录](../INDEX.md) 进入对应章节。

## 使用安装包

1. 从 GitHub Releases 下载最新 beta，管理员身份运行 `pgs_setup_0.1.0-beta.1.exe`。
2. 按向导安装，推荐勾选“安装并启动 PGS 服务”。
3. 安装完成后启动 **PGS 管理端（Qt）**。
4. 如果是首次安装，打开 `C:\ProgramData\ProcessGuard\state\pgs_initial_token.txt`，复制里面的 token。
5. 在 Qt 管理端填写 token，点击连接或刷新。
6. 添加要守护的程序。

首次 token 只会写入这个受限文件；后续状态文件不会保存明文 token。

## 使用便携包

解压 `pgs_release_0.1.0-beta.1.zip` 后，在管理员终端进入解压目录：

```bat
pgs_service.exe install
pgs_service.exe start
pgs_admin_qt.exe
```

之后同样从 `C:\ProgramData\ProcessGuard\state\pgs_initial_token.txt` 读取 token。

## 添加一个守护程序

普通用户推荐使用 Qt 管理端：

1. 填写 token。
2. 在 Bless/Start 区域选择程序路径。
3. 设置最大重启次数。
4. 点击启动并守护，或对已有 PID 执行守护。
5. 在列表中查看状态。

命令行用户可以看 [普通用户操作指南](USER_GUIDE.md)。

## 下一步

- 想知道每个功能做什么：读 [功能概览](FEATURES.md)。
- 想远程查看或管理：读 [界面与远程查看](FEATURE_UI.md)。
- 遇到问题：读 [常见问题](FAQ.md) 和 [排障指南](../operator/TROUBLESHOOTING.md)。
