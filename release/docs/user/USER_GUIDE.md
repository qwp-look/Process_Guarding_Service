# 普通用户操作指南

本指南面向“要把程序交给 PGS 守护”的用户。服务配置、远程管理、发布打包等高级内容见 [维护者操作指南](../operator/OPERATOR_GUIDE.md)。

## 安装后第一次使用

1. 启动 **PGS 管理端（Qt）**。
2. 读取首次 token：`C:\ProgramData\ProcessGuard\state\pgs_initial_token.txt`。
3. 在 Qt 管理端填入 token。
4. 点击刷新或 ping，确认连接成功。
5. 添加守护对象。

## 常用命令

Qt 管理端可以完成大多数操作。需要命令行时，在 PGS 安装目录或便携目录运行：

```bat
pgs_bless.exe ping --token your-token
pgs_bless.exe list --token your-token
pgs_bless.exe bless-start --path "C:\path\to\app.exe" --max-restarts 3 --hash auto --token your-token
pgs_bless.exe unbless --pid 1234 --token your-token
```

`--token` 可以放在命令前后。为了减少命令行泄露风险，也可以用环境变量：

```bat
set PGS_AUTH_TOKEN=your-token
pgs_bless.exe ping
pgs_bless.exe list
```

## 修改 token

在 Qt 管理端可以直接更新 token。命令行方式：

```bat
pgs_bless.exe token-set --token old-token --new-token new-token
```

PGS 会先验证旧 token，验证通过后才切换。服务重启后仍会记住新的 token。

## 修改守护策略

普通用户通常只需要最大重启次数：

```bat
pgs_bless.exe policy --pid 1234 --max-restarts 5 --token your-token
```

更多高级策略见 [守护功能](FEATURE_GUARD.md)。

## 使用 Web 页面

本机 Web 管理端适合浏览器操作。远程 Web 管理需要 TLS、用户文件和审计日志，属于维护者配置范围。

普通用户优先使用 Qt 管理端；如果维护者已经配置好 Web 地址，按维护者提供的地址和账号访问即可。

## 卸载

使用安装包安装的版本，建议从 Windows 设置或卸载程序卸载。卸载时安装目录、服务和防火墙规则会被清理；`C:\ProgramData\ProcessGuard` 默认保留，便于以后恢复状态。
