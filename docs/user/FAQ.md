# 常见问题

## 我应该用安装包还是便携包？

普通用户优先用安装包。它会处理安装目录、服务、快捷方式和卸载流程。

便携包适合调试、临时部署或高级维护者。

## token 在哪里？

首次安装服务且没有旧状态时，PGS 会生成 token，并写到：

```text
C:\ProgramData\ProcessGuard\state\pgs_initial_token.txt
```

这个文件所在目录会尝试限制为 SYSTEM 和 Administrators 可读。后续 PGS 不会保存明文 token。

## 为什么必须管理员权限？

PGS 需要作为 Windows 服务运行，并跨会话重启用户程序。管理员权限和默认 LocalSystem 身份能让它更稳定地完成这些动作。

## PPL 要不要开？

默认不要开。PPL 模块会涉及内核驱动，只有明确需要并理解风险时才启用。普通守护进程不需要 PPL。

## WindowsApps 为什么不能直接启动并守护？

Store/UWP 应用的启动方式和普通 exe 不一样。当前版本支持先启动后按 PID + AUMID 注册，自动 AUMID 推导和直接 `bless-start --winapp` 还没完成。

## Web 可以直接开到公网吗？

不建议。远程 Web 必须配置 TLS、用户文件、审计日志，并由维护者负责网络边界。
