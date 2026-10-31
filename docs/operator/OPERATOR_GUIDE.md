# 维护者操作指南

本文面向高级用户、维护者和部署人员。普通用户只需要 [快速开始](../user/QUICK_START.md) 和 [普通用户操作指南](../user/USER_GUIDE.md)。

## 服务安装与启动

便携目录或 release 目录中：

```bat
pgs_service.exe install
pgs_service.exe start
pgs_service.exe status
```

停止与卸载：

```bat
pgs_service.exe stop
pgs_service.exe uninstall
```

`install` 会把需要 SCM 后续启动继续生效的运行参数写入服务配置，例如端口、launcher provider opt-in、模块 permissive 模式。token 不写入 SCM 命令行。

## token 管理

推荐路径：

- 首次启动：读取 `C:\ProgramData\ProcessGuard\state\pgs_initial_token.txt`。
- 后续切换：用 Qt 管理端或 `token-set`。
- 控制台调试：用 `PGS_SERVICE_TOKEN` 设置服务进程 token。
- CLI/Qt/Web 子进程调用：用 `PGS_AUTH_TOKEN` 或 `--token`。

示例：

```bat
set PGS_SERVICE_TOKEN=your-token
pgs_service.exe run --port 12345
```

```bat
pgs_bless.exe token-set --old-token old-token --new-token new-token --token old-token
```

## 端口

PGS 默认管理端口是 `12345`。可以在运行或安装时指定：

```bat
pgs_service.exe run --port 23456
pgs_service.exe install --port 23456
```

客户端对应指定：

```bat
pgs_bless.exe --port 23456 ping --token your-token
```

## 模块与 launcher provider

普通模块默认不会在服务启动时全部扫描加载，推荐按需显式加载：

```bat
pgs_bless.exe module load --path "C:\Program Files\Process_Guarding_Service\modules\sched\pgs_sched_module.dll" --token your-token
```

provider 类模块（如 WindowsApps 的 `winapp` launcher）默认关闭。只有明确需要时才使用：

```bat
pgs_service.exe run --enable-launchers
```

安装成服务并长期启用时，把 opt-in 参数写进 SCM 配置：

```bat
pgs_service.exe install --enable-launchers
```

服务模式下建议传绝对 DLL 路径；相对路径只适合从 release 目录直接运行 `pgs_service.exe run` 的调试场景。`--allow-all-modules` 只用于开发和应急调试，生产环境不要开启。模块开发和 allowlist 细节见 [模块系统](../developer/MODULE_SYSTEM.md)。

## Web 远程管理

本地 Web 可以只绑定回环地址。远程模式必须显式开启并配置 TLS、用户文件和审计日志：

```bat
pgs_admin_web.exe ^
  --remote ^
  --bind 0.0.0.0 ^
  --http-port 18443 ^
  --pgs-token your-pgs-token ^
  --tls-cert cert.pem ^
  --tls-key key.pem ^
  --users-file users.txt ^
  --audit-log pgs_admin_audit.log
```

远程页面不把 PGS 管理 token 暴露给浏览器；后端持有 token 并代浏览器转发。

`users-file` 每行一个用户，推荐格式是：

```text
user;role;pbkdf2-sha256;iterations;saltHex;hashHex
```

`role` 可用 `viewer`、`operator`、`admin`。旧的 `user;role;saltHex;hashHex` 仍可读取，但只作为兼容格式。

## Cluster 面板

非回环监听必须配置 TLS 和 dashboard API token：

```bat
pgs_cluster_web.exe ^
  --listen-address 0.0.0.0 ^
  --listen-port 19090 ^
  --api-token dashboard-token ^
  --tls-cert cert.pem ^
  --tls-key key.pem
```

Cluster 用来集中查看多个节点。节点凭据、TLS 校验和远程网关策略由维护者负责。

节点文件由 Cluster 面板维护，格式是：

```text
name;https://node-host:18443;dpapi:<protected user:pass>
```

通过页面添加节点时会在 Windows 上用 DPAPI 保护凭据；手写旧式 `user:pass` 行仍能读取，但不建议长期保留。

## 管理员 VM 验收

完整验收使用：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tools\vm_acceptance.ps1 -EnablePpl -RunWinApp
```

这需要干净管理员 VM、安装器、真实服务权限，并可能需要 WindowsApps 环境。未完成或未验证项见 [未完成功能交接](../UNFINISHED_FEATURES_BACKLOG.md)。
