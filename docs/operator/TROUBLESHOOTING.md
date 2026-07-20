# 排障指南

## `pgs_bless ping` 失败

检查：

- PGS 服务是否启动：`pgs_service.exe status`。
- 端口是否一致：服务 `--port` 与客户端 `--port` 是否相同。
- token 是否正确。
- 是否有其它进程占用端口。

## token 不知道在哪里

首次启动生成的 token 位于：

```text
C:\ProgramData\ProcessGuard\state\pgs_initial_token.txt
```

如果状态目录被删除或权限异常，重新启动服务可能重新生成 token。生产环境建议记录安全存放位置。

## Qt/Web 能打开但列表为空

检查：

- token 是否正确。
- `pgs_bless.exe list --token <token>` 是否能返回。
- Qt/Web 配置的 `pgs_bless` 路径是否指向当前版本。
- PGS 服务端口是否一致。

## 模块加载失败

常见原因：

- DLL 不在模块目录内。
- `modules.allow` 缺少模块名或哈希不匹配。
- PPL 模块未 opt-in。
- 模块依赖 DLL 不在同目录或 PATH。

模块系统细节见 [模块系统](../developer/MODULE_SYSTEM.md)。

## Cluster 无法启动远程监听

确认使用的是当前参数名：

```bat
pgs_cluster_web.exe --listen-address 0.0.0.0 --listen-port 19090 --api-token token --tls-cert cert.pem --tls-key key.pem
```

非回环监听缺少 API token、TLS cert 或 TLS key 时会直接拒绝启动。

## `bless-start --winapp` 失败

优先检查：

- 当前会话是否是可交互用户会话，WindowsApps activation 需要用户 session。
- `--aumid` 是否正确，格式通常是 `PackageFamilyName!AppId`。
- 如果靠 `--path` 推导 AUMID，目标 exe 上层是否能读取 `AppxManifest.xml`。
- 服务/CLI 是否有权限查询激活后的进程路径。

该能力已接入 CLI 和重启路径，但不同 Store/UWP 应用行为差异较大，发布前仍建议在真实 WindowsApps 环境运行 `tools/verify_winapp.ps1`。

## release 打包时旧目录删不掉

通常是权限、杀毒软件、资源管理器预览或进程占用导致。处理方式：

- 关闭正在运行的 PGS/Qt/Web/Cluster。
- 确认没有打开 `release\` 内的 exe/dll。
- 必要时以管理员身份运行打包脚本。

## PPL 相关问题

PPL 默认关闭。只有在明确启用 `PGS_ENABLE_PPL=1` 或 `--enable-ppl` 后才会涉及 `Sirius.sys`。驱动加载、测试签名、真实 signer 生效需要管理员 VM 验证。
