# 远程控制网关（pgs_admin_web --remote）

Stage C 交付物：在 `pgs_admin_web` 基础上新增远程模式，加 TLS + RBAC + 审计，
默认关闭，显式配置才监听非回环。这是 Stage D 集群面板的前置。

远程模式是 **fail-closed**：证书、私钥、用户文件、审计日志任一缺失或不可用，服务都拒绝启动。

## 1. 启用远程模式

```bash
pgs_admin_web.exe --remote --tls-cert cert.pem --tls-key key.pem --users-file users.txt --audit-log pgs_audit.log
```

远程模式下：
- 默认绑定 `0.0.0.0`（若未显式 `--bind`）。
- 强制 TLS（`QSslServer` + OpenSSL 后端），支持 RSA / EC / DSA PEM 私钥自动探测。
- 强制 RBAC：首页 `/` 和每个 `/api/*` 请求都必须带 `Authorization: Basic <base64(user:pass)>`，
  并按路由所需角色校验。无用户文件或用户表为空时拒绝启动。
- 远程页面不会嵌入 PGS 管理 token。后端持有 `--pgs-token` 并代浏览器转发到 PGS。
- 变更类 API 额外要求同源 CSRF 证明：`Content-Type: application/json`、`X-PGS-CSRF`
  以及同源 `Origin` / `Referer` / `Sec-Fetch-Site` 浏览器头。这样即使浏览器缓存了 Basic
  凭据，跨站表单也不能直接触发 `/api/service/stop` 等管理动作。
- 本地回环模式（不带 `--remote`）行为不变，仍用进程内 API token + loopback，并校验
  `Host` / `Origin` 以防 DNS rebinding / CSRF。

## 2. RBAC 角色

| 角色 | 可访问 |
|------|--------|
| viewer | 只读：health/ping/guards/guard/service-status/cluster-health |
| operator | + 守护变更：bless/bless-start/policy/unbless/intentional |
| admin | + token 轮换、服务生命周期：token/service-install/start/stop/uninstall |

## 3. 用户文件格式

推荐格式：`user;role;pbkdf2-sha256;iterations;saltHex;hashHex`，role ∈ {viewer, operator, admin}。`hashHex` 是 PBKDF2-SHA256 派生出的 32 字节密钥十六进制字符串，不存明文密码。为兼容旧部署，仍可读取旧格式 `user;role;saltHex;hashHex`（HMAC-SHA256）。

生成示例（PowerShell + .NET PBKDF2-SHA256）：

```powershell
$saltBytes = New-Object byte[] 16
[Security.Cryptography.RandomNumberGenerator]::Fill($saltBytes)
$iterations = 210000
$hashBytes = [Security.Cryptography.Rfc2898DeriveBytes]::Pbkdf2(
  [Text.Encoding]::UTF8.GetBytes('s3cret'), $saltBytes, $iterations,
  [Security.Cryptography.HashAlgorithmName]::SHA256, 32)
$saltHex = -join ($saltBytes | ForEach-Object { $_.ToString('x2') })
$hashHex = -join ($hashBytes | ForEach-Object { $_.ToString('x2') })
"admin;admin;pbkdf2-sha256;$iterations;$saltHex;$hashHex"
```

文件权限应仅 SYSTEM+Administrators（放 `ProgramData\ProcessGuard\` 下）。远程模式已做在线失败审计和退避；若用户文件可能离线泄露，PBKDF2 格式比旧 HMAC 格式更适合作为默认。后续还可继续迁移到 Argon2id/bcrypt。

## 4. 审计

远程模式下成功 API 请求会写入 `--audit-log` 指定文件：
`时间 user=xxx action="METHOD /path" from=<ip>`。

认证失败、角色不足、登录退避也会记审计记录（`login-failed:*` / `login-throttled`）。
CSRF 失败会直接拒绝请求；如需把所有拒绝路径都落审计，可在 `authorizeApi` 中再扩展拒绝日志。

## 5. 集群前置端点

`GET /api/cluster/health` 返回本节点 `ok/listen_url/remote/guard_count/pgs_ok`，
供 `pgs_cluster_web` 轮询。该端点要求 viewer 及以上角色。

## 6. 证书

远程模式需要 PEM 格式 cert + key。RSA 与 ECDSA 均可；自签 RSA 证书可用：
```
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes -subj "/CN=pgs-gateway"
```
客户端（`pgs_cluster_web`）默认严格校验节点证书。自签/私有 CA 节点请把 CA 传给
`pgs_cluster_web --node-ca-cert <ca.pem>`；只有隔离实验环境才使用 `--node-insecure-tls`。
