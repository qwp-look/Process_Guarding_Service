# 远程控制网关（pgs_admin_web --remote）

Stage C 交付物：在 `pgs_admin_web` 基础上新增远程模式，加 TLS + RBAC + 审计，
默认关闭，显式配置才监听非回环。这是 Stage D 集群面板的前置。

## 1. 启用远程模式

```bash
pgs_admin_web.exe --remote --tls-cert cert.pem --tls-key key.pem --users-file users.txt --audit-log pgs_audit.log
```

远程模式下：
- 默认绑定 `0.0.0.0`（若未显式 `--bind`）。
- 强制 TLS（QSslServer + OpenSSL 后端），无证书则拒绝启动（fail-closed）。
- 强制 RBAC：每个 `/api/*` 请求必须带 `Authorization: Basic <base64(user:pass)>`，
  并按路由所需角色校验。无用户文件或用户表为空时拒绝启动。
- 本地回环模式（不带 `--remote`）行为不变，仍用进程内 API token + loopback。

## 2. RBAC 角色

| 角色 | 可访问 |
|------|--------|
| viewer | 只读：health/ping/guards/guard/service-status/cluster-health |
| operator | + 守护变更：bless/bless-start/policy/unbless/intentional |
| admin | + token 轮换、服务生命周期：token/service-install/start/stop/uninstall |

## 3. 用户文件格式

`user;role;saltHex;hashHex`，role ∈ {viewer, operator, admin}。salt+hash 用 HMAC-SHA256，
不存明文密码。生成示例（PowerShell + openssl）：

```powershell
$salt = -join ((1..16) | ForEach-Object { '{0:x2}' -f (Get-Random -Max 256) })
$pw = 's3cret'
$hash = openssl dgst -sha256 -mac HMAC -macopt hexkey:$salt -binary $pw | openssl enc -base64
``

实际请用配套脚本生成；文件权限应仅 SYSTEM+Administrators（放 `ProgramData\ProcessGuard\` 下）。

## 4. 审计

远程模式下每次变更类操作（bless/unbless/policy/intentional/token/service-*）写一行到
`--audit-log` 指定文件：`时间 user=xxx action=xxx from=<ip>`。被拒请求也记 `DENY`。

## 5. 集群前置端点

`GET /api/cluster/health` 返回本节点 `ok/node/listen_url/remote/guard_count/pgs_reachable`，
供 `pgs_cluster_web` 轮询。该端点要求 viewer 及以上角色。

## 6. 证书

远程模式需要 PEM 格式 cert + key（建议 RSA 2048+）。自签证书可用：
```
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes -subj "/CN=pgs-gateway"
```
客户端（`pgs_cluster_web`）默认对自签证书宽松校验；如需严格校验请部署正式 CA 签发的证书。
