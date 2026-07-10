# 集群监控面板（pgs_cluster_web）

Stage D 交付物：一个独立的 Web 仪表盘进程，聚合多个 PGS 节点的健康与守护状态。
它定时（5s）并发轮询各节点的 `/api/cluster/health` 与 `/api/guards`（由 Stage C 远程网关提供），
缓存结果，浏览器前端 1s 刷新读缓存，不打爆节点。

## 1. 运行

本地默认模式只监听回环地址，适合在运维机上直接打开：

```bash
pgs_cluster_web.exe --listen-port 19090 --nodes-file pgs_cluster_nodes.txt
```
浏览器访问 `http://127.0.0.1:19090/`。仪表盘支持在线增删节点（name / https://host:12443 / user:pass）。
即使是本地默认模式，`/api/cluster/*` 也会使用进程内随机 API token；内置页面会自动填入这个
token，跨站页面无法读取它或用 simple request 写节点注册表。

如果要绑定非回环地址，必须同时提供 API token 与 HTTPS 证书/私钥；否则拒绝启动：

```bat
pgs_cluster_web.exe ^
  --listen-address 0.0.0.0 ^
  --listen-port 19090 ^
  --nodes-file pgs_cluster_nodes.txt ^
  --api-token <dashboard-token> ^
  --tls-cert cert.pem ^
  --tls-key key.pem
```

远程浏览器访问 API 时可用 `X-API-Token: <dashboard-token>` 或
`Authorization: Bearer <dashboard-token>`。内置页面会把输入的 token 存在浏览器
`localStorage`，仅用于访问 cluster dashboard 自身 API，不会发给被管理节点。

节点 HTTPS 证书默认严格校验。若 PGS 节点使用私有 CA，可给聚合器传入 CA：

```bat
pgs_cluster_web.exe --node-ca-cert pgs-node-ca.pem
```

实验环境才可使用 `--node-insecure-tls` 关闭节点证书校验；这会让节点 Basic 凭证暴露给主动 MITM，
生产环境不要开启。

## 2. 节点注册表

文件格式，一行一个节点：`name;baseHttpsUrl;user:pass`。`#` 开头为注释。
凭证即 Stage C 远程网关的 RBAC 用户（Basic auth）。注册表由仪表盘进程持久化到本地文件。

URL 规则：

- 必须是 `https://host[:port]`。
- 拒绝 `https://user:pass@host` 这类嵌入式凭据，避免 list/summary/API 或前端显示时泄漏。
- 拒绝 query/fragment；节点认证只放在第三列 `user:pass`。
- `name`、URL、`credentials` 不能包含分号、换行或控制字符，避免破坏注册表格式或注入额外节点行。

示例 `pgs_cluster_nodes.txt`：
```
# name;baseHttpsUrl;user:pass
node1;https://10.0.0.5:12443;admin:s3cret
node2;https://10.0.0.6:12443;operator:pass2
```

## 3. 展示与告警

- 顶部汇总：节点数 / 离线数 / 守护总数 / 死亡守护数。
- 节点卡片网格：每节点名称、UP/DOWN 标签、guard 数、URL、离线时的错误信息。
- 告警：节点离线（卡片红框）、guard 死亡（汇总红色计数）。
- 下钻：点节点卡片可由运维自行打开该节点单机 Web 页（复用 Stage C 网关地址）。

## 4. API

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/cluster/summary` | 全集群汇总 + 各节点状态（JSON） |
| GET | `/api/cluster/nodes` | 节点列表 |
| POST | `/api/cluster/nodes` | 增加节点 `{name,url,credentials}` |
| DELETE | `/api/cluster/nodes` | 删除节点 `{name}` |

上述 `/api/cluster/*` 全部需要 token。默认 loopback 且未设置 `--api-token` 时，进程会生成本次运行
随机 token 并嵌入本地页面；非回环监听必须使用显式 `--api-token`，自动 token 不允许暴露到网络。
POST/DELETE 还要求 `Content-Type: application/json`。

## 5. 安全注意

- 仪表盘对节点默认启用 TLS peer verify；私有 CA 用 `--node-ca-cert` 加入信任。
- `--node-insecure-tls` 会退回旧的 `VerifyNone` 行为，仅用于隔离实验环境。
- 仪表盘默认监听 `127.0.0.1`。非回环监听强制 HTTPS + API token，避免 dashboard token 和节点
  `user:pass` 在网络上明文传输。
- 节点凭证不会从 list/summary API 回显，但仍以明文存在节点注册表文件中。文件权限应仅运维可读；
  后续如需更强本机保护，可用 Windows DPAPI 加密第三列凭据。
- 轮询缓存按节点 generation 与请求 serial 校验，删除/重加同名节点或旧请求晚返回时不会污染新节点状态。

## 6. 构建

`qt/pgs_cluster_web/CMakeLists.txt` 已就绪，需 Qt 6.8+ Core/Network/HttpServer。`tools/build_qt_web.sh`
会单独构建 `pgs_admin_web` 与 `pgs_cluster_web`；`tools/package_release.bat` 会把集群端、Qt runtime、
OpenSSL TLS plugin 和必要的 MSYS2 MinGW DLL 一起放入 `release/`。
