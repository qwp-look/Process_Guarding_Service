# 集群监控面板（pgs_cluster_web）

Stage D 交付物：一个独立的 Web 仪表盘进程，聚合多个 PGS 节点的健康与守护状态。
它定时（5s）并发轮询各节点的 `/api/cluster/health` 与 `/api/guards`（由 Stage C 远程网关提供），
缓存结果，浏览器前端 1s 刷新读缓存，不打爆节点。

## 1. 运行

```bash
pgs_cluster_web.exe --listen-port 19090 --nodes-file pgs_cluster_nodes.txt
```
浏览器访问 `http://<本机>:19090/`。仪表盘支持在线增删节点（name / https://host:12443 / user:pass）。

## 2. 节点注册表

文件格式，一行一个节点：`name;baseHttpsUrl;user:pass`。`#` 开头为注释。
凭证即 Stage C 远程网关的 RBAC 用户（Basic auth）。注册表由仪表盘进程持久化到本地文件。

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

## 5. 安全注意

- 仪表盘对节点使用自签证书宽松校验（`VerifyNone`），因为假定运维信任自己的节点。
- 仪表盘本身监听 `0.0.0.0`，部署时应限制访问（防火墙 / 仅内网）或前置反向代理加鉴权。
- 节点凭证以明文存在节点注册表文件中，文件权限应仅运维可读。

## 6. 构建

`qt/pgs_cluster_web/CMakeLists.txt` 已就绪，需 Qt6 Core/Network/HttpServer。当前 `tools/package_release.bat`
未自动包含集群端，如需打包可仿照 Qt 端的 windeployqt6 流程追加。
