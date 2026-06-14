# PGS 网页控制端规划与现状

## 1. 目标澄清

这里说的“网页控制端”，不是“在 Qt 里加一个查询网页的功能页”，而是：

- 提供一个真正运行在浏览器里的管理界面
- 可以查看守护列表、调整策略、更新 token、启动/停止服务
- 让远程或本机运维都能通过 HTTP/HTML 访问

当前仓库里的 Qt `HTTP Probe` 只能算一个临时调试小工具，不应该继续往“控制端网站”方向硬扩。

当前代码状态补充：

- Qt 里的临时 HTTP 页已经移除
- 第一阶段 `pgs_admin_web` 已经落地为独立 Web 管理进程
- 当前实现优先复用现有 `pgs_bless.exe` / `pgs_service.exe`
- 当前已落地的接口覆盖：`ping/list/get/bless/bless-start/policy/unbless/intentional/token/service-*`

## 2. 推荐架构

推荐拆成三层：

1. `PGS`
   继续做守护核心，只负责本地守护协议、监控和重启
2. `pgs_admin_web`
   新增一个 Web 管理端进程，负责 HTTP API、静态页面、鉴权、会话
3. 浏览器前端
   负责表格、表单、日志展示、轮询或事件推送

这样做的好处是：

- 不把 HTTP/Web 复杂度塞进 `PGS` 核心
- 不让浏览器直接碰内部文本协议
- 可以逐步演进前端，而不破坏现有 CLI/Qt 管理端

## 3. 技术选型建议

优先复用现有环境里已经成熟可用的东西，不重复造轮子。

### 3.1 后端 HTTP 层

首选建议：`Qt HttpServer` + `Qt Network`

原因：

- 你的环境里已经有 Qt6 相关模块
- 现有仓库已经在用 Qt 管理端，依赖一致
- 路由、JSON、HTTP 返回这些能力够用
- 比手搓 Winsock/HTTP 解析稳定很多

备选：

- `Boost.Beast`
- `Crow`
- `cpp-httplib`

如果后面希望网页控制端完全脱离 Qt，再考虑这些备选更合适。

### 3.2 与 PGS 的通信层

推荐不要让网页端直接重写一套协议字符串拼接。

更好的做法是先抽一个小的本地客户端层，例如：

- `src/client/PGSClient.h`
- `src/client/PGSClient.cpp`

由它统一封装：

- 连接 `127.0.0.1:12345`
- token 封装
- `register/list/get/policy/token-set` 请求构造
- 响应解析

然后：

- `pgs_bless` 复用这个 client
- `pgs_admin_web` 也复用这个 client

这样能把“协议知识”从 CLI 和未来 Web 后端里抽出来，避免复制粘贴。

### 3.3 前端页面

第一阶段完全不需要上重型前端框架，简单 HTML + JS 就够了。

建议先做：

- 守护列表页
- 单个守护对象详情页
- 服务控制页
- token 管理页
- 操作日志页

等 API 稳定后，再考虑是否切换到更完整的前端框架。

## 4. API 形态建议

建议网页控制端对外暴露 JSON API，而不是把内部文本协议直接透传给浏览器。

可先定义这类接口：

- `GET /api/ping`
- `GET /api/guards`
- `GET /api/guards/{pid}`
- `POST /api/guards/bless`
- `POST /api/guards/bless-start`
- `POST /api/guards/{pid}/policy`
- `POST /api/guards/{pid}/intentional`
- `DELETE /api/guards/{pid}`
- `POST /api/token`
- `POST /api/service/install`
- `POST /api/service/start`
- `POST /api/service/stop`
- `GET /api/service/status`

这样浏览器端拿到的永远是结构化 JSON，不需要理解底层 `OK/ERR` 文本协议。

## 5. 鉴权建议

网页控制端至少要分清两层鉴权：

- 浏览器访问 `pgs_admin_web` 的会话鉴权
- `pgs_admin_web` 访问 `PGS` 的 token 鉴权

不建议把 `PGS token` 直接暴露在网页前端脚本里。

更合理的方式是：

- 浏览器先登录 `pgs_admin_web`
- 后端在服务端安全地持有或转发 `PGS token`
- 前端只调后端 HTTP API

## 6. 日志与实时性

第一阶段可以先做简单轮询：

- 守护表格每 1s 或 2s 拉一次
- 服务状态按需刷新

如果后面要做得更顺滑，再考虑：

- `WebSocket`
- `Server-Sent Events`

但这个阶段不建议一开始就做太重。

## 7. 自我守护与部署建议

如果后面新增 `pgs_admin_web`，部署关系建议是：

- `PGS` 仍由 Windows SCM 管理并负责故障恢复
- `pgs_admin_web` 可以作为单独服务或控制台工具运行

不要让 `PGS` 自己同时承担：

- 守护核心
- HTTP 服务
- 静态页面托管
- 自身恢复

职责过度堆叠之后，排障会很痛苦。

## 8. 落地顺序建议

建议按这个顺序推进：

1. 抽取 `PGSClient` 公共客户端层
2. 先做只读网页端：`ping/list/get/status`
3. 再做写操作：`policy/unbless/token-set`
4. 最后补 `bless-start`、服务管理、实时推送

## 8.1 当前阶段边界

当前第一阶段已经够用，但还保留了两个明确边界：

- Web 后端目前还是通过 CLI 工具调用 PGS，而不是直接复用公共客户端库
- 页面鉴权目前默认面向本机运维场景，最稳妥的部署仍然是绑定 `127.0.0.1`

## 9. 当前结论

结论很直接：

- “网页控制端”值得做
- 但不应该继续沿着“Qt 里查网页”这个方向做
- 当前已经改成独立 `pgs_admin_web`
- 下一步再继续抽公共 `PGSClient` 层，会比现在更干净
