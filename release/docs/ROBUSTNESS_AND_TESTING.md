# ProcessGuard 鲁棒性与测试说明

## 1. 本文目的

这份文档专门说明以下问题：

- 当前实现重点防御了哪些历史缺陷
- 现在的守护状态模型为什么这样设计
- 构建、验证、烟测分别覆盖什么
- 仍然存在的边界和后续可继续增强的方向

它不是快速上手文档；若只想看如何编译和使用，请先看：

- `README.md`
- `docs/SERVICE_MODE_GUIDE.md`
- `docs/TECHNICAL_ARCHITECTURE.md`

## 2. 当前鲁棒性设计

### 2.0 守护集合现在是“可恢复归档”，不是纯内存

这次最重要的变化，是把守护目标从“只活在当前服务进程内存里”提升成了“有 durable desired state 的归档模型”：

- 活跃运行态放在 `m_guards`
- 持久化期望态放在 `m_persistedGuards`

这带来的结果是：

- 服务被 SCM 拉起来后不会从空白内存重新开始
- 它会先读档，再决定哪些进程该重新接管、哪些该重新拉起
- token hash 也会跟随归档一起恢复

### 2.1 守护状态按 `guardId` 跟踪，而不是按路径

历史问题是“同路径多实例互相污染策略”：

- 两个不同 PID 如果都来自同一个 exe 路径
- 若策略按 `path` 记录
- 一个实例异常退出会累加另一个实例的重启计数
- 一个实例主动退出还可能把另一个实例的策略整条删掉

当前实现改为：

- 每个逻辑守护对象分配一个稳定的 `guardId`
- `guardId` 在“同一守护对象重启前后”保持不变
- `pid` 变化时，仅更新 `m_guards[pid]`
- 重启计数与最大重启次数存入 `m_policyByGuardId`

这样带来的效果是：

- 同一路径多实例可独立计算重启次数
- 主动退出只影响自己的 guard
- 同路径兄弟进程不会共享上限和计数

### 2.2 服务端注册时会核对 `pid` 与真实镜像路径

历史问题是客户端可能提交：

- `--pid A`
- `--path B`

如果服务端盲目信任客户端路径，就会出现：

- 当前监控的是 `A` 的句柄
- 但未来重启时启动的是 `B`

当前实现做法：

- 服务端收到 `register` 后
- 先根据 `pid` 查询真实镜像路径
- 再与客户端提交路径做归一化比较
- 不一致直接拒绝注册

这保证了：

- hash 校验与真实镜像绑定
- 重启目标和被监控目标保持一致

### 2.3 `bless-start` 尽量做到原子

历史问题是：

1. CLI 先启动进程
2. 再计算 hash
3. 再连接 PGS 注册

若中间任何一步失败，进程已经跑起来了，但其实没有受管。

当前实现改为：

1. `CreateProcessW(..., CREATE_SUSPENDED)`
2. 计算路径与 hash
3. 向 PGS 注册
4. 注册成功后 `ResumeThread`
5. 若注册失败，则直接终止这个尚未恢复的子进程

这意味着：

- 成功路径：启动和受管几乎同时成立
- 失败路径：不会遗留一个“启动了但没守护”的半成品

### 2.4 协议收发不再由单个监听线程串行阻塞

历史问题是：

- 监听线程 `accept`
- 然后直接 `recv`
- 没超时
- 没 worker
- 没完整发送循环

只要有一个慢客户端连上不发完，整个管理口就会被卡住。

当前实现：

- 监听线程只负责 `accept`
- 新连接进入队列
- 固定数量 worker 线程负责 `recv/process/send`
- `recv` 有超时
- 单条消息有大小上限
- `sendAll` 处理 partial send

这不是完整的高并发网络框架，但足以覆盖当前工具型协议的鲁棒性需求。

### 2.5 失败清理策略

当前实现中，以下情况会主动清理状态：

- `intentional` 退出：删除该 guard 的策略
- `unregister`：删除该 guard 的策略
- 达到重启上限：删除该 guard 的策略
- 重启尝试失败：删除该 guard 的策略

这样做的目标是：

- 不让旧的重启计数污染下一次全新注册
- 不让无主策略长期滞留在内存里

### 2.6 服务重启后的恢复策略

当前恢复策略是：

- 若归档里的 `lastKnownPid` 仍然存在且路径匹配，则重新接管
- 若目标进程不存在，则先检查该 guard 的重启预算；未超限才按归档中的路径、参数、会话信息尝试拉起
- 若 guard 曾被标记为 `intentional` 且现在已经不在，则从归档移除
- restore 阶段的重新拉起也计入 `restartCount` / `recentRestartMs`，不会因为服务自身重启而绕过 crash-loop 限额
- restore 阶段达到上限或重新拉起失败时，会从归档删除该 guard，避免下一次服务启动再次复活

这让“服务自己被恢复”与“它守护的进程也要跟着恢复”形成了一条完整链路。

## 3. 重启保真度说明

### 3.1 已经改善的部分

对于 `bless --pid`：

- CLI 会尽量抓取现有进程命令行参数
- 作为默认 `restartArgs`
- 比“无参数重启”更接近原始启动方式

对于 `bless-start`：

- 默认保留 `--start-args`
- 若用户未显式传 `--restart-args`
- PGS 后续重启沿用首次启动参数

### 3.2 仍然不是完整克隆

当前重启仍然无法自动完整恢复：

- 任意自定义环境变量
- 原进程运行时动态修改后的工作目录
- 某些由父进程注入的句柄与上下文
- GUI/控制台附着状态

因此建议是：

- 最稳妥场景优先使用 `bless-start`
- 对已有外部进程，必要时显式传 `--restart-args`

## 4. 图形控制端鲁棒性调整

当前 Qt 桌面端做了以下收口：

- 守护表格默认自动刷新改为 `1000 ms`
- 自动刷新时不再每轮 `resizeColumnsToContents()`
- 表格 JSON 短暂解析失败时，保留旧表而不是清空
- 表格刷新错误显示到状态栏

同时，真正的浏览器控制端现在已经单独落成 `pgs_admin_web`：

- 它不再伪装成 Qt 里的一个“查网页”页签
- 它是独立 Web 后端 + 浏览器前端
- HTTP 层与 `PGS` 核心职责分离
- 本地模式只允许回环绑定，并用进程内 token + Host/Origin 校验防 DNS rebinding / CSRF
- remote 模式 fail-closed：TLS + RBAC + audit log 必须就绪；变更类 API 还要求同源 CSRF 头

## 5. 构建、验证、烟测的区别

### 5.1 `tools/build_pgs.sh`

职责：

- 编译 C++ 主线
- 生成 `pgs_service.exe`
- 生成 `pgs_bless.exe`
- 生成示例程序
- 生成 sched / health / profile / report / ppl 模块产物

不覆盖：

- Qt 管理端
- 运行期协议交互

### 5.2 `tools/verify_pgs.sh`

职责：

- 检查关键文件存在
- 执行 `tools/build_pgs.sh`
- 执行 `tools/run_unit_tests.sh`
- 执行 `tools/smoke_test_pgs.sh`
- 配置并编译 Qt 桌面端
- 配置并编译浏览器控制端

适合：

- 本地改动后的日常回归
- 本地做一轮接近 CI 的基础构建验证

### 5.3 拆分后的 unit / Qt Web 脚本

可单独运行的验证入口：

- `tools/test_core_units.sh`：只编译并运行 `tests/test_pgs_core.cpp`
- `tools/test_sched_cron.sh`：只编译并运行 `tests/test_sched_cron.cpp`
- `tools/run_unit_tests.sh`：顺序调用上面两个 unit 脚本，供本地和旧入口复用
- `tools/build_qt_web.sh`：单独配置并构建 `pgs_admin_web` 与 `pgs_cluster_web`

Windows `cmd.exe` 入口也保留了兼容脚本：`tools/test_core_units.bat`、
`tools/test_sched_cron.bat` 和 `tools/test_pgs_core.bat`。GitHub Actions 会按
C++ 主线构建、core unit、sched cron unit、smoke test、Qt Web 构建拆成独立步骤，
方便定位失败阶段。

### 5.4 `tools/smoke_test_pgs.sh`

当前烟测覆盖：

- `PGS_SERVICE_TOKEN=... pgs_service.exe run` 启动
- `pgs_bless ping`
- `pgs_bless list --json`
- `token-set` 在线切换 token
- `bless-start` 原子启动并注册（目标为专用 `smoke_worker.exe`）
- 服务异常退出后的 token 恢复
- 服务重启后的守护对象恢复
- `get --pid`
- 守护对象清理

它不是压力测试，也不是完整回归测试；它的定位是：

- 尽快发现“服务起不来/协议不通/关键命令失效”这类一眼致命的问题

### 5.5 跳过烟测

如果当前机器上已经有其它 PGS 占用默认端口，或者你只想做纯编译检查，可以：

```bash
PGS_SKIP_SMOKE=1 ./tools/verify_pgs.sh
```

## 6. 示例程序的鲁棒性补充

`guard_example` 与 `quick_start` 已补上：

- 宽字符可执行路径获取
- UTF-8 转换
- token 自动带入重启参数

这解决了两个常见问题：

- 中文路径下自注册失败或路径不一致
- 非空 token 场景下首次重启后无法再次注册

## 7. 当前已知边界

下面这些点并不是“坏掉了”，而是当前实现有意识地还没做成更重的方案：

- 协议仍然是自定义文本协议，不是 protobuf/grpc
- 已有磁盘归档恢复，但还不是带历史版本/事务语义的完整配置数据库
- 还没有压力测试脚本
- Web remote RBAC 用户文件已支持 PBKDF2-SHA256，旧 HMAC-SHA256 记录仅作为兼容格式保留；后续可继续迁移到 Argon2id/bcrypt
- cluster 节点凭据不从 API 回显，Windows 上新保存的 registry 第三列会用 DPAPI 保护；仍需限制文件 ACL，因为同一运行账号可解密
- `bless --pid` 对任意外部进程仍无法自动百分百还原原始环境变量与工作目录

## 7.1 关于“服务自我守护”

从鲁棒性角度看，“让 PGS 自己守自己”不能简单理解成“在 PGS 内部再加一段监控自己 PID 的代码”，因为：

- 同一个进程崩溃后，内部逻辑不会继续运行
- 真正能在它死后把它拉起来的，必须是外部监督者

当前更合理的层次划分是：

- `PGS` 负责守护业务进程
- `Windows SCM` 负责守护 `PGS` 服务

因此当前实现把“服务自身恢复”交给 SCM 故障恢复动作，而不是在 `PGS` 核心里再造一层递归式自守护机制。这个方案更简单，也更符合 Windows 服务生态。

## 8. 后续可继续增强的方向

如果后面继续往上做，我建议优先级如下：

1. 在管理员 VM 上跑完整 E2E：SCM install/start/stop、TLS remote gateway、cluster dashboard、PPL opt-in
2. 增加压力测试与长稳测试脚本，验证高频注册/注销和频繁异常退出场景
3. 为 remote users 文件迁移强 KDF（PBKDF2/Argon2id/bcrypt），为 cluster nodes 文件接 DPAPI
4. 若协议继续扩展，再考虑迁移到 `JSON schema` 或 `protobuf`
