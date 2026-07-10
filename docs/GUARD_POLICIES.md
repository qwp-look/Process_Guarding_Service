# 守护策略（v3 hardening）

本文档说明 v3 引入的高级重启策略字段、默认值、与旧 `--max-restarts` 的兼容关系，
以及 WindowsApps（UWP/Store）守护用法。

## 1. 字段总览

| 字段 | CLI 选项 | 默认 | 含义 |
|------|----------|------|------|
| 重启上限 | `--max-restarts N\|no` | `3` | 在窗口内允许的最大重启次数；`no`=无限 |
| 滑动窗口 | `--restart-window <秒>` | `0` | 0=生命周期累计（旧语义，向后兼容）；>0=仅统计该窗口内的重启 |
| 重启延迟 | `--restart-delay <ms>` | `0` | 决定重启后等待多久再拉起 |
| 指数退避 | `--restart-backoff` | 关 | 开启后延迟按 `delay * 2^min(index,6)` 增长，上限 60s |
| 假活检测 | `--hang-timeout <ms>` | `0` | >0 时对 guard 的可见窗口用 `SendMessageTimeout(WM_NULL)` 探测，超时即视为假活 |
| 退出连杀 | `--kill-on-exit` | 关 | 打开 Job 的 `KILL_ON_JOB_CLOSE`，PGS 退出时连守护族一起终结 |
| 应用类型 | `--winapp` | Win32 | 标记为 WindowsApps 守护，重启经 AUMID 激活 |
| AUMID | `--aumid <id>` | 空 | WindowsApps 用户模型 ID，`--winapp` 下必填 |

## 2. 兼容矩阵（与旧 `--max-restarts`）

- 不传任何新字段时，行为与 v2 完全一致：`max-restarts` 是**生命周期累计**上限，到达后永久退役。
- `--restart-window 0`（默认）= 旧语义；窗口自愈仅在 `--restart-window > 0` 时生效。
- 旧归档（v2）恢复后所有新字段补默认值，守护不中断。
- 重启计数与滑动窗口时间戳会随 guard 归档持久化。服务被 SCM 拉起后，不会因为 PGS 自己重启而清空
  crash-loop 计数。

## 2.1 服务恢复时的重启预算

PGS 启动恢复归档时按以下规则处理：

- 归档中的 `lastKnownPid` 仍活着且路径匹配：重新接管，不计作一次重启。
- 进程已不存在且未 intentional：按 desired-state 重新拉起，**这次拉起计入重启次数/窗口**。
- 已达到 `maxRestarts` 或窗口内上限：该 guard 从归档退休，不会在下一次服务重启后反复复活。
- 重新拉起失败：该 guard 从归档和策略表删除，行为与运行期“永久重启失败”一致。
- 配置了 `--restart-delay` / `--restart-backoff` 时，重启计数在进入延迟队列前就会落盘；PGS 在延迟窗口内
  崩溃/停止，也不会丢掉这次预算消耗。

## 3. 监控机制（Job Object + IOCP）

- 每个守护对象拥有一个**命名 Job** `Global\PGS-Job-<guardId>`，子/孙进程自动留挂在 job 内
  （breakaway 禁用），`restart`/`unregister`/`intentional` 触发 `TerminateJobObject` 清场。
- 退出通知经 **IOCP 完成端口** 触达 monitor 线程，延迟从 200ms 轮询降到~50ms；
  200ms 句柄轮询 + 假活探测仍作为兜底。
- `--kill-on-exit` 默认**关闭**：保证 PGS 自身崩溃后守护进程仍存活，便于 SCM 重启后复接管；
  显式开启则 PGS 退出时整族随之终结（用于"PGS 停止=守护也停"的场景）。
- 命名 Job 需要 `SeCreateGlobalPrivilege`（LocalSystem/管理员），这是默认服务身份
  仍为 LocalSystem 的主因之一。

## 4. WindowsApps 守护

WindowsApps（UWP/Store 打包应用）无法用 `CreateProcessW` 直接启动，必须经 AUMID
激活。两种方式：

```bash
# 方式 A：自动探测（路径命 WindowsApps\ 时服务端读 AppxManifest 推导 AUMID）
./build/pgs_bless.exe bless-start --path "C:/Program Files/WindowsApps/Microsoft.WindowsCalculator_xxx/Calculator.exe" --winapp --max-restarts 3

# 方式 B：手动 AUMID（最稳）
./build/pgs_bless.exe bless --pid 1234 --winapp --aumid Microsoft.WindowsCalculator_8wekyb3d8bbwe!App --max-restarts 3
```

重启走 `restartAppGuard`：复用目标会话用户 token → `shell:AppsFolder\<AUMID>` 激活，
回取新 pid 句柄。`path` 仍记录原始可执行路径用于 hash 校验与人读。

## 5. token / 权限提醒

- 本轮 token 仍经环境变量 `PGS_AUTH_TOKEN` 传递；Qt/Web 已避免命令行泄露，但子进程会
  继承该变量（已知风险，后续可演进为 named-pipe 握手）。
- 跨会话重启需要 LocalSystem 身份；`--service-account` 切换低权账号会退化为 Session 0 fallback。
