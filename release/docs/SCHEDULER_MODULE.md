# 计划任务模块（pgs_sched_module）

PGS 计划任务模块 `sched` 提供 cron / 一次性 / 间隔三种触发方式，到期自动执行受限的
PGS 命令（bless / unbless / policy 等）。它是首个使用 **ABI v2** 的模块：通过
`PGS_Services` 回调从自己的后台线程反向调用 PGS，不再是无状态的请求/响应插件。

## 1. 调度格式

| 类型 | type | expr 取值 | 说明 |
|------|------|-----------|------|
| cron | cron | 分 时 日 月 周（5 段） | 标准 cron 语义，分钟粒度 |
| 一次性 | once | YYYY-MM-DDTHH:MM:SS | 触发一次后自动禁用 |
| 间隔 | interval | 正整数秒 | 每 N 秒一次，可选 count 限定次数 |

### cron 字段
- 分 0-59、时 0-23、日 1-31、月 1-12、周 0-6（0=周日）
- 支持 *（任意）、a-b（范围）、a,b,c（列表）、star/n（步进）、a-b/n
- 日（DOM）与周（DOW）当两者都被限制时按 Vixie cron OR 语义：匹配任一即触发；
  其中之一为 *（任意）时只看被限制的那个；两者都 * 则每天触发。
- 不支持月份/周英文缩写（纯数字），保持解析器零依赖。

### 错过执行策略（服务停机后恢复）
- once：若到期时间已过且仍启用，重启后补跑一次然后禁用。
- cron / interval：不补跑历史，按当前时钟重算下一个到期点（避免重启风暴）。

## 2. 动作白名单

允许：bless register unbless unregister policy set-policy intentional list get ping
禁止：token-set module load/unload service install/stop/uninstall ppl

这是防提权硬约束：即使 pgs_sched.db 被篡改，也无法通过调度执行高危命令。

## 3. 持久化

调度状态存于模块目录下 pgs_sched.db（与 DLL 同目录），文本 KV，原子写（tmp + 替换）。
字段：id;type;expr;action;enabled;last_run_ms;next_run_ms;run_count;max_count。
PGS（被 SCM）重启后模块在 PG_Init 重新加载并按错过执行策略重算。

## 4. CLI 用法

```bash
pgs_bless.exe schedule add --cron "*/2 * * * *" --action "bless 1234|-1"
pgs_bless.exe schedule add --once "2026-07-09T15:30:00" --action "unbless 1234"
pgs_bless.exe schedule add --interval 300 --count 5 --action "policy 1234|no"
pgs_bless.exe schedule list
pgs_bless.exe schedule remove --id 1
pgs_bless.exe schedule disable --id 2
pgs_bless.exe schedule enable --id 2
```

--action 的值是一条 PGS 行协议命令（bless <pid>|<maxRestarts> 等）。

## 5. ABI v2 说明（模块作者）

PG_Init(void* reserved) 的 reserved：
- ABI v1 模块：reserved 为 NULL，忽略即可（如 ppl 模块）。
- ABI v2 模块：reserved 指向 PGS_Services，含 call(context,request,response,size) 与 now_ms(context)，size 为结构体字节数（前向兼容）。

v2 模块必须在解引用前检查 reserved != NULL。详见 include/Process_Guard/PGModule.h。

## 6. 构建

tools/build_pgs.bat 与 tools/build_pgs.sh 已包含 pgs_sched_module.dll 的构建，
并将 sched 写入默认 modules.lock 信任文件（同时保留 modules.allow 兼容）。需开启普通模块加载（PGS_ENABLE_MODULES=1 或 --enable-modules）才会被 PGS 扫描加载；PPL/驱动开关与本模块无关。
