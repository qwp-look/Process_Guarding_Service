# PGS Module Ecosystem Foundation

PGS now treats the service as a stable guard core plus a guarded module ecosystem. The core owns the TCP protocol, durable guard state, Job Object attachment, authentication, and the final security loader. Feature logic such as PPL, scheduling, health, profiles, reports, and future community modules lives behind module manifests and trust policy.

## Protocol v3

The new module command path is JSON-RPC shaped and transport-neutral. Current transport is still the local PGS TCP command plus in-process DLL invocation, but the envelope can be reused by Named Pipes, a module host process, or a remote management proxy.

Request envelope:

```json
{
  "jsonrpc": "2.0",
  "id": "uuid-or-number",
  "module": "profile",
  "method": "profile.apply",
  "params": {},
  "context": {
    "trace_id": "...",
    "caller": "tcp|scheduler|web|qt",
    "deadline_ms": 5000
  }
}
```

Response envelope:

```json
{"jsonrpc":"2.0","id":"...","result":{}}
```

or:

```json
{"jsonrpc":"2.0","id":"...","error":{"code":"ERR_CODE","message":"..."}}
```

Limits: default request/response payload is 64 KB. Long tasks should return `{ "accepted": true, "operation_id": "..." }`; large binary data should return an artifact id instead of embedding bytes. The service now includes a shared in-memory OperationStore with TTL cleanup and an ArtifactStore under the service state directory. `module op-status` queries operation records, while `module artifact get --json` returns metadata and `module artifact get --out <path>` downloads content by chunks with client-side size/SHA-256 verification. Service chunk reads also recompute artifact size/SHA-256 before returning bytes. Operators can use `module artifact cleanup [--expired|--all] [--verify]`, `module artifact status [--verify]`, and `module artifact policy` for retention, bounded byte quota, and health visibility.

ArtifactStore defaults to a 24-hour TTL, 16 MB per artifact, and 256 MB total store bytes. `module artifact policy` can change TTL within 60 seconds..7 days, `max_artifact_bytes` within 64 KB..64 MB, and `max_total_bytes` within 1 MB..1 GB; the total limit must be at least the single-artifact limit. The effective policy is persisted in `artifact_policy.cfg` and is returned by status/policy/doctor surfaces.

Artifact metadata includes `sensitive` and `sensitivity`; dump/minidump artifacts default to high sensitivity with a 6-hour TTL cap, backup-like artifacts default to medium with a 24-hour cap, and status/doctor expose sensitive counts. Chunk download start/complete/expired/invalid events are recorded in `events list`.

## Module ABI

ABI v2 stays supported through `PG_Invoke(const char*, char*, size_t)`. ABI v3 modules can additionally export:

```c
int PG_InvokeJson(const char *requestJson, char *responseJson, size_t responseJsonSize);
```

PGS probes this export dynamically. If it is missing, `module invoke` falls back to a KV shim with `op=<method-suffix>;method=<full-method>;params_json_b64=<envelope>` so older modules can continue working while they migrate.

`PGS_ServicesV3` adds `call_json`, `emit_event`, `get_data_dir`, and `log` after the v2-compatible fields. The first fields mirror `PGS_Services`, so existing modules that only read v2 fields continue to work. Module `emit_event` JSON may include a safe `type` field; the core records that type directly in `events list` and stores the raw JSON as base64 detail, falling back to `module.event` for unsafe or missing types.

## Trust Files

`modules.lock` is the primary trust file. When a release tree contains `modules.lock`, the loader expects strict hash-pinned entries; `modules.allow` is only a legacy compatibility path for trees that do not ship `modules.lock`.

`modules.lock` records:

- `name`
- `version`
- `sha256`
- `publisher`
- `source`
- `capabilities`
- `risk`
- `trustedAt`
- `signature_policy`
- `require_signed`

The loader still has final refusal authority: the resolved DLL path must stay inside the modules root, the module name must match the path-derived key, ABI must be supported, hash/signature trust must pass, and high-risk modules such as `ppl` require the kernel-module opt-in switch.

`--hash none` also means no persisted module or guard hash is written by the relevant trust/register path; future restarts must not treat an empty hash as a mismatch.

## Module Manager Extensions

Manager extensions use `include/Process_Guard/PGModuleManager.h` and live under `module_managers/<name>/manager.dll`. They are not ordinary modules and they do not receive a callback that can execute PGS management commands. Their role is limited to repository index parsing, install planning, version compatibility, and trust advice. The core loader executes the plan only after its own checks pass.

Manager extensions also need their own manifest and trust chain. The default bundled manager is metadata-only today; future registry clients should download candidate modules to `modules_staging/`, present the plan, then let the core verify and promote into `modules/<name>/`.

## Code Reuse And Split Points

The codebase is now large enough that future feature work should actively split reusable pieces instead of growing `PGSProtocol.cpp`, `pgs_bless.cpp`, or individual module files indefinitely. Prefer small shared files with clear ownership when a helper is used by two or more surfaces.

Recommended split points:

- Protocol parsing and JSON helpers: move lightweight JSON/KV parsing toward shared structured helpers, then gradually replace string scans in module install, manifest handling, OperationStore, and ArtifactStore.
- Module install/trust helpers: keep download, registry parsing, risk prompts, staging metadata, lockfile update, rollback, and load orchestration in reusable units instead of duplicating them between CLI, service, Qt, and Web.
- Security policy helpers: centralize capability/risk/role decisions so CLI, Web RBAC, module callbacks, and future named-pipe transport use the same table.
- Filesystem trust helpers: reuse final-path, ACL, hash, signature, and staging/rollback checks across `ModuleManager`, doctor/repair, release smoke, and service install flows.
- UI response parsing: share a stable response schema for module results rather than having Qt/Web parse ad hoc text differently.

When adding or splitting reusable code, update the relevant docs in the same change. A feature PR that changes protocol, module trust, validation behavior, or operator commands should not leave `MODULE_ECOSYSTEM.md`, `UNFINISHED_FEATURES_BACKLOG.md`, `SECURITY_HARDENING_BACKLOG.md`, or user/operator docs stale.

All build/test examples and scripts should assume MSYS2/MinGW64 and carry explicit environment variables as documented in `docs/developer/BUILD.md` and `docs/developer/TESTING.md`.

## Community Repository Shape

The future split repositories should look like this:

- `pgs-module-sdk`: ABI headers, CMake templates, schema files, examples, and writing guide.
- `pgs-modules-registry`: registry index, module metadata, publisher identity, release hashes, and review notes.

PGS itself should only download to `modules_staging/` and never load a community DLL until the operator explicitly verifies and trusts it. Registry metadata is advisory; final trust is based on hash, signature, publisher, manifest schema, capabilities, risk, and user confirmation.

## Current Commands

- `pgs_bless doctor [--json]`
- `pgs_bless module invoke --name <name> --method <namespace.method> --params-json <json>`
- `pgs_bless module verify|reload|disable|rollback`
- `pgs_bless module permissive status|on|off [--confirm]`
- `pgs_bless module op-status <operation-id> [--json]`
- `pgs_bless module artifact get <id> [--json|--out <path>]`
- `pgs_bless module artifact cleanup [--expired|--all] [--verify]`
- `pgs_bless module artifact status [--verify] [--json]`
- `pgs_bless module artifact policy [--ttl-ms N] [--max-artifact-bytes N] [--max-total-bytes N] [--auto-cleanup|--no-auto-cleanup] [--verify-on-status|--no-verify-on-status] [--json]`
- `pgs_bless notify status|config [--eventlog|--no-eventlog] [--popup|--no-popup]`
- `pgs_bless metrics summary|json|prometheus`
- `pgs_bless backup status|snapshot [--artifact] [--max-bytes N]`
- `pgs_bless eventlog status|recent [--limit N] [--source <name>]`
- `pgs_bless dump status|collect --pid <pid> [--type normal|with-data] [--confirm]`
- `pgs_bless service-guard status|query|start|stop|ensure --name <service> [--state running|stopped] [--confirm]`
- `pgs_bless service-guard policy [--allow <svc1,svc2>] [--allow-protected|--no-allow-protected] [--confirm]`
- `pgs_bless service-guard policy-clear --confirm`
- `pgs_bless file-watch status|add|list|check|remove --path <file> [--id <id>] [--action event|none]`
- `pgs_bless policy-template status|set|list|remove|apply --name <template> [--pid <pid>]`
- `pgs_bless remote-agent status|heartbeat|guards`
- `pgs_bless update status|verify --path <release-manifest.json>`
- `pgs_bless script-runner status|config|add|list|run [--id <id>] [--path <script>] [--start-args "..."] [--enable|--disable] [--confirm]`
- `pgs_bless ppl set|get|clear` as compatibility sugar through module invocation

`module call` and `module.manifest` remain supported for ABI v2 modules.

## Guard Capability Upgrades

The guard core now exposes service-side `start-register`, per-guard `health-check set|get|clear`, `restart-hook set|get|clear`, and `group create|add|remove|pause|resume|restart|list`. These are designed as protocol foundations for future modules and UI surfaces:

- `start-register` lets the service create the process suspended, attach the Job Object, register the guard, then resume it.
- health checks are stored as JSON schema-like config for HTTP/TCP/window/CPU/memory-style checks.
- guard groups store startup order, dependencies, pause/resume state, and allow group restart.
- restart hooks are stored as structured JSON only; script execution is disabled unless a future trusted module/runner explicitly implements it.
- guard summaries include runtime profile fields such as last exit time/code, cumulative runtime, average restart interval, paused, group, and crash-loop state.
- guard summaries include quarantine fields such as guard id, status, last failure, next retry time, and failure count.
- health checks now execute process/TCP/HTTP probes in a dedicated worker and can emit events, restart, or quarantine.

Modules that call back into these commands through `PGS_ServicesV3.call_json` need matching capabilities such as `guard.register`, `guard.health`, `guard.group`, or `guard.hook`.

## Bundled Module Set

The release build currently writes 16 bundled modules into `modules.lock`: `sched`, `health`, `profile`, `report`, `notify`, `metrics`, `backup`, `eventlog`, `dump`, `service_guard`, `file_watch`, `policy`, `remote_agent`, `update`, `script_runner`, and `ppl`. The newer operational modules are deliberately narrow first passes: no chat/webhook/mail integrations, no update downloader/installer, no remote listener in `remote_agent`, and script execution is disabled until explicitly enabled and confirmed. `script_runner` additionally requires scripts to resolve under the service data scripts directory by final path, pins SHA-256 at registration, re-hashes before run, and emits config/add/run audit events. `service_guard` is bounded by confirm-required mutations, default-deny protected services, an optional persisted allowlist, and mutation/policy audit events. `file_watch` is similarly bounded: at most 64 rules, local absolute drive paths only, and default denies for UNC/device/ADS/Windows system paths.

## Module Registry

PGS 官方模块仓库：[qwp-look/PGS_Model](https://github.com/qwp-look/PGS_Model)

仓库是 PGS 模块的权威分发渠道。客户端通过拉取 `registry.json` 索引获取可用模块列表，并按三档信任模型决定安装行为。

### 三档信任

| 档位 | 发布者 | PGS 默认行为 |
|---|---|---|
| `official` | 仅 qwp-look | 直接信任，hash 不匹配则 fail-closed |
| `curated` | 经 qwp-look 审核 | 信任，安装时提示已审核第三方模块 |
| `community` | 任何人 | 默认拒绝，需 `--trust-community` 显式 opt-in |

`community` 档在代码签名基础设施就绪前默认拒绝加载，防止仓库成为供应链攻击入口。详细规则见仓库 [docs/TRUST_LEVELS.md](https://github.com/qwp-look/PGS_Model/blob/main/docs/TRUST_LEVELS.md)。

### registry.json 结构

客户端拉取 `registry.json` 获取模块索引：

```json
{
  "version": "1",
  "pgs_min_version": "0.1.0-beta.1",
  "modules": [
    {
      "name": "sched",
      "trust": "official",
      "risk": "low",
      "capabilities": ["guard.schedule"],
      "bundled": true,
      "latest": "0.1.0-beta.1",
      "versions": [
        {
          "version": "0.1.0-beta.1",
          "download_url": "...",
          "sha256": "...",
          "manifest_url": "..."
        }
      ]
    }
  ]
}
```

`bundled: true` 表示该模块随 PGS 安装包内置，无需单独下载；`download_url` 为空。

### module install 流程（基础闭环已完成）

```bat
pgs_bless.exe module install sched
pgs_bless.exe module install my-tool --trust-curated
pgs_bless.exe module install experimental --trust-community
```

当前 CLI registry install 已串到服务端安装闭环：CLI 负责拉取 `registry.json`、结构化校验 registry/module/version 字段、限制下载地址为 `https://raw.githubusercontent.com/...`、下载 DLL 与 `module.manifest.json`、校验 SHA-256、展示 trust/risk 警告并处理确认；最终安装统一调用服务端 `module install <base64-dll-path> --confirm --load --source registry`。CLI 不再直接复制 DLL 到 `modules/<name>/`。

实际安装流程：拉取 `registry.json` -> 结构化字段校验 -> 下载到 `modules_staging/` -> SHA-256 校验 -> 下载并校验 `module.manifest.json` -> 核对 name/trust/risk/capabilities -> 对 `community` 要求 `--trust-community` 和 typed `YES`，对所有 `high`/`critical` 要求 `--confirm` -> 调用服务端 `module install` -> 服务端重新检查 DLL/manifest/hash/risk -> 结构化更新 `modules.lock` -> promote 到 `modules/<name>/` -> 按请求 load。

安装失败必须可解释并可回滚。失败时不要留下半安装模块，也不要绕过 `modules.lock` 直接 `module load`。社区模块即使通过 hash 校验，也只代表下载完整性，不代表代码安全。

下载路径也按安全默认值处理：registry JSON、manifest 和 DLL 响应都有大小上限，外部 URL 仅允许 `https://raw.githubusercontent.com/...`，服务端仍会重新校验 sidecar manifest 和 DLL identity。

高风险模块（`risk: high` 或 `risk: critical`）安装时额外需要 `--confirm`，不论档位。

开放第三方模块前的剩余硬前提：live PGS_Model 正例验证、hash mismatch / manifest mismatch / community 未确认 / high-risk 未确认等负例 E2E、签名策略或更严格 publisher policy。结构化 JSON 校验、共享策略 helper、服务端安装闭环和 hash-pinned `modules.lock` 写入已经落地。

### 贡献模块

- 提交 curated 模块：见仓库 [docs/CONTRIBUTING.md](https://github.com/qwp-look/PGS_Model/blob/main/docs/CONTRIBUTING.md)
- 发布新版本：见仓库 [docs/PUBLISHING.md](https://github.com/qwp-look/PGS_Model/blob/main/docs/PUBLISHING.md)
