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

Limits: default request/response payload is 64 KB. Long tasks should return `{ "accepted": true, "operation_id": "..." }`; large binary data should return an artifact id instead of embedding bytes. The service now includes a shared in-memory OperationStore with TTL cleanup and an ArtifactStore under the service state directory. `module op-status` queries operation records, while `module artifact get --json` returns metadata and `module artifact get --out <path>` downloads content by chunks with client-side size/SHA-256 verification. Service chunk reads also recompute artifact size/SHA-256 before returning bytes. Operators can use `module artifact cleanup [--expired|--all] [--verify]`, `module artifact status [--verify]`, and `module artifact policy` for retention and health visibility.

## Module ABI

ABI v2 stays supported through `PG_Invoke(const char*, char*, size_t)`. ABI v3 modules can additionally export:

```c
int PG_InvokeJson(const char *requestJson, char *responseJson, size_t responseJsonSize);
```

PGS probes this export dynamically. If it is missing, `module invoke` falls back to a KV shim with `op=<method-suffix>;method=<full-method>;params_json_b64=<envelope>` so older modules can continue working while they migrate.

`PGS_ServicesV3` adds `call_json`, `emit_event`, `get_data_dir`, and `log` after the v2-compatible fields. The first fields mirror `PGS_Services`, so existing modules that only read v2 fields continue to work.

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

## Community Repository Shape

The future split repositories should look like this:

- `pgs-module-sdk`: ABI headers, CMake templates, schema files, examples, and writing guide.
- `pgs-modules-registry`: registry index, module metadata, publisher identity, release hashes, and review notes.

PGS itself should only download to `modules_staging/` and never load a community DLL until the operator explicitly verifies and trusts it. Registry metadata is advisory; final trust is based on hash, signature, publisher, manifest schema, capabilities, risk, and user confirmation.

## Current Commands

- `pgs_bless doctor [--json]`
- `pgs_bless module invoke --name <name> --method <namespace.method> --params-json <json>`
- `pgs_bless module verify|reload|disable|rollback`
- `pgs_bless module op-status <operation-id> [--json]`
- `pgs_bless module artifact get <id> [--json|--out <path>]`
- `pgs_bless module artifact cleanup [--expired|--all] [--verify]`
- `pgs_bless module artifact status [--verify] [--json]`
- `pgs_bless module artifact policy [--ttl-ms N] [--auto-cleanup|--no-auto-cleanup] [--verify-on-status|--no-verify-on-status] [--json]`
- `pgs_bless notify status|config [--eventlog|--no-eventlog] [--popup|--no-popup]`
- `pgs_bless metrics summary|json|prometheus`
- `pgs_bless backup status|snapshot [--artifact] [--max-bytes N]`
- `pgs_bless eventlog status|recent [--limit N] [--source <name>]`
- `pgs_bless dump status|collect --pid <pid> [--type normal|with-data] [--confirm]`
- `pgs_bless service-guard status|query|start|stop|ensure --name <service> [--state running|stopped] [--confirm]`
- `pgs_bless file-watch status|add|list|check|remove --path <file> [--id <id>] [--action event|none]`
- `pgs_bless policy-template status|set|list|remove|apply --name <template> [--pid <pid>]`
- `pgs_bless remote-agent status|heartbeat|guards`
- `pgs_bless update status|verify --path <release-manifest.json>`
- `pgs_bless script-runner status|config|add|list|run [--enable|--disable] [--confirm]`
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

The release build currently writes 16 bundled modules into `modules.lock`: `sched`, `health`, `profile`, `report`, `notify`, `metrics`, `backup`, `eventlog`, `dump`, `service_guard`, `file_watch`, `policy`, `remote_agent`, `update`, `script_runner`, and `ppl`. The newer operational modules are deliberately narrow first passes: no chat/webhook/mail integrations, no update downloader/installer, no remote listener in `remote_agent`, and script execution is disabled until explicitly enabled and confirmed.
