# Remaining Upgrade Plan

This document captures the unfinished work after the module ecosystem and security-kernel upgrade. It is intended as a handoff plan for the next development thread.

## Current Status

Completed in the current repository state:

- Module protocol v3 foundation: JSON-RPC style `module invoke`, ABI v3 `PG_InvokeJson`, `PGS_ServicesV3`, request/response size and deadline policy.
- Shared OperationStore / ArtifactStore: core JSON methods now expose `pgs.operation.*` and `pgs.artifact.*`; CLI/Web/Qt cover operation status, artifact metadata/download, cleanup, store status, and retention policy controls.
- WindowsApps activation: `bless-start --winapp --aumid` can activate and register apps, and CLI can best-effort derive AUMID from `AppxManifest.xml` when given a WindowsApps exe path.
- Notify module: Windows-native Event Log delivery plus opt-in local popup, no chat/webhook/mail integration.
- Profile/scheduler runtime DB migration: state DBs now live under the service data directory with copy-only compatibility from the old module directory.
- PPL decoupling: PPL is treated as a critical-risk module gated by explicit kernel/risk flags, while legacy `ppl set/get/clear` remains a CLI compatibility layer.
- Module trust foundation: `module.manifest.json`, `modules.lock`, staging install, rollback, reload/disable/verify commands, capability/risk checks, and protected loader ownership in core.
- Module manager extension foundation: separate `module_managers/` directory, manager manifest/schema, and ABI declarations; managers can advise but cannot bypass the core loader.
- Doctor and UI scope: CLI/Web/Qt doctor surface, v3 guard fields, module page risk/trust details, and existing visual style preserved.
- Guard protocol upgrades: service-side `start-register`, health-check config, restart-hook config storage with execution disabled, guard groups, paused state, and runtime profile fields.
- Build and release foundation: top-level CMake, build script updates, package script rebuild behavior, bundled `modules.lock`, release smoke coverage, and release docs/schema packaging.
- Metrics/backup/eventlog modules: bundled first pass is implemented, covered by build/smoke, and exposed through CLI plus Web/Qt convenience surfaces.
- Remaining candidate modules implemented as bundled first pass: `dump`, `service_guard`, `file_watch`, `policy`, `remote_agent`, `update`, and `script_runner` now build into `modules.lock`, ship in release packaging, and have high-level CLI wrappers plus smoke status/function checks.
- Release metadata first pass: `tools/write_release_manifest.ps1` generates `release-manifest.json`, `SHA256SUMS.txt`, and first-party `sbom.spdx.json`; `build_installer.bat` writes them beside installer/zip; publish workflow uploads them and requests GitHub artifact attestation.
- GitHub Actions `build` and `publish-release` workflows are temporarily manual-only (`workflow_dispatch`) while backlog items are pushed in small batches.

Known intentionally incomplete areas:

- `restart-hook` only stores structured config and returns `execution=disabled`; no script or module action execution is enabled.
- Code signing is still not configured. Release manifest/SBOM/checksum generation is implemented locally and wired into publish workflow, but a live GitHub Release run must still confirm repository attestation permissions and final asset upload behavior.
- Automatic GitHub CI/CD triggers are temporarily disabled; push/tag validation depends on local MSYS2/MinGW64 verification until workflows are re-enabled.
- New higher-risk bundled modules are intentionally conservative: `dump collect`, service start/stop/ensure, and `script_runner run` require `--confirm`; `script_runner` is disabled by default, accepts only scripts whose final path resolves under the service data scripts directory, pins SHA-256 at registration, re-hashes before run, and emits audit events; `update` only verifies local manifests and does not download or install anything.
- VM-level E2E checks for LocalSystem, low-privilege service accounts, real PPL/test-signing, remote TLS, and clean installers still need dedicated environment runs.
- Local Web loopback mode now uses an HttpOnly `pgs_local_session` cookie plus `X-PGS-CSRF`; the page no longer embeds a Web API bearer. This still needs live VM/browser validation before a security release.
- `ModuleManager` / protocol JSON parsing still uses lightweight string extraction in several security-relevant paths. It is acceptable for bundled fixtures but should be replaced or explicitly constrained before opening community modules.
- Release versioning is now sourced from root `VERSION` for local packaging and the publish workflow; README/download snippets still need review whenever the public version string changes.
- `PGSClient::sendCommand()` now owns its Winsock runtime setup, so fresh shared-library callers do not need hidden `WSAStartup()` boilerplate.
- Artifact download verifies downloaded size and SHA-256 client-side; service-side chunk reads recompute size/SHA-256 before serving; `module artifact cleanup/status/policy` exist; doctor reports ArtifactStore health. Periodic cleanup, download audit events, first-pass sensitive-artifact metadata/reporting, and configurable bounded byte quotas are now implemented; remaining artifact work is stronger remote-download auditing/UI prompts and operation persistence decisions if durable long tasks become required.

## Workstream A: Global Operation Store

Status: implemented first functional pass in the service core. `module op-status <operation-id> [--json]` now queries the shared OperationStore; the remaining work below is hardening, durable persistence if needed, and richer long-task conventions.

### Design

Add a service-owned `OperationStore` with these fields per operation:

- `id`: opaque generated id, preferably `op_<128-bit random hex>`.
- `module`: module name that owns the operation.
- `method`: JSON-RPC method that accepted the operation.
- `status`: `accepted`, `running`, `succeeded`, `failed`, `cancelled`, or `expired`.
- `progress`: integer 0-100 when known, otherwise absent.
- `message`: short user-facing status text.
- `result`: small JSON object for final success, subject to protocol size limits.
- `error`: `{code,message}` for final failure.
- `artifact_ids`: optional array of artifact ids produced by the operation.
- `created_ms`, `updated_ms`, `expires_ms`.
- `trace_id`, `caller`, `deadline_ms` copied from request context when available.

Storage should start in memory with durable JSON snapshots under ProgramData only if needed. The first implementation can be in-memory plus TTL cleanup, because modules that need durable long work can still own their persistence. Do not block the module worker while an operation is running.

### API Shape

Service callbacks exposed to ABI v3 modules:

- `operation_create(request_json, response_json, response_size)` or a `call_json` method such as `pgs.operation.create`.
- `operation_update(operation_id, patch_json)` or `pgs.operation.update`.
- `operation_finish(operation_id, result_json)`.
- `operation_fail(operation_id, error_json)`.

Prefer routing through `PGS_ServicesV3.call_json` with namespaced core methods first, because it keeps ABI churn low:

- `pgs.operation.create`
- `pgs.operation.update`
- `pgs.operation.finish`
- `pgs.operation.fail`
- `pgs.operation.get`

CLI/protocol:

- `module op-status <operation-id>` returns `OK <json>` or plain text summary.
- Add optional `pgs_bless module op-status <id> --json` if the current CLI parsing style supports it cleanly.

### Security Rules

- Only the module that created an operation can update/finish/fail it, unless the caller is core/admin.
- Enforce id opacity; do not allow caller-chosen ids except test hooks.
- Apply TTL and maximum operation count per module to avoid memory abuse.
- Cap stored `result` and `message`; large final data must use artifacts.
- Redact token-like values from status messages if adding generic logging.

### Implementation Steps

1. Done: Add `OperationStore` types and locking in the service/core layer.
2. Done: Wire store into module callback access through `PGS_ServicesV3.call_json`.
3. Done: Implement namespaced core JSON calls: `pgs.operation.create/get/update/finish/fail`.
4. Done: Replace `module op-status` placeholder with real lookup and CLI `--json`.
5. Done: Add opportunistic TTL/max-count cleanup.
6. Remaining: decide whether operation records need durable snapshots for long-running modules.
7. Remaining: add richer long-operation examples only when a bundled module genuinely needs asynchronous work.

### Tests

Unit tests:

- create/get operation lifecycle.
- update progress and message.
- finish with result.
- fail with error.
- expired operation returns clear error.
- max result size is rejected.
- module A cannot update module B's operation.

Integration tests:

- service smoke: create operation through a module/core test call, query with `module op-status`.
- JSON output parses and keeps stable fields.
- old modules and old `module call` are unaffected.

Acceptance criteria:

- `module op-status <id>` no longer returns the placeholder for valid ids.
- invalid/expired ids return deterministic errors.
- long-running module convention is documented with a minimal example.

## Workstream B: Global Artifact Store

Status: implemented first functional pass plus retention, integrity cleanup, download audit, sensitive-artifact metadata, and bounded byte quota policy. Modules can put artifacts through `pgs.artifact.put`; operators can inspect metadata with `module artifact get <id> --json`, download chunks with `--out`, clean the store with `module artifact cleanup [--expired|--all] [--verify]`, inspect health with `module artifact status [--verify]`, and configure policy with `module artifact policy`. Client downloads verify size/SHA-256, service chunk reads recompute size/SHA-256 before serving, metadata id/file-name mismatches fail closed, doctor reports ArtifactStore health including sensitive counts, and the health loop periodically removes expired artifacts when auto-cleanup is enabled. Remaining work is richer remote/UI prompts, remote-download audit policy, and durability polish.

### Design

Add a service-owned `ArtifactStore` under ProgramData, for example:

```text
%ProgramData%/ProcessGuard/artifacts/
  <artifact-id>.bin
  <artifact-id>.json
```

Metadata fields:

- `id`: opaque generated id, preferably `art_<128-bit random hex>`.
- `module`: producer module.
- `method`: producer method.
- `content_type`: MIME type or `application/octet-stream`.
- `filename`: safe display filename, sanitized.
- `size`: byte count.
- `sha256`: content hash.
- `created_ms`, `expires_ms`.
- `trace_id` and optional `operation_id`.
- `sensitive` and `sensitivity`: currently `medium` for backup-like artifacts and `high` for minidumps/dumps.

Default policy:

- max artifact size: defaults to 16 MB and is configurable through `module artifact policy --max-artifact-bytes`, bounded to 64 KB..64 MB.
- max total artifact bytes: defaults to 256 MB and is configurable through `module artifact policy --max-total-bytes`, bounded to 1 MB..1 GB and never below the single-artifact limit.
- default TTL: 24 hours for transient artifacts; configurable through `module artifact policy --ttl-ms` with a bounded range of 60 seconds to 7 days.
- sensitive TTL clamp: `high` artifacts are capped at 6 hours and `medium` artifacts at 24 hours even when the global policy is longer.
- no direct path exposure in protocol responses.

### API Shape

Core JSON calls via `PGS_ServicesV3.call_json`:

- `pgs.artifact.put`: accepts base64 content for small artifacts or a safe temporary file handle/path only if the path is already controlled by PGS.
- `pgs.artifact.get_meta`: returns metadata.
- `pgs.artifact.delete`: optional for producer cleanup.

For large payloads, avoid asking modules to pass huge base64 through the 64 KB JSON-RPC limit. Initial implementation can support small artifacts via base64 and reserve streaming/file-handoff for later, but the store itself should be designed for binary files.

CLI/protocol:

- `module artifact get <id> --json` returns metadata only, not raw bytes.
- `pgs_bless module artifact get <id> --out <path>` downloads by chunks and verifies size/SHA-256.
- `module artifact status [--verify] [--json]` reports `store_exists`, `root_secured`, count/bytes, expired/corrupt/orphaned counts, and effective policy.
- `module artifact policy [--ttl-ms N] [--max-artifact-bytes N] [--max-total-bytes N] [--auto-cleanup|--no-auto-cleanup] [--verify-on-status|--no-verify-on-status] [--json]` reads or updates the retention and quota policy.

### Security Rules

- Artifact ids are opaque; never use user input as a filename.
- All resolved paths must remain under the artifact root.
- Sanitize display filenames and reject path separators.
- Enforce per-artifact and total-store size limits.
- Validate stored hash before serving if practical.
- Do not serve expired artifacts.
- Restrict write access to trusted modules through the core callback path.

### Implementation Steps

1. Done: Add `ArtifactStore` metadata/content write path under the service state directory.
2. Done: Enforce per-artifact and total-store size limits, plus metadata expiry checks.
3. Done: Wire `pgs.artifact.put` and `pgs.artifact.get_meta` into module `call_json` callbacks.
4. Done: Replace `module artifact get` placeholder with real metadata/chunk retrieval.
5. Done: Extend CLI with `--json` metadata mode and `--out <path>` chunk download.
6. Done: Verify downloaded artifact size/SHA-256 in CLI and smoke test output.
7. Done: add cleanup command with expired/all/hash-verification modes and event recording.
8. Done: validate artifact content size/SHA-256 before every server-side chunk response.
9. Done 2026-07-20: promote cleanup into configurable retention policy (`ttl_ms`, `auto_cleanup`, `verify_on_status`).
10. Done 2026-07-20: expose store health through CLI `module artifact status`, Web `/api/artifact/status`, Qt report controls, and doctor `artifact_store` check.
11. Done 2026-07-20: fail closed on artifact metadata id/file-name mismatch and cover status/policy/doctor paths in smoke.
12. Done 2026-07-26: add periodic/background cleanup from the health loop, explicit artifact download audit events, `sensitive`/`sensitivity` metadata, dump high-sensitivity TTL, sensitive counts in status/doctor, and smoke coverage for audit/sensitive fields.
13. Done 2026-07-28: make max artifact bytes/max total bytes configurable within safe bounds, expose them through CLI/Web/Qt policy controls, persist them in `artifact_policy.cfg`, and cover them in smoke policy/status JSON checks.
14. Remaining: add stronger remote/Web/Qt download prompts and remote-download audit policy.

### Tests

Unit tests:

- put/get metadata/content.
- reject oversize artifact.
- reject unsafe filename.
- reject path traversal ids.
- expired artifact is not served.
- hash is recorded and stable.

Integration tests:

- module/core test creates artifact and returns id.
- `pgs_bless module artifact get <id> --out <file>` writes expected bytes.
- status/policy JSON output parses and reflects effective TTL/verification policy.
- doctor JSON includes an `artifact_store` check.
- release/runtime smoke includes artifact retrieval, policy, status, cleanup, and doctor visibility paths.
- smoke confirms sensitive artifact metadata/status fields and `artifact.download-complete` audit visibility.

Acceptance criteria:

- valid artifact id can be fetched with `--out`.
- invalid/expired artifact id returns deterministic error.
- no artifact API exposes raw filesystem paths.

## Workstream C: SBOM And Release Provenance Automation

Status: implemented first functional pass on 2026-07-19. `tools/write_release_manifest.ps1` is PowerShell 5.1-compatible and generates a release tree manifest, artifact checksums, and first-party SPDX JSON. `tools/build_installer.bat` invokes it after installer/zip creation. `.github/workflows/publish-release.yml` now verifies these metadata files, uploads them as release assets, and runs `actions/attest-build-provenance@v2` for installer, portable zip, checksums, manifest, and SBOM. Remaining work is code signing, a live GitHub release run to validate attestation permissions, and richer third-party dependency identification if a full dependency SBOM is required.

Goal: every GitHub release artifact is traceable to CI-built binaries and includes machine-readable component and hash metadata.

### Release Artifacts

Generate and publish:

- `ProcessGuardService-<version>-win64.zip` or current package name.
- `SHA256SUMS.txt` for every release file.
- `release-manifest.json` with file names, sizes, SHA-256, build commit, build time, toolchain versions, and module hashes.
- `sbom.spdx.json` or `sbom.cdx.json`.
- provenance/attestation produced by GitHub Actions artifact attestation or SLSA generator.

### CI Design

Add GitHub Actions workflow, for example `.github/workflows/release.yml`:

1. Trigger on tags and manual dispatch.
2. Set up MSYS2 MinGW64 and Qt6 dependencies.
3. Build with `tools/package_release.bat` or a CI-specific wrapper.
4. Run unit tests and `tools/release_smoke.ps1 -Fresh`.
5. Generate `release-manifest.json` and `SHA256SUMS.txt`.
6. Generate SBOM with Syft or Microsoft SBOM Tool.
7. Upload artifacts.
8. On tag builds, create or update GitHub Release from CI outputs only.
9. Generate artifact attestations/provenance.

### Tool Choice

Preferred fast path:

- `anchore/sbom-action` or Syft for SBOM.
- `actions/attest-build-provenance` for provenance.
- PowerShell script for `release-manifest.json` and `SHA256SUMS.txt`.

Fallback if SBOM tooling is noisy on Windows Qt DLLs:

- Generate a first-party manifest with hashes immediately.
- Add full SBOM in a second PR once dependency identification is stable.

### Implementation Steps

1. Done: add `tools/write_release_manifest.ps1` using .NET SHA256 API, with a PowerShell 5.1-compatible relative-path helper.
2. Done: wire metadata generation into `tools/build_installer.bat` after zip/installer creation.
3. Done: generate first-party SPDX JSON from the exact release tree.
4. Done: publish workflow uploads `SHA256SUMS.txt`, `release-manifest.json`, and `sbom.spdx.json` beside installer/zip.
5. Done: publish workflow requests GitHub build provenance attestation for installer, zip, checksums, manifest, and SBOM.
6. Done: root `VERSION` feeds batch packaging, Inno Setup, release workflow asset names, release name, and default tag.
7. Remaining: run a live workflow release and confirm attestation permissions/assets in GitHub UI.
8. Remaining: add code signing and, if needed, replace/augment first-party SBOM with Syft or Microsoft SBOM Tool output.
9. Remaining: make README/download snippets version-placeholder based so public docs do not drift from `VERSION`.

### Tests

Local tests:

- run `tools/package_release.bat`.
- run `tools/write_release_manifest.ps1 -Release release`.
- verify manifest hash values match actual files.
- run `tools/release_smoke.ps1 -Fresh`.

CI tests:

- build succeeds from a clean checkout.
- release smoke passes on GitHub runner.
- uploaded artifact contains `modules.lock`, schemas, manager manifest, and docs.
- SBOM file exists and is valid JSON.
- provenance/attestation step completes.
- publish workflow expected filenames match generated filenames for the same `PGS_VERSION`.

Acceptance criteria:

- No release artifact is produced from local stale `release/` state.
- CI build publishes hash manifest, SBOM, and provenance.
- Docs clearly instruct users to verify release artifacts against CI/GitHub Release metadata.
- One version value controls installer name, zip name, workflow release asset names, and user-facing docs.

## Workstream D: VM E2E Validation

Goal: verify the security-sensitive behavior in realistic Windows environments.

Matrix:

- LocalSystem service install/start/stop.
- Administrator console service run.
- Low-privilege account access denial and token behavior.
- PPL/test-signing enabled host with Sirius driver path.
- Remote Web with TLS and token checks.
- Cluster dashboard basic flow.
- Clean machine using release package only, no MSYS2 in PATH.

Tests:

- service install preserves intended persistent args.
- PPL module remains blocked without kernel/risk flags.
- trusted bundled modules load from `modules.lock`.
- tampered module hash is rejected.
- staging install cannot be loaded before confirmation.
- local Web Host/Origin/CSP/no-store behavior remains enforced.
- Job Object attach status appears in summary/list/get.

Acceptance criteria:

- `tools/vm_acceptance.ps1` passes on a clean VM.
- Any required manual PPL/test-signing step is documented with exact commands and expected output.

## Workstream E: Reliability Layer

Goal: move PGS from a basic restart tool toward an operator-grade guard that can explain failures, suppress destructive loops, and detect false-alive targets.

Scope:

- Done 2026-07-18: Quarantine / needs-attention state for restart failures instead of immediate guard retirement.
- Done 2026-07-18: Durable failure fields `QUARANTINED`, `LAST_FAILURE_B64`, `NEXT_RETRY_MS`, `FAILURE_COUNT`; bounded failure history remains future work.
- Done 2026-07-18: Health Check execution for `process`, `tcp`, and `http` probes, using a dedicated health worker thread that cannot block monitor or client workers.
- Done 2026-07-18: Windows-native notify surface for `guard.restart`, `guard.restart-failed`, `guard.quarantine`, `auth.token-set`, `module.load-failed`, PPL-related events, and other core events. Per operator decision, no chat software, webhook, mail, or remote messenger integration; default is Windows Event Log, optional local popup is opt-in.
- Done 2026-07-19: Web console can retry/clear quarantined guards and set/get/clear health checks; guard table shows quarantine/failure/health fields. Full guard detail timeline remains future work.
- Done 2026-07-20: Qt guard table now shows guard id, quarantine/failure-code/health fields, highlights quarantined rows, and can retry or clear quarantine for the selected guard.
- Done 2026-07-20: Qt guard table now includes a Health policy editor for `process`, `tcp`, and `http` probes, with set/get/clear actions wired through the existing `pgs_bless health-check` command path.
- Done 2026-07-20: `tools/smoke_test_pgs.sh` now covers TCP closed and HTTP unexpected-status health failures, uses a dynamic smoke port by default, and clears stale artifacts before artifact count assertions so repeated local runs remain deterministic.

Implementation notes:

1. Done: Add quarantine fields to persisted guard state and summary output.
2. Done: Change restart failure handling to persist quarantine instead of erasing the guard by default.
3. Done: Add `guard retry` and `guard clear-quarantine` protocol verbs and CLI wrappers.
4. Done: Implement health probes with per-probe timeout, failure thresholds, and `event`/`restart`/`quarantine` actions.
5. Done: Add bundled `notify` module and async `notifyLoop` delivery from structured `recordEvent()` calls.
6. Done 2026-07-19: Add Web controls for guard recovery, health-check config, notify config, report artifact operations, and artifact download.
7. Done 2026-07-19: Add Qt module-page convenience controls for scheduler, notify, report operation/artifact flows.
8. Done 2026-07-20: Add Qt guard table quarantine/failure-code/health columns and selected-guard retry/clear-quarantine actions.
9. Done 2026-07-20: Add Qt Health policy controls for process/tcp/http probes and health-check set/get/clear.
10. Done 2026-07-26: Add runtime `module permissive status|on|off` so the development escape hatch can be audited and revoked without editing state files by hand.

Tests:

- Done: restart-window exhaustion enters quarantine and can be cleared, covered by `tools/smoke_test_pgs.sh`.
- Done: process health probe reaches `healthy`, covered by `tools/smoke_test_pgs.sh`.
- Done 2026-07-20: TCP closed and HTTP unexpected-status probes reach `unhealthy`, covered by `tools/smoke_test_pgs.sh`.
- Done: Qt health policy UI builds through `cmake --build build\pgs_admin_qt --config Release` with explicit MSYS2/MinGW environment variables.
- Next: missing executable, access denied, hash mismatch, and session token failure enter quarantine with deterministic reason codes.
- Next: retry succeeds after the underlying issue is fixed and clears quarantine.
- Next: timeout/DNS health failures and `restart`/`quarantine` health actions get dedicated automated E2E coverage.
- Done: Windows-native notify delivery failure records `notify.delivery-failed` and never blocks core monitoring; smoke verifies `notify status` when modules are enabled.

## Workstream F: Doctor And Repair Center

Goal: give operators one consistent diagnostic surface across CLI, Qt, and Web instead of scattering checks through scripts and UI-specific code.

Diagnostics should cover:

- service install/running status and SCM recovery configuration.
- PGS token state, bootstrap token file location, and state directory ACL.
- listen port occupancy and PGS protocol reachability.
- modules root ACL, `modules.lock` hash coverage, PPL gate state, and permissive mode.
- Qt/OpenSSL/MinGW runtime closure for release trees.
- ProgramData state/module data directories and runtime DB migration status.
- release version consistency across workflow, installer, docs, and generated artifact names.

Repair commands should start conservative:

- `repair-state-acl`.
- `repair-modules-acl`.
- `repair-modules-lock` / bundled hash regeneration for local release trees.
- `clear-web-session` after loopback Web moves to cookie/session mode.

Acceptance criteria:

- `pgs_bless doctor --json` returns stable machine-readable fields.
- Done 2026-07-20: Qt and Web render the same doctor schema instead of duplicating checks.
- Deliberately broken ACLs, missing lockfiles, missing runtime DLLs, and port conflicts are detected with actionable messages.
- Done 2026-07-20: Qt Doctor / Repair page exposes `repair-state-acl`, `repair-modules-acl`, and `repair-modules-lock`, then refreshes doctor output after successful repair.

## Workstream G: Module Roadmap

## Workstream G0: Cluster Dashboard Productization

Status: partially completed on 2026-07-20. Cluster Web now supports node add/remove/edit/test, credential replacement/clearing without echoing saved credentials, immediate `/api/cluster/health` testing, and guard detail fields for quarantine/health/failure code. The registry still persists credentials through the existing DPAPI path where available.

Remaining work: add a real remote-gateway integration smoke using a second running Web node, add browser/DOM automation for add/edit/test/remove, and decide whether remote cluster mutations need a separate audit log beyond the local registry file. HTTP API automation now exists through `tools/cluster_api_smoke.ps1` and the expanded VM acceptance Cluster section.

Web console response productization status: completed first pass on 2026-07-20. The page now has a `Structured Result` area for module, scheduler, report, operation, artifact, metrics, backup, eventlog, and notify responses. It keeps raw Activity Log output while rendering parsed key-value/table views and auto-filling operation/artifact ids when returned by report/backup flows. Remaining Web work is browser DOM automation, stronger field-level validation, and grouped error guidance.

Implemented bundled first pass:

1. `metrics`: JSON and Prometheus-style metrics for guards, restarts, crash loops, events, and service uptime.
2. `backup`: local service-state snapshot export with token/artifact/temp exclusions and optional ArtifactStore output. Import/restore is intentionally not implemented yet.
3. `eventlog`: read local Windows Application Event Log entries with source filtering; notify remains the writer for PGS-origin events.
4. `dump`: explicit opt-in local minidump collection into ArtifactStore. Collection requires `confirm=1`, caps artifacts at 16 MB, and does not expose raw dump paths.
5. `service_guard`: local Windows SCM query/start/stop/ensure helper. Mutations require `confirm=1`, default-deny protected SCM services, support a persisted mutation allowlist, and emit audit events for policy changes and mutation denial/attempt/result.
6. `file_watch`: demand-driven local file change detector. Rules persist under the service data directory, `check` emits local PGS events for changed files, no background watcher thread or remote notification channel is opened, and rules are capped at 64 local absolute drive paths with UNC/device/ADS/Windows system-path denies.
7. `policy`: named guard-policy templates with optional apply through the service callback surface.
8. `remote_agent`: local node heartbeat/guard metadata surface for future cluster integration. It opens no listener and provides no chat/webhook integration.
9. `update`: local `release-manifest.json` verifier. It reads manifest `release_root`, verifies only the release tree `files` array, ignores artifact absolute paths for tree verification, and performs no network download or install.
10. `script_runner`: disabled-by-default restricted local runner. Operators must enable it, register scripts whose final path resolves under `modules\script_runner\scripts` in the service data directory, keep the registered SHA-256 unchanged, and pass `confirm=1` to run. Config/add/run denial/attempt/result emits local audit events.

Every bundled module now ships with manifest files, `modules.lock` capability/risk metadata, build script integration, release packaging, and smoke coverage. A first batch of high-risk negative tests now covers confirmation gates, service_guard protected-service/allowlist boundaries and mutation denial audit, script-runner path/default-disable/final-path/hash-tamper boundaries and run denial audit, file-watch unreadable and system-path denial paths, update tampering, artifact sensitivity, and download audit. Remaining work is production hardening: structured UI for the new modules, broader doctor visibility, stronger capability enforcement, signing/hash fail-closed policy, and deeper environment-specific negative tests.

## Workstream H: Local Transport And Client Runtime

Goal: make local management safer and shared client code harder to misuse. First runtime-hardening step is complete; named pipe transport remains the main security item.

Implementation steps:

1. Done: `PGSClient::sendCommand()` performs internal one-time Winsock initialization, so callers no longer need to call `WSAStartup()` first.
2. Add Windows named pipe transport with a DACL limited to SYSTEM and Administrators.
3. Keep loopback TCP during compatibility, but make new local clients prefer named pipe.
4. Eventually let installed-service mode disable loopback TCP unless explicitly requested.

Tests:

- `PGSClient` works from a fresh process without caller-managed `WSAStartup()`.
- non-admin users cannot connect to the named pipe.
- existing CLI/Qt/Web TCP behavior remains compatible during transition.

## Workstream I: Shared Code And Documentation Discipline

Goal: split duplicated, security-relevant helpers only where reuse reduces risk or drift, and keep implementation changes paired with documentation updates.

Candidate split points:

1. Structured JSON/schema helpers for registry, module manifest, lockfile, OperationStore, ArtifactStore, and Web/Qt result parsing. These should replace lightweight string extraction first on external-input and install paths.
2. Module trust/risk/capability policy helpers shared by CLI prompts, Web/Qt summaries, and service-side enforcement. The service remains the final authority; clients only preflight and explain.
3. Filesystem safety helpers for canonical path checks, staging directories, hash verification, ACL checks, atomic promote, and rollback.
4. Protocol/client response parsing helpers so CLI, Qt, Web, tests, and future module managers do not grow separate ad-hoc parsers.
5. Test command wrappers that always carry explicit MSYS2/MinGW64 environment variables instead of relying on ambient `PATH`.

Implementation discipline:

- Split code next to the feature that needs it; avoid broad refactors with no immediate caller.
- Keep public behavior stable while moving helpers behind existing command names and module APIs.
- Update docs in the same change whenever protocol, module trust, validation behavior, build/test commands, or operator-visible UI changes.
- All build/test examples must follow the explicit MSYS2/MinGW64 environment pattern in `docs/developer/BUILD.md` and `docs/developer/TESTING.md`.

Acceptance criteria:

- Security-sensitive parsing and install code has a single shared implementation per concern.
- Feature changes that affect operators update the matching docs before being considered complete.
- Existing smoke, unit, and release scripts remain runnable from an MSYS2 environment with explicit environment variables.

## Workstream J: Registry Module Install Closure

Goal: finish `pgs_bless module install <name>` as a safe registry-to-service install flow for the PGS_Model repository without letting the CLI bypass the core module loader.

Current state:

- Done 2026-07-26: CLI registry install now validates the PGS_Model registry with shared `PGModulePolicy` helpers, restricts DLL/manifest URLs to `https://raw.githubusercontent.com/...`, verifies SHA-256, validates downloaded `module.manifest.json`, applies trust/risk confirmation gates, and hands the staged DLL to service `module install --source registry --load`.
- Done 2026-07-26: the service install path is the final authority. It requires sidecar `module.manifest.json`, validates manifest name/ABI/risk/capabilities, requires `--confirm` for high/critical and community manifests, stages/promotes with rollback, and updates `modules.lock` through structured JSON rather than string scanning.
- Remaining closure is live registry/E2E hardening: a real non-bundled PGS_Model positive install, negative install fixtures, and code-signing/publisher policy.

Target flow:

1. CLI fetches `registry.json` from PGS_Model and validates it with the shared structured helper.
2. CLI downloads the selected DLL plus `module.manifest.json` into staging and verifies SHA-256 before any install action.
3. CLI displays source/trust/risk warnings and enforces `community` opt-in plus high/critical confirmation.
4. CLI calls service `module install` with the staged DLL path and `--source registry`; CLI does not mutate `modules/<name>/` directly.
5. Service revalidates DLL identity, sidecar manifest, risk confirmation, lockfile state, and performs promote/rollback.
6. Optional load happens only after service install succeeds and records audit events for install/load/failure.

Security rules:

- The service is fail-closed and is the final authority for install, lockfile mutation, and load.
- Registry and manifest parsing must be structured, bounded, and schema-validated before opening third-party modules.
- Hash-pinned install is acceptable before code signing; signing can later add a stricter policy for curated/community modules.
- Audit events should include registry source, module name/version, trust tier, risk, capabilities, hash, caller, and failure reason.

Tests:

- Done: `test_pgs_core` covers `PGModulePolicy` identifier/hash checks, manifest validation, registry validation, URL restrictions, and trust/risk install decisions.
- Done: explicit MSYS2/MinGW64 CMake build and CTest pass with `PGS_BUILD_TESTS=ON`.
- Remaining: positive install from a local registry fixture and live PGS_Model registry when a non-bundled module exists; negative E2E cases for hash mismatch, schema mismatch, missing fields, community without opt-in, high/critical without confirmation, staging promote failure, rollback, and reload after install.

## Recommended Next Order

1. Verify the Web loopback session-cookie change in a live VM/browser run before claiming the security release.
2. Add code signing and run one live GitHub release to validate metadata upload plus provenance attestation.
3. Decide whether OperationStore needs durable snapshots; add stronger Web/Qt/remote artifact download prompts/audit policy if artifacts become long-lived or remotely exposed.
4. Add deterministic quarantine reason codes and negative E2E coverage for missing exe, access denied, hash mismatch, session token failure, health timeout/DNS failures, and retry-after-fix; health restart/quarantine action E2E is now covered in smoke.
5. Productize UI responses further: add Web browser DOM automation, grouped error guidance, field-level validation, and Cluster browser automation for add/edit/test/remove.
6. Build out Doctor/Repair schema hardening and additional repair actions on top of the current shared CLI/Qt/Web doctor surface.
7. Productize the newly bundled modules: add structured Web/Qt views, doctor checks, and the remaining negative tests for dump size/permission/process-missing failures, file-watch rule/path policy, script-runner ACL/signature/RBAC, and update signing-ready rollback boundaries.
8. Run VM E2E last for the release candidate, after protocol and release surfaces stop changing.

Expected effort:

- Web session/cookie local-mode change: 0.5 to 1 day.
- Operation durability decision plus artifact audit/periodic cleanup: 0.5 to 1 day.
- Quarantine reason-code negative tests: 0.5 to 1.5 days.
- Doctor/Repair center MVP: 1 to 2 days depending on UI scope.
- New module production hardening and structured UI: 1 to 2 days depending on how much Web/Qt surface is included.
- Code signing plus live GitHub attestation validation: 0.5 to 1.5 days depending on certificate and repository permissions.
- VM E2E validation: 0.5 to 1 day once a suitable VM is available.

## Handoff Notes

- Keep `module op-status` and `module artifact get/status/policy/cleanup` backward-compatible with the command names now used by CLI/Web/Qt; do not expose raw artifact filesystem paths.
- Do not enable restart-hook execution in the same PR as operation/artifact stores; keep that risk isolated.
- Do not let manager extensions execute loader actions directly. They should continue returning plans only.
- Keep request/response defaults at 64 KB and invoke deadline default at 5 seconds, max 60 seconds.
- Prefer adding focused tests to existing `test_pgs_core` and `test_module_manager` before adding broad new harnesses.
- Treat `SECURITY_HARDENING_BACKLOG.md` as the source for security release blockers and `UNFINISHED_FEATURES_BACKLOG.md` as the source for feature/module backlog.
- Update these handoff documents whenever implementation changes one of their “current state” assumptions; stale handoff notes are more dangerous than missing notes.
