# Remaining Upgrade Plan

This document captures the unfinished work after the module ecosystem and security-kernel upgrade. It is intended as a handoff plan for the next development thread.

## Current Status

Completed in the current repository state:

- Module protocol v3 foundation: JSON-RPC style `module invoke`, ABI v3 `PG_InvokeJson`, `PGS_ServicesV3`, request/response size and deadline policy.
- PPL decoupling: PPL is treated as a critical-risk module gated by explicit kernel/risk flags, while legacy `ppl set/get/clear` remains a CLI compatibility layer.
- Module trust foundation: `module.manifest.json`, `modules.lock`, staging install, rollback, reload/disable/verify commands, capability/risk checks, and protected loader ownership in core.
- Module manager extension foundation: separate `module_managers/` directory, manager manifest/schema, and ABI declarations; managers can advise but cannot bypass the core loader.
- Doctor and UI scope: CLI/Web/Qt doctor surface, v3 guard fields, module page risk/trust details, and existing visual style preserved.
- Guard protocol upgrades: service-side `start-register`, health-check config, restart-hook config storage with execution disabled, guard groups, paused state, and runtime profile fields.
- Build and release foundation: top-level CMake, build script updates, package script rebuild behavior, bundled `modules.lock`, release smoke coverage, and release docs/schema packaging.

Known intentionally incomplete areas:

- `module op-status` and `module artifact get` are stable protocol slots, but the global operation/artifact backing stores are not implemented yet.
- `restart-hook` only stores structured config and returns `execution=disabled`; no script or module action execution is enabled.
- SBOM and release provenance are documented as goals, but not automated as CI artifacts yet.
- VM-level E2E checks for LocalSystem, low-privilege service accounts, real PPL/test-signing, remote TLS, and clean installers still need dedicated environment runs.

## Workstream A: Global Operation Store

Goal: make long-running module work observable through `module op-status <operation-id>` without blocking worker threads.

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

1. Add `OperationStore` types and locking in service/core layer.
2. Wire store into `PGS` or `PGSProtocol` where module callbacks can access it.
3. Implement namespaced core JSON calls via `PGS_ServicesV3.call_json`.
4. Replace `module op-status` placeholder with real lookup.
5. Add cleanup tick or opportunistic cleanup on create/get.
6. Add CLI `--json` support if low-risk.
7. Add example long-operation behavior to one bundled module only if it does not bloat scope; otherwise add a test-only module path.

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

Goal: allow modules to return large or binary outputs as artifact ids instead of embedding data in JSON-RPC responses.

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

Default policy:

- max artifact size: start with 16 MB unless a config value already exists.
- max total artifact bytes: start with 256 MB under ProgramData.
- default TTL: 24 hours for transient artifacts.
- no direct path exposure in protocol responses.

### API Shape

Core JSON calls via `PGS_ServicesV3.call_json`:

- `pgs.artifact.put`: accepts base64 content for small artifacts or a safe temporary file handle/path only if the path is already controlled by PGS.
- `pgs.artifact.get_meta`: returns metadata.
- `pgs.artifact.delete`: optional for producer cleanup.

For large payloads, avoid asking modules to pass huge base64 through the 64 KB JSON-RPC limit. Initial implementation can support small artifacts via base64 and reserve streaming/file-handoff for later, but the store itself should be designed for binary files.

CLI/protocol:

- `module artifact get <id>` streams bytes to stdout only when safe.
- Prefer adding `pgs_bless module artifact get <id> --out <path>` for normal usage.
- `--json` should return metadata only, not raw bytes.

### Security Rules

- Artifact ids are opaque; never use user input as a filename.
- All resolved paths must remain under the artifact root.
- Sanitize display filenames and reject path separators.
- Enforce per-artifact and total-store size limits.
- Validate stored hash before serving if practical.
- Do not serve expired artifacts.
- Restrict write access to trusted modules through the core callback path.

### Implementation Steps

1. Add `ArtifactStore` with metadata read/write and atomic file writes.
2. Add size/TTL cleanup.
3. Wire `pgs.artifact.put` and metadata lookup into module `call_json` service callbacks.
4. Replace `module artifact get` placeholder with real retrieval.
5. Extend CLI with `--out <path>` and metadata mode.
6. Document artifact id response pattern in module ecosystem docs.

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
- stdout mode works for text artifacts or is explicitly blocked for binary if that is the chosen policy.
- release smoke includes one artifact retrieval path.

Acceptance criteria:

- valid artifact id can be fetched with `--out`.
- invalid/expired artifact id returns deterministic error.
- no artifact API exposes raw filesystem paths.

## Workstream C: SBOM And Release Provenance Automation

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

1. Add `tools/write_release_manifest.ps1` using .NET SHA256 API, not `Get-FileHash`.
2. Add CI workflow for build/test/package/artifact upload.
3. Add SBOM generation action.
4. Add provenance/attestation step.
5. Update README and service guide release sections with verification instructions.
6. Add a CI smoke job that fails if `release/modules/modules.lock` has fewer than 5 modules or missing 64-char hashes.

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

Acceptance criteria:

- No release artifact is produced from local stale `release/` state.
- CI build publishes hash manifest, SBOM, and provenance.
- Docs clearly instruct users to verify release artifacts against CI/GitHub Release metadata.

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

## Recommended Next Order

1. Implement OperationStore first, because it defines the long-task status contract.
2. Implement ArtifactStore second, because operations can reference artifact ids.
3. Add release manifest/SBOM/provenance automation third, because package script and release smoke are already stable.
4. Run VM E2E last, after the protocol and release surfaces stop changing.

Expected effort:

- OperationStore + tests: 1 to 1.5 days.
- ArtifactStore + tests: 1 to 1.5 days.
- SBOM/provenance CI: 0.5 to 1.5 days depending on GitHub runner/Qt setup.
- VM E2E validation: 0.5 to 1 day once a suitable VM is available.

## Handoff Notes

- Keep `module op-status` and `module artifact get` backward-compatible with their current placeholder command names.
- Do not enable restart-hook execution in the same PR as operation/artifact stores; keep that risk isolated.
- Do not let manager extensions execute loader actions directly. They should continue returning plans only.
- Keep request/response defaults at 64 KB and invoke deadline default at 5 seconds, max 60 seconds.
- Prefer adding focused tests to existing `test_pgs_core` and `test_module_manager` before adding broad new harnesses.
