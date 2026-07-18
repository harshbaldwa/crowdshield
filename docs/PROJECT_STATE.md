# Crowdshield Project State

Canonical state timestamp: 2026-07-17T23:36:45-05:00

## Project identity and boundary

- Project/module/binary/container: `crowdshield`
- License: MIT
- Repository: `/home/vicky/homelab/containers/crowdshield`
- Git: initialized locally on branch `main`; no commits
- Allowed writes: this repository only
- Production deployment and production-service changes: prohibited
- Real CrowdSec decision writes: prohibited without explicit user approval

A pre-existing development credential remains at `secrets/lapi-credentials.yaml`. It is ignored by Git and was never printed or copied.

## Current milestone

Phases 1, 2, 3a, and 3b are complete. Phase 3c (runtime orchestration and operator interfaces) is active.

Detailed evidence and design baseline:

- `docs/discovery.md`
- `docs/architecture.md`
- `docs/api-assumptions.md`
- `docs/threat-model.md`
- `docs/plans/2026-07-17-crowdshield-implementation.md`

## Completed work

- Created the project directory structure.
- Added a secret/state/tool-cache-safe `.gitignore`.
- Initialized a local Git repository without committing.
- Inspected host, Docker, CrowdSec, LAPI, and `monitor` read-only.
- Verified CrowdSec v1.7.8 machine authentication with the existing development credential.
- Verified an empty, read-only, machine-authenticated alert query.
- Verified LAPI reachability from a peer on `monitor`.
- Inspected CrowdSec v1.7.8 Swagger and implementation source.
- Verified official Spamhaus DROP IPv4/IPv6 URLs, NDJSON format, observed counts, retrieval guidance, terms, and attribution.
- Verified the FireHOL Level 1 HTTPS URL, netset format, observed count/headers, update behavior, composition, and licensing uncertainty.
- Recorded the user's acceptance of the current Spamhaus DROP terms and FireHOL Level 1 aggregate-license uncertainty.
- Completed architecture, threat model, exact CrowdSec API assumptions, and a 23-task vertical TDD implementation plan.
- Selected `go.yaml.in/yaml/v3` v3.0.4 and `modernc.org/sqlite` v1.54.0 as the only direct non-standard runtime dependencies.
- Installed the official Go 1.26.5 linux/amd64 toolchain under ignored project-local `.tools/` after verifying its published SHA-256 checksum.
- Bootstrapped module `crowdshield`, build metadata, and the configuration-independent `version` command.
- Implemented strict bounded YAML configuration, explicit typed environment overrides, conservative defaults, and the complete checked-in configuration example.
- Implemented dedicated credential loading with regular-file, symlink, size, strict-permission, field, and internal-HTTP-host checks plus redacted formatting and mutable secret clearing.
- Implemented the closed-schema JSON logging boundary; raw errors, HTTP diagnostics, panic values/stacks, indicators, URLs, payloads, and secrets cannot be logged through its API.
- Implemented `net/netip` normalization, mapped-IPv4 handling, explicit special-purpose exclusions, exact deduplication with provenance, allowlist-overlap precedence, and covered-host suppression without CIDR expansion/merge.
- Implemented bounded Spamhaus JSONL, FireHOL netset, and plain parsers; metadata/truncation/family/malformed limits; safety filtering; absolute/relative feed checks; and deterministic snapshot versions.
- Implemented a bounded feed HTTP client with conditional requests, content checks, public-only DNS resolution/dialing, redirect limits, HTTPS downgrade prevention, and response-body clearing.
- Added representative local feed fixtures, MIT `LICENSE`, and `.env.example` without real secret values.
- Added embedded, checksummed SQLite migrations and transactional repositories for durable feed definitions, accepted snapshots, missing-grace state, deduplicated enforcement state, exact owned decisions, and recoverable LAPI operations.
- Implemented authoritative feed-definition updates, persisted conditional validators and minimum retrieval/backoff state, 304 handling, changed-definition handling, unsolicited-304 rejection after definition changes, and last-known-good preservation.
- Implemented the bounded CrowdSec machine-JWT client and a CrowdSec v1.7.8-shaped in-memory mock without requiring a bouncer key or broad decision routes.
- Implemented exact owned-decision persistence, create-verify-record-expire replacement, pending-operation recovery, live ownership verification before exact-ID expiration, and protection of unrelated/foreign decisions.
- Implemented deterministic feed priority and deduplication, missing grace, dry-run changed-definition previews without persistence/LAPI contact, independent feed and batch failure continuation, LAPI-outage state preservation, and non-overlapping reconciliation runs.
- Added a vertical integration test through real SQLite, the real reconciliation/client layers, and the protocol-shaped mock LAPI.
- Through the Phase 3b checkpoint, made no deployment, real CrowdSec write, Git commit, image publication, registry push, container/network change, or production-service/configuration modification.
- Added a closed `internal/ops` event/result/count vocabulary shared by scheduling, metrics, readiness, notifications, persistence, and the developing runtime. It cannot carry raw errors, URLs, credentials, payloads, identifiers, or network indicators.
- Implemented a deterministic, non-overlapping scheduler with injected clock/random sources, bounded startup jitter, anchored cadence with missed-run skipping, cancellation-safe timers, bounded exponential retry, operational lifecycle events, and reentrancy protection.
- Implemented a dependency-free, concurrency-safe Prometheus text registry with fixed descriptors, configured-feed label bounds, deterministic exposition, build information, HTTP method handling, and last-known-good active-decision gauge behavior.
- Implemented concurrency-safe liveness/readiness state, bounded readiness reasons, synchronization freshness and LAPI grace handling, fixed JSON handlers, and a cancellable observability HTTP server with bounded lifecycle events.
- Implemented optional ntfy delivery using fixed templates and bounded request/response handling, plus threshold, cooldown, deduplication, recovery, stale-sync, startup, and opt-in success policies. Notifications remain disabled by default.
- Added migration 2 and a validated SQLite notification-delivery-state repository. Persisted notification state contains only closed enum state, counters, and timestamps; it contains no destination, token, request body, message, raw error, or network indicator.
- Implemented bounded synchronization history, per-feed run results, interrupted-run recovery, monotonic typed runtime timestamps, and transactional age-based pruning of terminal Crowdshield history. Pruning preserves running work, pending/ambiguous journals, active decisions, desired or referenced enforcement objects, active/recent feed entries, and notification deduplication state.
- Added the runtime-composition package under `internal/app`, including a privacy boundary converting synchronization reports and categorized failures into validated bounded operational results while discarding raw error text.
- Added validated operational-event fan-out to the closed JSON logger, metrics registry, and readiness tracker. Invalid events are dropped before any sink.
- Added a durable synchronization job that orders run-history begin, engine execution, owned-decision counting, bounded result conversion, uncancelled history finalization, metrics/readiness/events, and deduplicated notifications. Cancelled runs finalize without entering notification state or transport.
- Added explicit cached LAPI startup authentication and an exact, bounded, canonical `crowdsec.allowed_http_hosts` config list for intentionally trusted plain-HTTP machine endpoints. Runtime never derives this allowlist from the credential file.
- Added production dependency composition across credentials, SQLite migrations/integrity, LAPI, reconciler, feed fetcher, sync engine, metrics, readiness, notifications, scheduler, observability HTTP, and the bound listener, with cleanup of every acquired resource on constructor failure.
- Added runtime startup recovery/restoration, active-decision gauge restoration, due-only transactional history pruning, startup authentication, partial-startup cleanup, worker failure handling, explicit cancellation coordination, ordered scheduler join, notification close, HTTP shutdown, network/listener cleanup, final SQLite close, credential destruction, and one-shot lifecycle protection.
- Wired persisted last-safe timestamps to stale-sync notification evaluation without adding a timer goroutine. Added idle-connection shutdown for ntfy transport.
- At the 2026-07-17T22:58:59-05:00 interim Phase 3c checkpoint, `go test -count=1 ./...` passed across all 19 current packages.
- At the 2026-07-17T23:36:45-05:00 runtime checkpoint, normal tests passed for `internal/app`, `internal/config`, `internal/lapi`, and `internal/notify`; `internal/app` passed race testing in 1.082s.
- Through this runtime checkpoint, made no deployment, real CrowdSec write, Git commit, image publication, registry push, container/network change, or production-service/configuration modification.

## Verified external interfaces

### CrowdSec LAPI v1.7.8

- Base URL in container: `http://crowdsec:8080`
- Health: `GET /health`
- Login: `POST /v1/watchers/login`
- Machine read/create route: `GET|POST /v1/alerts`
- Exact alert read: `GET /v1/alerts/{id}`
- Exact decision expiration: `DELETE /v1/decisions/{id}`
- Machine JWT lifetime: one hour
- Required machine User-Agent shape: `<name>/<version>`
- `GET /v1/decisions` requires a bouncer API key and will not be used
- No decision update endpoint exists
- Create response returns alert IDs; exact alert read returns decision IDs
- Delete-by-ID expires a decision by setting its end time to now

### Feed interfaces

- Spamhaus v4: `https://www.spamhaus.org/drop/drop_v4.json`, NDJSON, IPv4
- Spamhaus v6: `https://www.spamhaus.org/drop/drop_v6.json`, NDJSON, IPv6
- FireHOL Level 1: `https://iplists.firehol.org/files/firehol_level1.netset`, comment-prefixed netset text, IPv4

## Current architecture (partially implemented; Phase 3c active)

One Go process with:

1. standard-library CLI shell, build metadata, and closed-schema `log/slog` JSON logging (implemented; remaining commands pending);
2. strict YAML configuration plus environment overrides (implemented);
3. direct read-only machine credential loading (implemented);
4. bounded feed HTTP client and parser registry (implemented);
5. `net/netip` normalization, explicit unsafe-range table, CIDR allowlists, exact deduplication, and host-covered-by-range suppression (implemented);
6. transactional SQLite state and embedded migrations (implemented);
7. CrowdSec machine-JWT client and mock LAPI (implemented against the verified v1.7.8 contract; no real write exercised);
8. feed synchronization and reconciliation with last-known-good state, missing grace, exact ownership, replacement, and recovery semantics (implemented);
9. non-overlapping scheduler with startup jitter and bounded retry/backoff (implemented and focused-tested);
10. small standard-library HTTP server for metrics/health/readiness (implemented and focused-tested);
11. optional bounded ntfy client and durable delivery state (implemented and focused-tested);
12. bounded synchronization history/runtime timestamps and ownership-safe history pruning (implemented and focused-tested);
13. runtime production composition, bounded observer/log fan-out, startup recovery/authentication, due pruning, graceful cancellation, and ordered shutdown (implemented and focused/race-tested); operator CLI remains active Phase 3c work.

Direct non-standard runtime dependencies are limited to `go.yaml.in/yaml/v3` v3.0.4 (MIT/Apache-2.0) and `modernc.org/sqlite` v1.54.0 (BSD-3-Clause). Standard library code supplies CLI, HTTP, structured logging, metrics exposition, scheduling, and notifications.

## Key design decisions

- Never shell out to `cscli` from the application.
- Never require a bouncer key, Console enrollment, Central API blocklists, Docker socket, or direct CrowdSec DB access.
- Create LAPI decisions by posting Alerts containing Decisions.
- Represent ownership with local alert/decision IDs plus verified machine ID, exact origin, scenario namespace, scope, and value.
- Refresh with create-verify-record-expire replacement semantics; never expire first.
- Never use broad filtered delete routes.
- Batch alert submissions and cap all response bodies.
- Store complete feed provenance locally even when enforcement is deduplicated.
- Keep per-feed retrieval cadence separate from the six-hour reconciliation cadence. Spamhaus downloads should be persisted and limited to once per 24 hours while LAPI TTL refresh can use last-known-good state every six hours.
- Treat absolute feed bounds, relative change limits, empty/HTML/truncated content, and malformed-line thresholds as hard last-known-good preservation gates.
- A feed failure never increments missing counters and never causes removal.
- Allowlists override creation and refresh; newly overlapping allowlists trigger removal only after ownership verification.
- Logs and metric labels never contain IPs, CIDRs, URLs, credentials, response bodies, raw payloads, or unbounded error strings.
- Administrator-requested `explain` output may display its explicit argument, but must bypass application logging.

## Feed terms and remaining assumptions

- On 2026-07-17, the user explicitly accepted the current Spamhaus DROP Terms for this project.
- On 2026-07-17, the user explicitly accepted FireHOL Level 1's `license=unknown` aggregate status for this project.
- Exactly the requested Spamhaus IPv4, Spamhaus IPv6, and FireHOL Level 1 feeds may be enabled by default; no additional feeds may be silently enabled.
- The project must still preserve attribution, avoid data redistribution, and document the licensing uncertainty.
- Internal HTTP to CrowdSec is trusted only within the existing `monitor` Docker bridge.
- FireHOL's page summary count can differ from its downloaded record count; downloaded content is authoritative for validation.

## Testing status

Completed manual/read-only checks:

- live CrowdSec version and LAPI status;
- LAPI health from host and a `monitor` peer;
- development credential file safety/shape;
- machine login response shape;
- empty scenario-filtered machine alert query;
- feed endpoint status, headers, body size, structure, family, and parseability.

Historical Phase 3a milestone: 93 tests passed, 0 failed, 0 skipped across 7 packages.

Phase 3b milestone evidence:

- `go test -count=1 ./...` passed across all 13 packages listed below;
- `go vet ./...` passed;
- the exact aggregate number of individual tests was intentionally not collected and is not required. A denied optional counting pipeline was not retried or reformulated.

Packages in the successful normal suite:

- `crowdshield/cmd/crowdshield`
- `crowdshield/internal/buildinfo`
- `crowdshield/internal/config`
- `crowdshield/internal/credentials`
- `crowdshield/internal/feed`
- `crowdshield/internal/lapi`
- `crowdshield/internal/lapi/mock`
- `crowdshield/internal/logsafe`
- `crowdshield/internal/network`
- `crowdshield/internal/reconcile`
- `crowdshield/internal/state`
- `crowdshield/internal/syncer`
- `crowdshield/migrations`

Completed automated gates at this milestone:

- `go test -count=1 ./...`
- `go test -race -count=1 ./...`
- `go vet ./...`
- `go mod verify`
- checked-in configuration example load through the production strict loader
- log/credential failure-path canary tests

Interim Phase 3c evidence at `2026-07-17T22:58:59-05:00`:

- `go test -count=1 ./...` passed across all 19 current packages;
- focused race tests passed for `internal/metrics`, `internal/health`, `internal/notify`, and `internal/state` after their Phase 3c additions;
- the successful full suite includes the new `internal/app`, `internal/health`, `internal/metrics`, `internal/notify`, `internal/ops`, and `internal/scheduler` packages;
- notification SQLite restart/deduplication, notification/state concurrency, sync-history lifecycle/recovery, runtime-timestamp corruption handling, and exact ownership-safe pruning all have focused passing tests;
- this is an interim checkpoint, not the final Phase 3c gate: a complete post-runtime race run, `go vet`, module verification, privacy/leak checks, CLI verification, and lifecycle leak checks remain pending.

Runtime checkpoint evidence at `2026-07-17T23:36:45-05:00`:

- `go test -count=1 ./internal/app ./internal/config ./internal/lapi ./internal/notify` passed (`internal/app` 0.027s, `internal/config` 0.007s, `internal/lapi` 0.015s, `internal/notify` 0.014s);
- `go test -race -count=1 ./internal/app` passed in 1.082s;
- production composition was exercised with real temporary SQLite migrations, strict credentials, a local protocol-shaped login endpoint, the real scheduler/health server, a fake listener, cancellation, and leak-sensitive cleanup; no feed or real CrowdSec write occurred;
- deterministic fake lifecycle tests prove startup recovery/restoration/pruning ordering, state-failure cleanup, stopping-before-worker-cancellation, scheduler join before notification close, graceful HTTP stop, and store/credential cleanup order;
- this remains an interim checkpoint: CLI completion, current example/live config alignment for the exact internal HTTP host, full post-CLI suite/race/vet/module/privacy gates, and `max_history_entries` enforcement remain pending.

Required quality gates remain:

- `staticcheck ./...`
- `golangci-lint run`
- coverage report
- vulnerability scan
- SBOM generation
- secure container build and size measurement

The host still lacks global Go and the analysis/scanning tools. The verified project-local Go 1.26.5 toolchain and all Go caches/temporary files stay under ignored repository paths.

## Pending phases

### Phase 2: design (completed)

- Wrote `docs/architecture.md`.
- Wrote `docs/threat-model.md` with all required threats, mitigations, residual risks, invariants, and abuse cases.
- Wrote `docs/api-assumptions.md`, separating verified behavior from mock/real-write assumptions.
- Wrote the detailed 23-task vertical TDD plan under `docs/plans/`.
- Selected and documented minimal dependencies.
- Recorded the resolved feed-terms decision.

### Phase 3: core implementation

Use strict vertical TDD for (Phase 3b slices complete; Phase 3c active):

- configuration and environment overrides (complete);
- credential loading and redaction (complete);
- feed retrieval/parsers/validation (complete);
- network normalization/safety/allowlists/deduplication (complete);
- SQLite migrations and repositories (complete for Phase 3b state plus Phase 3c notification state, sync history, runtime timestamps, and age-based terminal-history pruning);
- ownership/reconciliation/missing grace/TTL/idempotency (complete);
- mock and typed LAPI client contracts (complete for Phase 3b; no real write exercised);
- orchestrated feed synchronization, definition changes, cadence/backoff, dry-run, and partial-failure behavior (complete);
- scheduler (implemented and focused-tested);
- operational event vocabulary, metrics, health, readiness, and bounded runtime fan-out/logging (implemented and focused-tested);
- ntfy transport, state machine, configuration, and persistence (implemented and focused-tested);
- bounded history/runtime timestamps and ownership-safe historical pruning (implemented and focused-tested; operator prune planning/confirmation remains CLI work);
- runtime composition and lifecycle (implemented and focused/race-tested, including production constructors, partial-startup cleanup, startup authentication/recovery/pruning, stale notification checks, cancellation, and ordered shutdown);
- CLI commands (pending after runtime composition).

### Phase 4: testing and hardening

- Run all required tests and static checks.
- Generate coverage.
- Run vulnerability/license checks.
- Perform one bounded review/fix pass.
- Do not use real LAPI writes.

### Phase 5: packaging and documentation

- Multi-stage non-root container.
- Read-only-root-compatible development Compose joining only external `monitor`.
- Do not run Compose.
- CI workflows for test/race/lint/static/build/container/SBOM/scan/license.
- Complete operator, deployment, security, attribution, credential, and development docs.

### Phase 6: final report

Report observed commands/results, sizes, coverage, scan findings, limitations, external user steps, optional real-LAPI test plan, rollback, and cleanup. Do not deploy or publish.

## Technical debt / open questions

- Feed terms are accepted for this project; future upstream term changes still require operator review.
- YAML v3.0.4 and modernc SQLite v1.54.0 are present and verified by the completed Phase 3b suite. Full vulnerability/license scanning remains pending for Phase 4.
- The mock LAPI covers authentication, create/read/expire, duplicate, recovery, and foreign-ownership contracts. Explicit runtime startup authentication, observer fan-out, and ordered lifecycle now have focused tests; no real write was exercised.
- Real LAPI origin-filter queries should not be a normal dependency due to a reported v1.7.8 issue.
- No real-LAPI write behavior has been exercised; that remains intentionally deferred to a separately approved plan.
- The age-based repository prune is implemented, but `database.max_history_entries` count enforcement and the operator-facing dry-run/`--confirm` prune workflow remain pending.
- Runtime production composition now requires an exact validated `crowdsec.allowed_http_hosts` entry for plain-HTTP credentials; checked-in and development configuration examples still need alignment before CLI/runtime verification.

## Immediate next step

Continue Phase 3c with strict vertical TDD on the operator CLI: wire `run` to the production runtime and signal cancellation, complete read-only `validate`, `status`, `sync --dry-run`, `explain`, `db check`, and bounded `prune` behavior with fixed exit codes/privacy guarantees, align configuration examples, then run the final Phase 3c suite/race/vet/module/privacy/leak gates.
