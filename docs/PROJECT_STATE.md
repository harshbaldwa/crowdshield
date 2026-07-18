# Crowdshield Project State

Canonical state timestamp: 2026-07-18T12:58:41-05:00

## Project identity and boundary

- Project/module/binary/container: `crowdshield`
- License: MIT
- Repository: `/home/vicky/homelab/containers/crowdshield`
- Git: branch `main`, tracking `origin/main` at `https://github.com/harshbaldwa/crowdshield.git`; the Phase 4 diff is reviewed locally before normal publication, and no history rewrite is permitted
- Allowed writes: this repository only
- Production deployment and production-service changes: prohibited
- Real CrowdSec decision writes: prohibited without explicit user approval

A pre-existing development credential remains at `secrets/lapi-credentials.yaml`. It is ignored by Git and was never printed or copied.

## Repository reconstruction checkpoint

Observed from the live repository at `2026-07-18T00:10:13-05:00` before new implementation work:

- `git status --short --branch` reported only `## main...origin/main`; there were no staged, unstaged, or nonignored untracked paths.
- `git log --oneline --decorate -n 10` reported the single commit `cf5949c (HEAD -> main, origin/main) first commit`.
- `git remote -v` reported `https://github.com/harshbaldwa/crowdshield.git` for fetch and push. A read-only `git ls-remote --heads origin` reported the same full commit for `refs/heads/main`.
- `git diff --stat`, `git diff --check`, `git diff --name-status`, and `git diff --cached --name-status` produced no findings. The live working tree is identical to the checked-in snapshot; nothing is implemented locally but uncommitted at this checkpoint.
- `git ls-files -ci --exclude-standard` found no tracked ignored files. The tracked artifact-pattern audit found only the intentional `secrets/.gitkeep`; the real development credential remains ignored by `/secrets/*`. Project-local Go toolchains and caches exist only under ignored repository paths.
- The committed tree contains no SQLite database, `.env`, local `config/crowdshield.yaml`, credential, generated binary, coverage output, or other build output.
- The verified ignored project-local Go 1.26.5 toolchain listed 20 packages: `crowdshield/cmd/crowdshield`, `crowdshield/internal/app`, `crowdshield/internal/buildinfo`, `crowdshield/internal/cli`, `crowdshield/internal/config`, `crowdshield/internal/credentials`, `crowdshield/internal/feed`, `crowdshield/internal/health`, `crowdshield/internal/lapi`, `crowdshield/internal/lapi/mock`, `crowdshield/internal/logsafe`, `crowdshield/internal/metrics`, `crowdshield/internal/network`, `crowdshield/internal/notify`, `crowdshield/internal/ops`, `crowdshield/internal/reconcile`, `crowdshield/internal/scheduler`, `crowdshield/internal/state`, `crowdshield/internal/syncer`, and `crowdshield/migrations`.
- The commit already contains runtime and CLI implementation files and tests. Their presence supersedes older statements that CLI implementation had not begun, but completeness remains unclaimed until the live code and required gates are inspected and run.
- This is an interim reconstruction checkpoint. No test, race, vet, module, privacy, or leak gate has been rerun yet in this session.

## Current milestone

Phases 1, 2, 3a, 3b, 3c, and 4 are complete. Phase 5 (packaging and operator documentation) is next; no deployment or real LAPI write has been authorized.

Detailed evidence and design baseline:

- `docs/discovery.md`
- `docs/architecture.md`
- `docs/api-assumptions.md`
- `docs/threat-model.md`
- `docs/plans/2026-07-17-crowdshield-implementation.md`

## Completed work

- Created the project directory structure.
- Added a secret/state/tool-cache-safe `.gitignore`.
- Initialized the Git repository and created the externally visible checkpoint commit `cf5949c` (`first commit`) on `main`; this checkpoint does not imply release or deployment readiness.
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
- Added migration 2 and a validated SQLite notification-delivery-state repository, then migration 3 to align its failure-category CHECK constraint with the canonical closed `internal/ops` vocabulary while preserving version-2 rows. Persisted notification state contains only closed enum state, counters, and timestamps; it contains no destination, token, request body, message, raw error, or network indicator.
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
- Replaced the executable's divergent command switch with the shared `internal/cli` dispatcher and production options. `main` now translates SIGINT/SIGTERM into context cancellation.
- Added production operator adapters for strict credential-aware configuration validation; daemon runtime; enforcing and dry-run one-shot synchronization; read-only status/feed/explanation queries; read-only database verification; and plan-by-default, exact-confirmation pruning.
- Dry-run synchronization authenticates to no LAPI endpoint, opens valid state immutably, falls back to an empty baseline only when state is absent, and never creates or mutates the database. Enforcing synchronization recovers interrupted runs, authenticates before feed fetch, records one bounded history result, preserves exact ownership behavior, and cleans up all clients/state.
- Read-only commands do not create or migrate state. `explain` canonicalizes only the operator's explicit argument, merges configured policy with persisted intent/ownership, and reports ambiguous ownership through exit 4 without logging the indicator.
- Added read-only, cascade-aware prune planning whose counts match applied deletion. Confirmed pruning is blocked while ambiguous operations exist and reports `mode=blocked`; active/referenced state remains protected.
- Enforced `database.max_history_entries` in both runtime and operator pruning, in addition to age retention, while preserving running sync rows. `go mod tidy` promoted the directly imported SQLite module and added its missing transitive checksums.
- Fixed two instrumentation-sensitive test synchronization gaps discovered by the full race gate: runtime readiness now waits for a served `/healthz`, and scheduler transition assertions wait for the next anchored timer. No production concurrency defect or race report was observed.
- Through the final Phase 3c checkpoint, made no deployment, feed-network enforcing run, real CrowdSec write, Git commit, image publication, registry push, container/network change, or production-service/configuration modification.
- Phase 4 hardened exact deletion proof: remote decision type must be `ban`, the exact ID must occur once, and live expiry must be present and parseable before exact-ID expiration.
- Phase 4 expanded ambiguous-operation recovery to the maximum seven-day decision lifetime and uses a 101st sentinel record to detect truncation while processing at most 100 results.
- Phase 4 disabled LAPI redirects so machine credentials cannot be forwarded through 307/308 responses, and wired net/http internal diagnostics through the existing sanitized logger with a safe discard fallback.
- Phase 4 aligned configuration validation with all downstream constructor bounds, rejects NaN malformed ratios, reduced the LAPI batch ceiling to the implemented 500, and removed the unused `crowdsec.retry` configuration surface rather than implying unsafe generic POST retries.
- Phase 4 added migration 3 for canonical notification failure categories, verified version-2 upgrade preservation, and replaced wrapping database enum conversions with closed checked decoding that rejects corrupted values.
- Phase 4 added direct tests for every deletion ownership predicate, LAPI redirect rejection, recovery query completeness, dry-run mutator guards, production operation-token generation, special-purpose DNS answers, configuration bounds, all notification failure categories, and schema upgrades.
- Phase 4 corrected the v1.7.8 create-response documentation to the verified string-ID array and addressed all default and focused Go analyzer findings, with narrow reviewed annotations only for intentional fixture/path behavior.
- Through Phase 4, made no deployment, real feed synchronization, real CrowdSec write, image publication, registry push, container/network change, or production-service/configuration modification.

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

## Current architecture (Phase 4 complete)

One Go process with:

1. standard-library CLI shell, build metadata, production action composition, and closed-schema `log/slog` JSON logging (implemented and verified);
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
12. bounded synchronization history/runtime timestamps and ownership-safe age/count history pruning with read-only planning and exact destructive confirmation (implemented and verified);
13. runtime production composition, bounded observer/log fan-out, startup recovery/authentication, due pruning, graceful cancellation, and ordered shutdown (implemented and verified by current normal/race suites);
14. production-backed `run`, `run --run-once`, `sync`, `status`, `validate-config`, `list-feeds`, `explain`, `prune`, and `db check` commands with stable exit codes, aggregate-only failures, immutable read paths, and signal cancellation.

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

Final Phase 3c evidence at `2026-07-18T01:17:32-05:00`:

- `go mod tidy -diff` produced no diff after applying required metadata cleanup, and `go mod verify` reported `all modules verified`;
- `go test -count=1 ./...` passed across all 20 packages; no aggregate individual-test count was collected or claimed;
- `go vet ./...` passed with no findings;
- `go build -trimpath ./cmd/crowdshield` succeeded, and the built binary returned `crowdshield dev (revision unknown, built unknown, go1.26.5 linux/amd64)` plus successful complete help dispatch;
- `go test -race -count=1 ./...` passed across all 20 packages after the two test synchronization repairs; the focused runtime lifecycle test additionally passed 10 normal and 5 race repetitions, and the focused scheduler transition test passed 20 race repetitions;
- `git diff --check` passed; the source credential-pattern scan and local database/key/log artifact scan reported zero matches;
- the final residual process/listener command was denied by the execution guard and was not retried or reformulated. Residual-process state therefore remains explicitly unverified, although all bounded test servers completed and no background process was intentionally started;
- no real feed synchronization, real LAPI write, deployment, container, network, registry, or production-service action occurred.

Final Phase 4 evidence at `2026-07-18T12:58:41-05:00`:

- `gofmt`, `go mod tidy -diff`, and `go mod verify` passed; module verification reported `all modules verified`.
- `go test -count=1 ./...`, `go test -race -count=1 ./...`, and `go vet ./...` passed across all 20 packages.
- `go build -trimpath -o .tmp/crowdshield ./cmd/crowdshield` succeeded. The ignored linux/amd64 binary measured 17,787,987 bytes, returned the expected development version, and dispatched complete help successfully.
- Atomic statement coverage is 73.7% aggregate. High-risk package coverage includes app 70.9%, config 70.0%, credentials 80.7%, feed 79.2%, LAPI 81.6%, network 79.8%, reconcile 70.3%, state 69.8%, and syncer 74.5%.
- Staticcheck v0.7.0, golangci-lint v2.12.2 default checks, and an expanded body-close/gosec/no-context/row-error/SQL-close profile all passed with zero issues.
- govulncheck v1.6.0 reported `No vulnerabilities found.`
- A CycloneDX 1.6 source SBOM was generated under ignored `.tmp/` with 9 external components. The built binary metadata and the material module list were captured separately under ignored `.tmp/`.
- The linux/amd64 binary includes 2 direct and 7 material transitive external modules. All are MIT, BSD-3-Clause, or YAML's MIT/Apache-2.0 dual license. `modernc.org/mathutil` is a go-licenses false negative but its cached v1.7.1 license is verified BSD-3-Clause; `modernc.org/libc` also carries third-party MIT material. Future binary/image distributions must include the applicable MIT/BSD notices. Graph-only modules are not compiled into the binary; the graph-only HashiCorp MPL-2.0 module creates no current distribution obligation.
- Tracked-artifact and privacy scans found no ignored tracked files, databases, executables, archives, private keys, JWTs, real tokens, or generated coverage/SBOM output. Two bearer-shaped matches are intentional redaction fixtures.
- Final private snapshots contained 586 process rows and 33 listener rows versus baseline counts of 585 and 33. No process executable resolved inside this repository and no listener mentioned Crowdshield or this repository.
- No real feed synchronization, real LAPI write, deployment, image publication, registry push, container/network change, or production-service/configuration modification occurred.

All Go analysis/scanning tools, SBOMs, binaries, caches, and reports remain under ignored project-local paths. Container build/size/image-SBOM/image-scan gates belong to Phase 5 because no container packaging exists yet.

## Pending phases

### Phase 2: design (completed)

- Wrote `docs/architecture.md`.
- Wrote `docs/threat-model.md` with all required threats, mitigations, residual risks, invariants, and abuse cases.
- Wrote `docs/api-assumptions.md`, separating verified behavior from mock/real-write assumptions.
- Wrote the detailed 23-task vertical TDD plan under `docs/plans/`.
- Selected and documented minimal dependencies.
- Recorded the resolved feed-terms decision.

### Phase 3: core implementation

Strict vertical TDD status (Phase 3 complete through 3c):

- configuration and environment overrides (complete);
- credential loading and redaction (complete);
- feed retrieval/parsers/validation (complete);
- network normalization/safety/allowlists/deduplication (complete);
- SQLite migrations and repositories (complete for notification state, sync history, runtime timestamps, and age/count-bounded terminal-history pruning plus read-only planning);
- ownership/reconciliation/missing grace/TTL/idempotency (complete);
- mock and typed LAPI client contracts (complete for Phase 3b; no real write exercised);
- orchestrated feed synchronization, definition changes, cadence/backoff, dry-run, and partial-failure behavior (complete);
- scheduler (implemented and normal/race-tested);
- operational event vocabulary, metrics, health, readiness, and bounded runtime fan-out/logging (implemented and focused-tested);
- ntfy transport, state machine, configuration, and persistence (implemented and focused-tested);
- bounded history/runtime timestamps and ownership-safe historical pruning (implemented and verified, including immutable planning, exact confirmation, ambiguity blocking, and configured count retention);
- runtime composition and lifecycle (implemented and full-suite/race-tested, including production constructors, partial-startup cleanup, startup authentication/recovery/pruning, stale notification checks, signal cancellation, and ordered shutdown);
- production CLI command composition, privacy, read-only guarantees, stable exit codes, dry-run behavior, enforcing one-shot behavior, and operator lifecycle (implemented and verified).

### Phase 4: testing and hardening (completed)

- Completed normal, race, vet, formatting, module-integrity, build, CLI-smoke, and atomic coverage gates.
- Completed Staticcheck, default and expanded golangci-lint, govulncheck, CycloneDX source SBOM, and material dependency/license review.
- Completed one bounded manual security/correctness review and test-first repair pass.
- Completed privacy, tracked-artifact, process, and listener checks.
- Used no real LAPI writes, deployment, Compose, registry, or production action.

### Phase 5: packaging and documentation

- Multi-stage non-root container.
- Read-only-root-compatible development Compose joining only external `monitor`.
- Do not run Compose.
- CI workflows for test/race/lint/static/build/container/SBOM/scan/license.
- Complete operator, deployment, security, attribution, credential, and development docs.

### Phase 6: final report

Report observed commands/results, sizes, coverage, scan findings, limitations, external user steps, optional real-LAPI test plan, rollback, and cleanup. Do not deploy or publish.

## Technical debt / open questions

- Feed terms are accepted for this project; future upstream term changes still require operator review. FireHOL Level 1 remains an explicitly accepted aggregate with `license=unknown`, so attribution and non-redistribution guidance must remain prominent.
- Source vulnerability and material license reviews are complete. Phase 5 binary/image distributions must add a third-party-notices artifact covering the applicable MIT/BSD notices, including modernc libc's third-party MIT material.
- The mock LAPI covers authentication, create/read/expire, duplicate, recovery, and foreign-ownership contracts. No real write was exercised; all write-shape assumptions in `docs/api-assumptions.md` remain subject to a separately approved minimal real-LAPI plan.
- Real LAPI origin-filter queries should not be a normal dependency due to a reported v1.7.8 issue.
- Generic request-level LAPI retry is intentionally not exposed: retrying ambiguous POST creates would be unsafe. Authentication retries once after 401 and journal recovery handles ambiguous creates. Any future safe-method retry policy requires a separate design and tests.
- Age/count retention, immutable prune planning, ambiguity blocking, and exact-confirmation application are implemented and verified; older notes that list these as pending are superseded.
- Runtime production composition requires an exact validated `crowdsec.allowed_http_hosts` entry for plain-HTTP credentials. Deployment-specific configuration still requires operator review during packaging; no live configuration was changed here.
- `README.md`, operator/deployment documentation, third-party notices, container/Compose files, CI, image SBOM/scanning, and measured non-root/read-only-root container behavior remain Phase 5 work.
- Final process/listener inspection found no repository executable process or Crowdshield listener. No background process was intentionally launched.

## Immediate next step

Proceed to Phase 5 packaging and operator documentation: add the missing README/operator guidance and notices, then build and scan a multi-stage non-root image and development Compose definition without running or deploying Compose. Preserve the no-real-LAPI-write and no-production-change boundary unless separately approved.
