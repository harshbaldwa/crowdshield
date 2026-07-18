# Crowdshield Implementation Plan

Date: 2026-07-17

> Execution note: this plan uses test-driven development. The user explicitly prohibited Git commits unless separately requested, so every otherwise natural commit checkpoint is recorded as a verification checkpoint only. Do not commit.

## Goal

Build and verify a production-quality local Go service that safely retrieves three configured threat feeds, maintains SQLite last-known-good/provenance/ownership state, and reconciles only Crowdshield-owned finite CrowdSec LAPI decisions.

## Architecture

One statically buildable Go process with standard-library CLI/HTTP/logging, strict YAML, CGO-free SQLite, bounded feed/LAPI/ntfy clients, pure normalization/planning logic, an operation journal for remote mutation recovery, and a single non-overlapping scheduler.

Design references:

- `docs/discovery.md`
- `docs/architecture.md`
- `docs/api-assumptions.md`
- `docs/threat-model.md`

## Technology

- Go 1.26.5
- `go.yaml.in/yaml/v3`
- `modernc.org/sqlite`
- standard library for all other runtime features
- Docker/BuildKit for container verification

## Global test discipline

For each task:

1. Add the smallest failing test.
2. Run only that package/test and observe the expected failure.
3. Implement the minimum correct behavior.
4. Re-run the focused test.
5. Run `go test ./...` before moving to the next vertical slice.
6. Refactor only while green.
7. Do not weaken a security assertion to make a test pass.

Normal test output must not print indicators or secret canaries.

## Task 1: Bootstrap the repository and local toolchain

**Files**

- Create: `go.mod`
- Create: `go.sum`
- Create: `LICENSE`
- Create: `README.md`
- Create: `internal/buildinfo/buildinfo.go`
- Create: `internal/buildinfo/buildinfo_test.go`
- Create: `cmd/crowdshield/main.go`
- Update: `.gitignore`

**Steps**

1. Download the official Go 1.26.5 Linux archive into ignored `.tools/`.
2. Verify SHA-256 exactly against `docs/discovery.md` before extraction.
3. Keep `GOCACHE`, `GOMODCACHE`, `GOPATH`, and installed tool binaries under ignored project directories.
4. Initialize module `crowdshield` with Go 1.26.
5. Add failing build-info/version tests.
6. Implement immutable build fields populated by `-ldflags` with safe development defaults.
7. Add the minimal entry point and verify `version` behavior.

**Focused verification**

```sh
.tools/go/bin/go test ./internal/buildinfo ./cmd/crowdshield
.tools/go/bin/go vet ./internal/buildinfo ./cmd/crowdshield
```

## Task 2: Strict configuration and environment overrides

**Files**

- Create: `internal/config/types.go`
- Create: `internal/config/load.go`
- Create: `internal/config/env.go`
- Create: `internal/config/validate.go`
- Create: `internal/config/duration.go`
- Create: `internal/config/config_test.go`
- Create: `internal/config/env_test.go`
- Create: `testdata/config/*.yaml`
- Create: `config/config.example.yaml`
- Create: `.env.example`

**Tests first**

- valid complete default config;
- unknown YAML field and second document rejection;
- oversized file rejection;
- duplicate/invalid feed name rejection;
- invalid URL/scheme/userinfo/fragment rejection;
- duration/count/ratio/batch/readiness consistency;
- CIDR allowlist canonicalization and invalid entry index error;
- explicit supported env overrides;
- unknown `CROWDSHIELD_` override rejection;
- ntfy token never appears in errors/string formatting;
- no mutation by `validate-config`.

**Core interfaces**

```go
type Loader struct { MaxBytes int64; LookupEnv func(string) (string, bool) }
func (l Loader) Load(path string) (Config, error)
func (c Config) Validate() error
```

**Focused verification**

```sh
.tools/go/bin/go test ./internal/config -run 'TestLoad|TestValidate|TestEnvironment'
```

## Task 3: Credential loading and redaction boundary

**Files**

- Create: `internal/credentials/credentials.go`
- Create: `internal/credentials/credentials_test.go`
- Create: `testdata/credentials/*.yaml` with canaries only

**Tests first**

- required `url`, `login`, `password`;
- 64 KiB limit;
- missing/malformed/unknown fields;
- symlink/non-regular rejection where supported;
- group/other permission rejection;
- URL validation;
- credential type cannot reveal password via `String`, `GoString`, or errors;
- parser failure and normal log path omit canary credential/token.

**Focused verification**

```sh
.tools/go/bin/go test ./internal/credentials ./internal/logsafe
```

## Task 4: Privacy-safe structured logging

**Files**

- Create: `internal/logsafe/category.go`
- Create: `internal/logsafe/event.go`
- Create: `internal/logsafe/logger.go`
- Create: `internal/logsafe/logger_test.go`

**Tests first**

- JSON shape and allowed fields;
- bounded feed/operation/category validation;
- injected raw error never emitted;
- indicator, CIDR, URL, password, token, auth-header, API-body, SQLite-row canaries absent;
- panic recovery emits category only and no panic value/stack;
- HTTP server error adapter emits category only.

Avoid a generic `logger.Error(msg, ...any)` API in application packages.

## Task 5: Network normalization, safety, allowlists, and dedupe

**Files**

- Create: `internal/network/entry.go`
- Create: `internal/network/safety.go`
- Create: `internal/network/allowlist.go`
- Create: `internal/network/dedupe.go`
- Create: `internal/network/*_test.go`

**Tests first**

- IPv4/IPv6 canonicalization;
- CIDR masking;
- mapped IPv4 behavior;
- exact duplicate provenance;
- bare host vs `/32`/`/128` semantics;
- host covered by imported range;
- overlapping CIDRs retained;
- adjacent CIDRs not merged;
- every explicit special-purpose range plus boundary neighbors;
- broad prefix overlapping a special range rejected;
- allowlist exact/contains/contained/partial overlap precedence;
- deterministic primary contributor.

**Pure interface**

```go
type Candidate struct { Prefix netip.Prefix; Kind Kind; FeedID int64 }
type Desired struct { Prefix netip.Prefix; Scope Scope; Contributors []int64; Suppression Suppression }
func BuildDesired(candidates []Candidate, allow []netip.Prefix) ([]Desired, Summary)
```

## Task 6: Feed parser registry and fixtures

**Files**

- Create: `internal/feed/parser.go`
- Create: `internal/feed/spamhaus.go`
- Create: `internal/feed/netset.go`
- Create: `internal/feed/plain.go`
- Create: `internal/feed/parser_test.go`
- Create: `internal/feed/spamhaus_test.go`
- Create: `internal/feed/netset_test.go`
- Create: `testdata/feeds/*`

**Tests first**

- comments, blanks, individual addresses, CIDRs, inline comments;
- Spamhaus metadata first, NDJSON records/count/family/timestamp/final newline;
- FireHOL netset comments/final newline;
- malformed-line threshold below/equal/above;
- line and token limit;
- empty body;
- truncated final record;
- duplicate records;
- fixture tests for IPv4 and IPv6;
- parser errors expose only entry index/category.

Fixtures use IANA documentation ranges and synthetic metadata, never copied production feed bodies.

## Task 7: Bounded SSRF-resistant feed fetcher and validation

**Files**

- Create: `internal/feed/fetcher.go`
- Create: `internal/feed/transport.go`
- Create: `internal/feed/validate.go`
- Create: `internal/feed/fetcher_test.go`
- Create: `internal/feed/validate_test.go`

**Tests first with `httptest` and injected resolver/dialer**

- timeout and cancellation;
- redirect count and redirect to unsafe destination;
- HTTP denied/explicitly allowed;
- private/local/special DNS results rejected;
- non-2xx;
- reliable content-type rejection;
- HTML media type and sniffed HTML;
- empty response;
- declared/actual size limit;
- final-byte truncation;
- 304 conditional retrieval;
- identifiable User-Agent;
- expected min/max;
- growth boundary;
- shrink retained-fraction boundary;
- failed validation preserves supplied previous snapshot;
- raw body/URL/indicator absent from logs/errors.

## Task 8: SQLite migrations and core state repositories

**Files**

- Create: `migrations/embed.go`
- Create: `migrations/001_initial.sql`
- Create: `internal/state/open.go`
- Create: `internal/state/migrate.go`
- Create: `internal/state/models.go`
- Create: `internal/state/feed.go`
- Create: `internal/state/sync.go`
- Create: `internal/state/state_test.go`
- Create: `internal/state/migration_test.go`
- Create: `testdata/database/*` only where a migration fixture is needed

**Tests first**

- fresh migration/schema version/checksum;
- repeated migration idempotency;
- foreign keys enabled;
- WAL/busy timeout/one connection;
- quick-check corruption failure via injectable check where deterministic;
- accepted feed snapshot transaction;
- rollback after injected mid-transaction failure;
- no credential columns/data;
- read-only dry-run mode causes no mutation;
- safe shutdown;
- migration from prior fixture when migration 2 is introduced.

Use temporary test directories; never open the development credential.

## Task 9: Feed state and missing-grace transitions

**Files**

- Create: `internal/state/provenance.go`
- Create: `internal/state/enforcement.go`
- Create: `internal/state/history.go`
- Create: `internal/state/provenance_test.go`
- Create: `internal/reconcile/plan.go`
- Create: `internal/reconcile/plan_test.go`

**Tests first**

- first successful snapshot;
- present resets missing;
- one successful miss retains provenance;
- second successful miss deactivates by default;
- failed/empty/suspicious feed does not advance missing;
- one feed disappears while duplicate contributor remains;
- allowlist suppresses desired object immediately;
- host-covered suppression;
- deterministic, idempotent plan;
- disabled feed behavior;
- history retention bounds.

## Task 10: Mock CrowdSec LAPI and typed client

**Files**

- Create: `internal/lapi/models.go`
- Create: `internal/lapi/client.go`
- Create: `internal/lapi/auth.go`
- Create: `internal/lapi/errors.go`
- Create: `internal/lapi/client_test.go`
- Create: `internal/lapi/mock_test.go` or `internal/lapi/lapitest/server.go`

**Mock scenarios**

- auth success/failure/expiry/refresh;
- exact User-Agent;
- create Alert batch and return Alert IDs;
- exact Alert read and decision IDs;
- exact delete/expiration;
- duplicate decisions;
- foreign decisions;
- bounded list/limit;
- 429, 500, timeout, malformed/oversized response;
- ambiguous create timeout after insertion.

**Client tests**

- response cap;
- one auth retry on 401;
- bounded retry/Retry-After;
- create/get/delete models match `docs/api-assumptions.md`;
- raw request/response and indicators absent from errors/logs;
- no bouncer `/v1/decisions` GET or bulk delete method exists.

## Task 11: Operation journal and synchronization engine

**Files**

- Create: `migrations/002_operations.sql`
- Create: `internal/state/operations.go`
- Create: `internal/reconcile/engine.go`
- Create: `internal/reconcile/ownership.go`
- Create: `internal/reconcile/recovery.go`
- Create: `internal/reconcile/engine_test.go`
- Create: `internal/reconcile/ownership_test.go`
- Create: `internal/reconcile/recovery_test.go`

**Tests first**

- create new decisions in bounded batches;
- finite 25-hour TTL;
- no refresh outside threshold;
- create-verify-expire refresh ordering;
- metadata-change refresh;
- no duplicate steady state;
- idempotent repeated sync;
- partial create failure recovery;
- ambiguous timeout recovery by operation token;
- delete only exact verified ownership;
- every ownership predicate mismatch blocks delete;
- foreign behavioral/AppSec/manual/Console/other-origin decision protection;
- allowlist removal;
- failed LAPI leaves recoverable local intent;
- dry-run produces plan and zero remote/persistent writes.

## Task 12: Orchestrated feed synchronization

**Files**

- Create: `internal/app/sync.go`
- Create: `internal/app/sync_test.go`

**Tests first**

- independent feed failure does not stop others;
- cadence skip reuses last-known-good state;
- Spamhaus 24-hour persisted minimum;
- retry/backoff avoids hammering;
- safe-success vs full-success timestamps;
- database failure aborts mutation safely;
- LAPI failure category/count;
- selected `--feed` behavior;
- no selected/healthy state corruption on partial failure.

## Task 13: Deterministic scheduler and graceful shutdown

**Files**

- Create: `internal/scheduler/clock.go`
- Create: `internal/scheduler/scheduler.go`
- Create: `internal/scheduler/scheduler_test.go`

**Tests first**

- immediate run with zero jitter;
- bounded deterministic startup jitter;
- run-immediately false;
- interval measured after completion;
- concurrent triggers never overlap;
- cancellation interrupts wait and in-flight context;
- graceful stop joins worker;
- no retry storm.

Use fake clock/random source; no wall-clock sleeps in unit tests.

## Task 14: Metrics registry

**Files**

- Create: `internal/metrics/registry.go`
- Create: `internal/metrics/metrics.go`
- Create: `internal/metrics/prometheus.go`
- Create: `internal/metrics/metrics_test.go`

**Tests first**

- every requested metric exists;
- counters/gauges/histogram exposition valid;
- feed/mode/operation enum labels only;
- configured feed cardinality bound;
- attempted indicator/URL/error/job-ID label rejected;
- no secret values;
- concurrent updates race-safe.

## Task 15: Health, readiness, and HTTP server

**Files**

- Create: `internal/health/state.go`
- Create: `internal/health/handlers.go`
- Create: `internal/health/server.go`
- Create: `internal/health/health_test.go`

**Tests first**

- health always concise/alive after server start;
- config/db/auth failure readiness reasons;
- initial LAPI authentication requirement;
- LAPI unreachable grace without immediate flap;
- never-synced and stale-sync failures;
- optional single feed failure does not immediately unready;
- content type/status/JSON shape;
- no indicators/errors/paths/credentials;
- server read/header/write/idle limits;
- graceful shutdown.

## Task 16: ntfy failure/recovery state machine

**Files**

- Create: `internal/notify/client.go`
- Create: `internal/notify/events.go`
- Create: `internal/notify/state.go`
- Create: `internal/notify/notify_test.go`

**Tests first**

- disabled is no-op;
- bearer token sent but never logged;
- timeout/status/response-size handling;
- minimum severity;
- feed failure threshold crossing only once;
- LAPI failure;
- suspicious change;
- stale full sync;
- one recovery after notified failure;
- startup and optional first success;
- routine success disabled default;
- payload has no indicator/URL/error/credential canaries;
- notification failure does not fail sync or recurse.

## Task 17: CLI and application lifecycle

**Files**

- Create: `internal/cli/root.go`
- Create: `internal/cli/run.go`
- Create: `internal/cli/sync.go`
- Create: `internal/cli/status.go`
- Create: `internal/cli/config.go`
- Create: `internal/cli/feeds.go`
- Create: `internal/cli/explain.go`
- Create: `internal/cli/prune.go`
- Create: `internal/cli/version.go`
- Create: `internal/cli/cli_test.go`
- Update: `cmd/crowdshield/main.go`
- Create: `internal/app/app.go`
- Create: `internal/app/app_test.go`

**Tests first**

- required commands and help/usage;
- `run --run-once`, `sync --dry-run`, `sync --feed`;
- status fields and no secret/indicator leakage;
- validate-config no mutation/contact;
- list-feeds state;
- explain exact/contributors/allowlist/covering-range/ownership;
- prune defaults dry-run and requires exact `--confirm`;
- prune never targets foreign state;
- version without config;
- SIGTERM graceful ordering;
- stable exit codes;
- panic recovery sanitization.

## Task 18: Repository policy and operator documentation

**Files**

- Create/update: `README.md`
- Create: `SECURITY.md`
- Create: `CONTRIBUTING.md`
- Create: `CODE_OF_CONDUCT.md`
- Create: `CHANGELOG.md`
- Create: `docs/configuration.md`
- Create: `docs/development.md`
- Create: `docs/deployment.md`
- Create: `docs/operations.md`
- Create: `docs/crowdsec-machine-credentials.md`
- Create: `docs/feed-attribution.md`
- Keep aligned: `docs/PROJECT_STATE.md`

README must say prominently that Crowdshield is independent and not an official CrowdSec product.

Document every requested operation, exact credential command without executing it, feed terms/attribution, backup/restore, upgrade/rollback/uninstall, safe prune, metrics, and optional real-LAPI test plan.

## Task 19: Build, container, and development Compose

**Files**

- Create: `Makefile`
- Create: `Dockerfile`
- Create: `compose.dev.yaml`
- Create: `.dockerignore`
- Create: `.golangci.yml`

**Container checks**

- pinned Go builder version;
- `CGO_ENABLED=0`, trimpath, readonly module mode, reproducible ldflags;
- scratch final with copied CA bundle and numeric non-root user;
- binary-native `healthcheck` subcommand or equivalent;
- no shell/package manager;
- only `/data` writable at runtime;
- Compose joins only external `monitor`;
- config/credential read-only mounts;
- non-root, read-only root, cap-drop ALL, no-new-privileges;
- no host/privileged/socket/production mounts;
- development port published only as documented;
- do not run Compose without user approval.

**Verification**

```sh
make build
file bin/crowdshield
ldd bin/crowdshield || true
docker build --target runtime -t crowdshield:dev .
docker image inspect crowdshield:dev
```

Building the image is allowed; running the Compose stack is not.

## Task 20: CI and dependency automation

**Files**

- Create: `.github/workflows/test.yml`
- Create: `.github/workflows/race.yml`
- Create: `.github/workflows/lint.yml`
- Create: `.github/workflows/build.yml`
- Create: `.github/workflows/container.yml`
- Create: `.github/dependabot.yml` or `renovate.json`

Workflows:

- use immutable action commit SHAs with version comments;
- require no PR secrets;
- test/vet/race/staticcheck/golangci-lint;
- build matrix where useful;
- container build without push;
- SBOM generation;
- vulnerability scan;
- license inventory/check;
- upload non-sensitive reports only;
- never publish an image.

Validate YAML and action references locally where tools permit.

## Task 21: Full hardening and one bounded review pass

**Commands**

```sh
.tools/go/bin/go mod tidy
.tools/go/bin/go mod verify
.tools/go/bin/go test ./...
.tools/go/bin/go test -race ./...
.tools/go/bin/go vet ./...
.tools/bin/staticcheck ./...
.tools/bin/golangci-lint run
.tools/go/bin/go test -covermode=atomic -coverprofile=coverage.out ./...
.tools/go/bin/go tool cover -func=coverage.out
.tools/bin/govulncheck ./...
make build
make container
make sbom
make scan
```

Additional checks:

- fuzz smoke tests for parsers/config where time-bounded;
- inspect goroutine/race behavior;
- verify normal test output has no canary indicators/credentials;
- inspect Git diff/status for accidentally tracked secret/state/tool artifacts;
- measure binary and image size;
- record scanner versions and findings;
- perform exactly one focused code/security review and fix only in-scope findings;
- rerun affected focused tests and one complete verification pass.

Missing host tools are installed project-locally where feasible; otherwise exact installation commands and the unexecuted gate are reported honestly.

## Task 22: Optional real-LAPI plan only

**Files**

- Complete plan in `docs/development.md` and `docs/operations.md`.

Do not execute without explicit immediate approval.

Plan requirements:

- record exact before alert/decision IDs and counts;
- use a user-approved documentation-only network value and short TTL;
- create one unique Crowdshield development decision;
- verify machine/origin/scenario/scope/value/duration/IDs;
- expire only its exact ID;
- record after IDs/counts;
- prove no unrelated decision changed;
- rollback on each failure branch.

## Task 23: Final project-state and report evidence

**Files**

- Update: `docs/PROJECT_STATE.md`
- Update: `CHANGELOG.md`

Record:

- architecture implemented vs deferred;
- files created;
- exact test/race/vet/lint/static/security results;
- coverage;
- binary/image sizes;
- SBOM and vulnerability findings;
- known limitations;
- commands for review/dry-run/build;
- external credential/deployment steps;
- optional real-LAPI plan;
- rollback/cleanup.

Do not commit, deploy, push, publish, generate credentials, or write a real CrowdSec decision.
