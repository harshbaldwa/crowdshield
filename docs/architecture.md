# Crowdshield Architecture

Status: design baseline for version 1

## 1. Purpose

Crowdshield is a small, local-only Go service that retrieves an explicitly configured set of external malicious-network feeds, validates them as untrusted input, keeps last-known-good state in SQLite, and reconciles only Crowdshield-owned temporary decisions into CrowdSec LAPI.

Crowdshield is independent software. It does not require CrowdSec Console enrollment, CrowdSec Central API blocklists, a hosted control plane, a bouncer key, the Docker socket, `cscli`, or direct access to CrowdSec's database.

## 2. Goals and non-goals

### Goals

- Conservative default feeds configured in local YAML.
- Bounded network, CPU, memory, goroutine, response, and retry behavior.
- Strong normalization and safety exclusions for IPv4 and IPv6.
- Exact provenance even when enforcement is deduplicated.
- Finite decisions that are refreshed before expiry.
- Last-known-good preservation and two-successful-retrieval missing grace.
- Exact, independently verified decision ownership before deletion.
- Deterministic, race-safe tests against a mock LAPI.
- Structured privacy-safe logs and bounded-cardinality Prometheus metrics.
- Local operational commands without a web UI.
- Secure static container running as non-root with only `/data` writable.

### Non-goals for version 1

- CrowdSec Console, Central API blocklists, or hosted management.
- A UI.
- Hostname, ASN, or automatically downloaded allowlists.
- Automatically exempting Cloudflare or any other provider.
- CIDR expansion, aggressive range aggregation, or adjacent-prefix merging.
- Modifying behavioral, AppSec, manual, Console, or third-party decisions.
- Recovering or adopting decisions not provably represented in local state.
- Real-LAPI write tests without separate user approval.
- Production deployment by the development workflow.

## 3. Context and trust boundaries

```text
                       outbound HTTPS
  +----------------+  ---------------->  +----------------------+
  | Crowdshield    |                     | Configured feed hosts |
  | non-root       |                     +----------------------+
  |                |
  | config (ro)    |  internal HTTP/JWT  +----------------------+
  | credential(ro) |  ---------------->  | CrowdSec LAPI v1     |
  | SQLite (/data) |                     | crowdsec:8080         |
  | HTTP :9090     |                     +----------------------+
  +-------+--------+
          |
          | optional HTTPS + bearer token
          v
  +----------------+
  | configured ntfy|
  +----------------+
```

Trust boundaries:

1. Feed bodies, response metadata, redirects, DNS answers, and remote timing are untrusted.
2. Local YAML and mounted credential files are operator-controlled but still parsed defensively.
3. The `monitor` Docker bridge is an internal trust boundary. LAPI traffic is plaintext inside it.
4. CrowdSec LAPI is authoritative for decision identifiers and current expiry, but must not be trusted to infer Crowdshield ownership from a broad filter.
5. SQLite is local durable memory and the primary ownership ledger. It contains network indicators but no credentials.
6. Metrics and logs are observable surfaces and must not expose network indicators, feed URLs, job IDs, errors, or secrets.
7. ntfy is an optional exfiltration boundary. Notifications contain only bounded event categories and counts.

## 4. Process modes

The single binary supports:

- `run`: initialize configuration, credentials, state, LAPI readiness, HTTP endpoints, and the non-overlapping scheduler.
- `run --run-once`: perform one sync and exit; compatibility form for automation.
- `sync`: perform one sync and exit, optionally for one named feed.
- `status`: read local state and perform a bounded LAPI login/connectivity check.
- `validate-config`: parse and validate all configuration and credential structure without opening or mutating SQLite or contacting LAPI/feed hosts.
- `list-feeds`: report configured feed definitions and enabled state without state mutation.
- `explain`: read state and explain an administrator-supplied address or prefix.
- `prune`: plan stale-owned cleanup; mutation requires `--confirm` and still performs exact ownership checks.
- `version`: print build metadata without loading configuration.

`--dry-run` means no persistent SQLite mutation and no CrowdSec or ntfy write. Existing state is opened read-only when available; otherwise an in-memory empty baseline is used. Feed GET requests are still allowed because validating the remote inputs is the purpose of the dry run.

## 5. Package layout

```text
cmd/crowdshield/            process entry point and panic boundary
internal/app/               dependency assembly and lifecycle
internal/cli/               standard-library subcommand parsing/output
internal/config/            strict YAML, durations, env overrides, validation
internal/credentials/       safe CrowdSec credential loader
internal/feed/              parser registry, fetcher, validators, snapshots
internal/network/           netip normalization, safety table, allowlists, dedupe
internal/state/             SQLite repositories and transactions
internal/lapi/              JWT machine client, API models, mock test server
internal/reconcile/         desired-state planner and ownership-safe actions
internal/scheduler/         injected clock/RNG, jitter, non-overlap
internal/logsafe/           structured event logger and error categories
internal/metrics/           small bounded Prometheus text registry
internal/health/            readiness state machine and HTTP handlers
internal/notify/            ntfy client and failure/recovery state machine
internal/buildinfo/         version/revision/build metadata
migrations/                 embedded ordered SQL migrations
testdata/                   bounded fixtures containing documentation ranges only
```

Dependencies point inward. Parsing, planning, and safety logic do not import SQLite, HTTP handlers, or process-global state.

## 6. Runtime dependencies

Version 1 uses only two direct non-standard runtime dependencies:

1. `go.yaml.in/yaml/v3` (MIT/Apache-2.0): strict local YAML decoding. YAML support is required by the external contract, and the standard library has no YAML parser.
2. `modernc.org/sqlite` (BSD-3-Clause): maintained CGO-free `database/sql` SQLite driver. This permits a static, shell-free image and avoids a libc runtime dependency.

Rejected alternatives:

- `mattn/go-sqlite3`: mature, but requires CGO and complicates reproducible static builds.
- `github.com/ncruces/go-sqlite3`: CGO-free and maintained, but its documentation states that each sandboxed database connection uses more memory. Crowdshield favors the lower-memory path.
- ORM frameworks: unnecessary and obscure transaction/ownership semantics.
- CLI/web frameworks: unnecessary for the small fixed command and HTTP surface.
- Prometheus client library: useful generally, but a small fixed registry avoids substantial dependency weight and makes cardinality rules explicit.

SQLite is configured with one open/idle connection, so connection-scoped PRAGMAs remain deterministic and runtime memory is bounded.

## 7. Configuration model

Primary path: `/config/crowdshield.yaml`, overrideable by `--config` or `CROWDSHIELD_CONFIG`.

Top-level sections are exactly:

- `server`
- `schedule`
- `database`
- `crowdsec`
- `decisions`
- `feeds`
- `allowlists`
- `validation`
- `logging`
- `notifications`

Validation rules include:

- configuration size capped at 1 MiB;
- one YAML document only;
- unknown fields rejected;
- duplicate feed names rejected case-insensitively;
- feed names constrained to a bounded lowercase slug and total feeds capped;
- all durations positive and internally consistent;
- count and ratio thresholds valid;
- feed URLs absolute, without userinfo or fragments;
- HTTPS required unless the feed explicitly opts into HTTP and global HTTP opt-in is enabled;
- remote feed destinations cannot resolve to local, private, link-local, multicast, unspecified, or explicit special-purpose addresses;
- allowlists are CIDRs only and canonicalized;
- paths absolute in container-oriented configuration;
- credentials regular, non-empty, and permissions-safe where the platform permits inspection.

Environment overrides are an explicit allowlisted mapping. Unknown `CROWDSHIELD_` variables produce a validation error except documented process variables. Values are parsed through the same typed validators as YAML. Dynamic feed enable overrides use the normalized feed name; feed URLs are intentionally kept in local YAML to make SSRF-relevant changes reviewable.

Sensitive values:

- CrowdSec login/password come only from the credential file.
- ntfy token normally comes from `CROWDSHIELD_NOTIFICATIONS_TOKEN`.
- no credential or token is persisted in config-derived diagnostic structures or SQLite.

## 8. Credential handling

Expected YAML fields:

```yaml
url: http://crowdsec:8080
login: crowdshield-dev
password: <secret>
```

Optional CrowdSec-compatible CA fields may be parsed only if implemented and documented; unknown fields otherwise fail closed.

Rules:

- cap the file at 64 KiB;
- reject non-regular files and symlinks where practical;
- reject group/other permission bits by default, with an explicit configurable warning-only mode for orchestrator-mounted secrets if required later;
- decode directly into a short-lived credential value;
- never stringify the credential value;
- never include YAML decoder source text in surfaced errors;
- clear mutable byte buffers after parsing where practical;
- retain only the fields needed by the authenticated client;
- never store credentials, authorization headers, or JWTs in SQLite, logs, metrics, readiness, panic text, or command output.

## 9. Feed retrieval pipeline

Each enabled feed is processed sequentially. Sequential retrieval bounds memory and avoids synchronized outbound bursts while still allowing independent failures.

```text
persisted cadence/backoff check
        |
        v
DNS + URL policy --> bounded HTTPS GET --> status/content checks
        |                                  |
        +----------------------------------v
                                size-limited body
                                         |
                                         v
                              parser by format name
                                         |
                                         v
                    normalize + family + safety exclusions
                                         |
                                         v
                    malformed/absolute/ratio/truncation gates
                                         |
                           valid only     v
                              transactional LKG replacement
```

### HTTP controls

- independent connect and total request timeouts;
- TLS verification using system/container CA roots;
- explicit TLS handshake and response-header timeouts;
- maximum three redirects by default;
- every redirect revalidates scheme, host, resolved addresses, and credentials absence;
- no proxy environment variables in the feed transport by default;
- `Content-Length` rejected when over the configured maximum;
- body read through a `max+1` limiter;
- only 2xx accepted, with 304 supported when conditional metadata exists;
- HTML media types and HTML-like leading content rejected;
- expected media types checked per feed, with a narrow compatibility list;
- identifiable `crowdshield/<version>` User-Agent;
- response bodies and remote errors never logged.

### Persisted cadence and retries

Each feed stores minimum retrieval interval, last attempt, last success, consecutive failures, and next retry. Restarting cannot bypass the cadence/backoff.

- Spamhaus defaults to a 24-hour minimum retrieval interval.
- FireHOL defaults to six hours.
- transient retry attempts are bounded, exponential, jittered, and remain inside the feed's request budget;
- `Retry-After` is honored only within configured upper bounds;
- a failed feed is not retried by every scheduler tick until its persisted next-retry time;
- manual dry-run does not update retry state.

### Parser contract

A parser receives a bounded byte slice or bounded reader and returns:

- normalized candidate entries with source kind (`ip` or `range`);
- total, blank, comment, malformed, and rejected counts;
- safe metadata needed for validation (never raw body or entry text);
- a typed error category and entry index for failures.

Registered version 1 formats:

- `spamhaus-drop-jsonl`: first nonblank NDJSON object is metadata; later records require `cidr`; metadata record count, family, timestamp, copyright, terms URL, and final newline are validated.
- `firehol-netset`: blank lines and `#` comments; one address/CIDR token before an optional inline comment; final newline required.
- `plain`: generic future-friendly IP/CIDR line format with blank lines and `#`/`;` comments, disabled unless configured.

Unknown JSON fields are tolerated for forward compatibility, but required fields and types are strict. Line/token limits prevent scanner allocation attacks.

## 10. Network normalization and safety

Canonical representation uses `net/netip`:

- IPv4-mapped IPv6 addresses are unmapped or rejected consistently;
- IPv4 and IPv6 addresses use canonical string form;
- CIDRs are masked to canonical network form;
- CIDRs are never expanded;
- exact duplicates collapse into one network object;
- contributor feed IDs remain in the many-to-many provenance table.

An entry is rejected if:

- parsing fails;
- it conflicts with the configured family;
- an address is not global unicast, is private, loopback, link-local, multicast, or unspecified;
- a prefix overlaps any explicit special-purpose network;
- its canonical form violates parser expectations.

The explicit table includes all minimum required ranges plus documentation, benchmark, protocol-assignment, translation, and other applicable IANA special-purpose ranges. Tests use a table-driven manifest so updates are reviewable.

### Allowlist precedence

Version 1 allowlists are CIDRs only.

- An allowlist takes precedence over every feed.
- Any overlap between an imported enforcement prefix and an allowlist suppresses the entire imported prefix. This is intentionally conservative: retaining a broad imported range would still block an allowlisted address.
- A newly overlapping allowlist makes an existing Crowdshield decision undesired. The next successful ownership-safe reconciliation expires it.
- Allowlists prevent both creation and refresh.

### Duplicate and overlap policy

- Exact network duplicates are enforced once.
- All contributing feeds remain queryable.
- A bare host is suppressed when a broader imported CIDR covers it.
- A `/32` or `/128` written as CIDR retains range provenance; if the same network also appears as a bare address, one deterministic enforcement scope is chosen and all provenance is retained.
- Overlapping CIDRs are retained independently.
- Adjacent or unrelated ranges are never merged.

A deterministic primary contributor (configuration order, then name) selects the LAPI scenario. If that contributor disappears but another remains, the next refresh can replace metadata without losing enforcement.

## 11. Feed validation and last-known-good policy

A candidate snapshot is accepted only if all applicable checks pass:

- non-empty body and at least one accepted entry;
- successful parser structure and final-record completion;
- malformed count and ratio at or below configured thresholds;
- accepted entry count inside absolute bounds;
- if a previous good snapshot exists, growth and retained-fraction limits pass;
- parser metadata count matches when the format provides a reliable count;
- content hash and metadata are internally coherent;
- body was not cut by the response-size limiter;
- response is not HTML or an error document.

`max_growth_ratio` means `new_count / old_count` may not exceed the configured value (at least 1.0).

`max_shrink_ratio` is the minimum retained fraction (greater than 0 and at most 1.0). For example, `0.5` rejects a new snapshot smaller than half the previous accepted count.

When validation fails:

- the candidate body and entries are discarded;
- the last-known-good snapshot and missing counters are unchanged;
- no removal is planned from that feed;
- a bounded failure category/count is recorded;
- independent feeds continue.

## 12. SQLite state model

SQLite path defaults to `/data/crowdshield.db`.

Initialization:

- open with `database/sql` and one connection;
- `PRAGMA foreign_keys=ON`;
- `PRAGMA journal_mode=WAL` for writable service mode;
- configurable busy timeout;
- `PRAGMA synchronous=NORMAL` by default;
- `PRAGMA quick_check` at startup;
- ordered embedded migrations in transactions;
- read-only URI mode for dry-run/status/explain where mutation is unnecessary.

Logical tables:

| Table | Purpose |
| --- | --- |
| `schema_migrations` | Applied migration version/checksum/time |
| `app_state` | Last sync attempt/success/full-success and bounded readiness state |
| `feeds` | Stable feed ID, definition fingerprint, enabled state, cadence/retry/health summaries |
| `feed_versions` | Accepted snapshot hash, retrieval time, count, conditional headers |
| `entries` | Canonical family/network/scope-kind identity |
| `feed_entries` | Feed provenance, first/last seen, consecutive successful-missing count, active flag |
| `enforcement_objects` | Deduplicated object, desired/suppressed state, primary contributor |
| `enforcement_sources` | Many-to-many contributor links |
| `lapi_decisions` | Local ownership record, alert ID, decision ID, scenario, expiry, lifecycle state |
| `lapi_operations` | Crash-recovery intent/outcome journal for create/replace/delete |
| `sync_runs` | Bounded history summary without indicators or raw errors |
| `feed_run_results` | Per-feed bounded outcome/count summary |
| `notification_state` | Threshold/recovery/stale notification state without token/server data |

Database values necessarily include normalized malicious networks to implement state and explain. No generic row dump is exposed. Tests and diagnostics report counts only.

### Transaction invariants

- A failed candidate never replaces the current feed version.
- Missing counters change only in the same transaction as an accepted feed version.
- Enforcement provenance changes atomically with accepted feed state.
- A LAPI decision becomes `active` locally only after its alert/decision identifiers are obtained and verified.
- Replaced old/new ownership records transition atomically after remote verification.
- No transaction is held open across an HTTP call.
- Every remote mutation has a durable operation intent before the call and a recoverable terminal state after it.

History retention is bounded by configurable counts/age; current ownership records are never pruned merely due to age.

## 13. Synchronization algorithm

A capacity-one semaphore protects the complete synchronization path. Scheduler, CLI, and HTTP-internal triggers cannot overlap.

### 13.1 Attempt

1. Allocate an opaque internal job identifier; never expose it as a metric label or log field unless the logging policy explicitly allows a bounded opaque ID. Default logging omits it.
2. Record last attempt (unless dry-run).
3. Process each selected enabled feed independently.
4. Accept good snapshots transactionally; retain good state on failure or cadence skip.
5. Build desired enforcement from all active last-known-good provenance.
6. Apply safety and allowlist suppression.
7. Diff desired objects against local active decision ownership.
8. Reconcile LAPI in bounded batches.
9. Commit run summaries and health timestamps.
10. Evaluate notifications from bounded outcomes.

### 13.2 Missing grace

For each feed independently:

- present in accepted snapshot: missing counter resets to zero;
- absent from accepted snapshot: counter increments by one;
- absent from two consecutive accepted snapshots by default: that feed's provenance becomes inactive;
- failed, skipped, empty, malformed, truncated, suspicious, or unavailable retrieval: counter is unchanged.

An exact object remains desired while any active feed provenance remains.

### 13.3 LAPI create

- Group new objects by deterministic primary feed/scenario.
- Chunk decisions to a configurable bounded batch size.
- Write a pending local operation with an opaque operation token.
- POST an Alert batch to `/v1/alerts`.
- Use alert source `scope=service`, `value=crowdshield`; never use an indicator as alert source or message.
- Use message `External threat feed: <feed-name>` and `scenario=crowdshield/<feed-name>`.
- Read each returned alert by exact ID.
- Match returned decisions by normalized scope/value/scenario in memory without logging values.
- Transactionally store verified ownership and complete the operation.

### 13.4 Refresh

CrowdSec v1.7.8 has no update endpoint. Refresh uses create-verify-expire:

1. create and verify replacement;
2. store replacement and mark old as pending expiration;
3. re-read the old exact alert and verify machine ID, decision ID, origin, scenario namespace, scope, and value;
4. expire the exact old decision ID;
5. mark old decision replaced/expired.

Default TTL is 25 hours; default refresh threshold is 12 hours remaining. Metadata changes also trigger replacement. A short duplicate window is safer than deleting first and creating an enforcement gap.

### 13.5 Removal

Removal is planned only when an object is undesired due to completed missing grace, allowlist overlap, feed disable/removal, or explicit confirmed prune.

Before every delete, all ownership predicates must pass:

- local active decision record exists;
- exact alert can be read;
- alert machine ID equals credential login;
- exact decision ID is attached to that alert;
- origin is exactly `crowdshield`;
- scenario begins with `crowdshield/` and matches the recorded scenario;
- scope/value match the local canonical object.

Any mismatch fails closed and produces an ownership-conflict category. Broad delete filters are never called.

### 13.6 Crash and ambiguous-outcome recovery

LAPI has no idempotency key. Every mutation therefore has a local operation record and opaque token represented in safe Alert metadata such as scenario hash/labels.

On startup or before a retry:

- recover pending operations first;
- exact known alert IDs are preferred;
- an ambiguous create may use a bounded scenario/time-window alert query and match the opaque operation token, machine ID, and decision set;
- if proof cannot be established within response limits, stop that operation and require operator review rather than risk duplication/deletion;
- delete 404/expired outcomes are treated as complete only when the local record proves the exact former ownership.

## 14. Sync success semantics

State distinguishes:

- `last_sync_attempt`: any run started;
- `last_sync_success`: reconciliation completed safely using available last-known-good state, even if one feed had a transient independent failure;
- `last_full_sync_success`: every enabled feed was healthy/current and LAPI reconciliation completed.

Readiness uses `last_sync_success` so one temporary optional feed failure does not flap service readiness. Stale-feed metrics and ntfy can still signal per-feed degradation. The recommended 12-hour stale-full-sync notification uses `last_full_sync_success`.

## 15. Scheduler and cancellation

- A clock and random source are injected for deterministic tests.
- With `run_immediately=true`, first sync occurs after a uniform random delay in `[0,startup_jitter]`.
- Test configuration can set jitter to zero.
- With `run_immediately=false`, first scheduled run occurs after the interval plus initial jitter.
- Recurring intervals are measured after the previous job finishes, preventing catch-up overlap.
- Feed retries use bounded jittered timers and persisted backoff.
- SIGINT/SIGTERM cancels the root context.
- Feed/LAPI/ntfy requests inherit cancellation.
- The HTTP server performs bounded graceful shutdown.
- SQLite closes after scheduler and HTTP workers stop.
- No work item creates an unbounded goroutine; service goroutines are fixed and joined.

## 16. LAPI client boundaries

The client has separate typed methods:

- `Authenticate`
- `Health`
- `ListAlerts` with bounded filters/result bytes
- `GetAlert`
- `CreateAlerts`
- `DeleteDecision`

Rules:

- one shared bounded `http.Client`;
- token cached in memory only;
- authenticate before expiry and retry once on 401;
- 403 is not retried as authentication refresh unless contractually appropriate;
- 429 honors bounded `Retry-After`;
- 5xx and timeouts use bounded backoff;
- JSON bodies capped and decoded strictly enough to reject malformed identifiers/types;
- never return raw bodies in errors;
- errors expose category, operation, and status class only;
- request and failure metrics use bounded operation/result labels.

## 17. Logging privacy

`log/slog` emits one JSON object per line to stdout for the long-running service.

Application code logs through a narrow event API accepting only:

- timestamp/level;
- feed name from validated bounded configuration;
- operation enum;
- duration;
- counts;
- success/failure status;
- sanitized error category;
- LAPI operation counts;
- transaction outcome.

It does not accept arbitrary errors or strings as structured values. Internal errors may wrap context for control flow, but the terminal log boundary maps them to an enum.

Panic recovery logs only `panic_recovered` and exits; it does not print panic values or stack traces. HTTP server internal errors use a sanitized adapter. Tests inject canary indicators, credentials, authorization headers, URLs, and raw payload fragments and assert they never appear.

Administrator CLI output is separate from application logging. `explain` may print the explicit administrator input and matching state, but does not route that output through `slog`.

## 18. Metrics

A fixed in-process registry exposes Prometheus text format. Metric names match the documented `crowdshield_*` surface.

Allowed labels are closed enums plus validated feed names and mode (`enforce` or `dry_run`). Forbidden labels/values include addresses, CIDRs, URLs, errors, job IDs, alert IDs, decision IDs, topics, and secrets.

Metrics are registered at initialization, not dynamically from errors. Feed count is configuration-bounded. Histogram buckets are fixed.

## 19. Health and readiness

`/healthz` returns only process liveness:

```json
{"status":"ok"}
```

`/readyz` returns 200 only when:

- configuration is valid;
- database initialized and passed corruption check;
- LAPI authentication is known valid;
- LAPI has not been unreachable longer than its grace period;
- at least one safe synchronization completed;
- last safe synchronization is not older than the threshold.

Failure response contains only bounded reason enums, for example:

```json
{"status":"not_ready","reasons":["sync_never_succeeded"]}
```

No network indicators, errors, paths, URLs, identities, or secrets are returned.

## 20. ntfy notifications

ntfy is disabled by default. Configuration and token come from environment overrides in normal deployment.

Events use bounded templates containing service name, severity, feed name where applicable, counts, and category. They never contain indicators, URLs, paths, credentials, raw errors, payloads, alert/decision IDs, or database rows.

Stateful suppression supports:

- threshold crossing after repeated feed failures;
- immediate LAPI reconciliation failure notification;
- suspicious feed-change notification;
- 12-hour full-sync staleness notification;
- one recovery notification after a notified problem clears;
- optional startup notification;
- routine success disabled by default;
- optional first successful development run notification.

Notification failure never fails synchronization and never recursively triggers notification.

## 21. CLI output and exit codes

Exit code classes are stable and documented:

- 0: success/ready/valid;
- 1: operational failure;
- 2: usage/configuration error;
- 3: not ready/degraded status where command semantics require it;
- 4: ownership conflict requiring operator review.

Human output is concise. Optional JSON output, where implemented, uses bounded documented fields and never includes credentials or tokens.

## 22. Resource budgets

Default design budgets:

- one feed body in memory at a time, bounded by feed limit (1–5 MiB defaults);
- feed entries in compact `netip.Prefix` slices/maps, not expanded addresses;
- one SQLite connection;
- fixed service goroutines;
- LAPI decision batches default 250–500 entries;
- HTTP response limits on every external endpoint;
- bounded sync history and operation-retention cleanup;
- no unbounded queues, maps keyed by remote errors, or per-entry metrics/logs.

Exact binary/image/RSS measurements are Phase 4/6 deliverables, not assumptions.

## 23. Deployment shape

The production target image is a statically linked binary in `scratch` when the pure-Go SQLite build and copied CA bundle verify successfully. The image includes:

- `/crowdshield`;
- CA certificate bundle;
- `/etc/passwd` and `/etc/group` entries or numeric-user configuration as needed for non-root execution;
- no shell, package manager, timezone database, or writable root paths.

Compose mounts config and LAPI credentials read-only and a local project `data/` directory at `/data`; joins only external `monitor`; uses non-root, read-only rootfs, all capabilities dropped, no-new-privileges, no host network, no Docker socket, and a binary-native healthcheck command.

The development workflow creates this Compose file but does not run it without explicit user approval.

## 24. Upgrade and compatibility policy

- Configuration and state schema versions are explicit.
- Migrations are forward-only, checksum-verified, and transaction-tested.
- Back up SQLite before upgrades.
- CrowdSec API behavior is pinned to verified v1.7.8 assumptions and checked at startup via API compatibility/authentication behavior.
- Unknown response fields are generally tolerated; missing or malformed required fields fail closed.
- Feed URL/format/terms are operator-visible local configuration and must be reviewed when upstream changes.
- Renovate/Dependabot proposes dependency updates; CI never publishes images.
