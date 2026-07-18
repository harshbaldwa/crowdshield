# Crowdshield Threat Model

Status: version 1 design baseline

## 1. Security objective

Crowdshield must turn untrusted remote network-indicator feeds into temporary CrowdSec decisions without allowing a feed, network attacker, configuration mistake, software defect, or lost local state to:

- block private/special/allowlisted networks;
- delete or alter decisions owned by another source;
- leak indicators or credentials through logs, metrics, health, notifications, or panic output;
- exhaust host/LAPI resources;
- obtain host/container privileges;
- silently replace last-known-good state with suspicious data.

Safety takes precedence over availability. When ownership, feed integrity, or API behavior is uncertain, Crowdshield fails closed for mutation and preserves known-good decisions until their finite TTL naturally expires.

## 2. Assets

| Asset | Security property |
| --- | --- |
| CrowdSec machine password/JWT | Confidentiality; bounded lifetime; never persisted beyond credential source |
| ntfy token | Confidentiality; never logged/persisted |
| CrowdSec foreign decisions | Integrity; never mutated by Crowdshield |
| Crowdshield-owned decisions | Correct provenance, finite TTL, safe lifecycle |
| CIDR allowlists | Integrity and precedence over feeds |
| Last-known-good feed state | Integrity and availability |
| SQLite ownership ledger | Integrity, recoverability, bounded access |
| Configuration | Integrity, explicit reviewed feed destinations |
| Logs/metrics/health | Confidentiality and bounded cardinality |
| Host/container/network | Isolation and least privilege |
| Build artifacts/dependencies | Provenance, reproducibility, vulnerability visibility |

Malicious indicators are not treated as secrets inside SQLite or administrator `explain` output, but they are prohibited from operational logs, metrics, health, notifications, and normal CI output.

## 3. Actors and assumptions

### Potential adversaries

- A malicious or compromised feed publisher.
- An attacker controlling feed DNS, routing, TLS termination, CDN, or redirect target.
- An attacker who obtains the LAPI machine credential or ntfy token.
- A malicious service/container already attached to `monitor`.
- A dependency/build-system compromise.
- An unauthenticated client that can reach Crowdshield's metrics/health listener.
- Accidental operator misconfiguration.
- A software defect or corrupted local database.

### Trusted actors/components

- The local operator controlling reviewed YAML, mounted secrets, and Compose invocation.
- The host kernel, Docker daemon, and mounted CA trust store.
- The configured CrowdSec LAPI to enforce correctly once an exact valid request is accepted.

The operator is trusted to intentionally add a feed or allowlist, but Crowdshield still rejects structurally unsafe values. A root-level attacker or compromised Docker daemon is out of scope; such an actor can read mounted credentials and alter binaries/state directly.

## 4. Trust boundaries

1. Internet to feed HTTP client.
2. DNS resolver/CA roots to destination validation.
3. Read-only config/credential mounts to process memory.
4. Crowdshield to CrowdSec over plaintext internal Docker HTTP.
5. Process to SQLite in writable `/data`.
6. Process to unauthenticated observability HTTP clients.
7. Process to optional remote ntfy.
8. Source repository/dependency registries to build artifact.
9. Container boundary to Docker host and peer containers.

## 5. Security invariants

These invariants must have direct tests:

1. A failed or suspicious feed never replaces last-known-good state.
2. Missing counters advance only after a successful accepted retrieval of that feed.
3. No removal occurs before the configured successful-missing grace count.
4. No imported prefix may overlap an allowlist or explicit unsafe range.
5. CIDRs are never expanded or automatically merged.
6. A delete targets only an exact locally recorded decision ID after live ownership verification.
7. No broad LAPI delete route is called.
8. Refresh creates and verifies replacement before expiring the old decision.
9. Every decision has finite TTL.
10. Dry-run causes no persistent SQLite, LAPI, or ntfy mutation.
11. Sync jobs never overlap.
12. External response and request bodies are bounded.
13. Logs/metrics/health/notifications never contain indicators or secrets.
14. Credential/token values are absent from errors and panic recovery.
15. Runtime goroutine/queue/cardinality growth is bounded by configuration constants.

## 6. Threat analysis

Risk ratings are qualitative before production measurements.

### T01: Malicious feed content

- Threat: A validly hosted feed deliberately supplies private, special, allowlisted, malformed, duplicate, or extremely broad networks.
- Impact: Severe false positives, local denial of service, resource exhaustion.
- Mitigations: strict parser registry; family validation; canonical `netip`; explicit IANA safety table; global-unicast classification; any-overlap allowlist precedence; absolute count/size bounds; ratio checks; malformed thresholds; no CIDR expansion; last-known-good preservation.
- Remaining risk: A syntactically valid public malicious prefix can still be a false positive. Human review and conservative source choice remain necessary.

### T02: Compromised feed server

- Threat: Publisher/CDN account compromise serves plausible but hostile data.
- Impact: Large-scale incorrect blocks.
- Mitigations: TLS; pinned reviewed URL in local YAML; DNS/redirect policy; expected counts; change ratios; two-successful-retrieval removal grace; finite TTL; suspicious-change notification; per-feed provenance and easy disable.
- Remaining risk: Slow poisoning within thresholds can evade count-based anomaly detection. No cryptographic feed signatures are available for the selected sources.

### T03: Feed truncation or empty response

- Threat: Network/proxy/server returns a prefix of the feed, zero bytes, or a cleanly terminated error body.
- Impact: Existing entries appear missing and could be removed.
- Mitigations: non-empty requirement; response-size completion flag; final-newline checks; Spamhaus metadata record count; absolute minimum; shrink ratio; HTML detection; malformed threshold; last-known-good preservation; missing counters unchanged on failure.
- Remaining risk: A truncated response that remains above every threshold and has internally rewritten metadata could be accepted after upstream compromise.

### T04: DNS manipulation or rebinding

- Threat: Configured hostname resolves or redirects to loopback, private services, metadata endpoints, or a changing address after validation.
- Impact: SSRF, secret exposure, local service probing.
- Mitigations: custom bounded dialer resolves and rejects unsafe addresses immediately before connection; URL and every redirect validated; no userinfo; HTTPS default; private/special literal rejection; no automatic proxy; redirect cap; host-to-dial binding within the request.
- Remaining risk: Trusted resolver/host compromise and TOCTOU details in platform DNS remain. Local operator can explicitly weaken HTTP policy but not private-destination policy in version 1.

### T05: TLS failure/downgrade

- Threat: Invalid certificate, interception, downgrade to HTTP.
- Impact: Feed tampering or disclosure.
- Mitigations: normal certificate/hostname validation; HTTPS required; redirect scheme revalidation; no insecure-skip-verify option; HTTP requires explicit global and per-feed opt-in; selected defaults remain HTTPS.
- Remaining risk: A compromised trusted CA can impersonate a feed host.

### T06: Excessive feed size or decompression bomb

- Threat: Huge response consumes memory/disk/CPU.
- Impact: Service/host denial of service.
- Mitigations: reject oversized Content-Length; `max+1` streaming cap; no compressed responses by default unless bounded decompression is deliberately implemented; one feed processed at a time; line/token caps; count maximum; no address expansion.
- Remaining risk: Parsing the configured maximum still consumes bounded CPU/memory. Defaults are deliberately small.

### T07: Malformed CIDRs and parser confusion

- Threat: Ambiguous whitespace, inline comments, mapped addresses, noncanonical prefixes, oversized lines, JSON type tricks.
- Impact: Incorrect decision or parser crash.
- Mitigations: format-specific parsers; strict required types; bounded lines; `netip`; prefix masking; mapped-address policy; entry-index-only errors; fuzz/property tests; panic boundary without values.
- Remaining risk: Future upstream format changes may be rejected until configuration/parser is updated; this is preferable to unsafe acceptance.

### T08: False positives

- Threat: Legitimate public network appears in an accepted feed.
- Impact: Availability loss for users/services.
- Mitigations: conservative explicit feed set; CIDR allowlists with overlap precedence; per-feed attribution; `explain`; missing grace; finite TTL; dry-run; feed disable; suspicious-size gates; no broad range merging.
- Remaining risk: No automated reputation system can prove maliciousness. Operator allowlisting and source review remain required.

### T09: Credential theft

- Threat: Machine password/JWT or ntfy token leaks via image, filesystem, process args, logs, errors, metrics, panic, SQLite, notification, or repository.
- Impact: LAPI mutation or notification abuse/exfiltration.
- Mitigations: read-only mounted credential; secrets ignored by Git; direct file read; strict permissions; no CLI argument/env for LAPI password; in-memory JWT only; no raw errors/bodies; safe logger API; panic without stack/value; no secrets in health/metrics/state; non-root/read-only container; token from env; tests with canaries.
- Remaining risk: Host root/Docker daemon and same-UID process inspection can access process memory/mounts. Environment-provided ntfy token may be visible to privileged host tooling.

### T10: LAPI compromise or malicious response

- Threat: LAPI returns malformed, oversized, conflicting IDs/metadata or accepts unintended deletes.
- Impact: State corruption or foreign decision deletion.
- Mitigations: response caps; strict positive IDs; exact alert readback; scope/value/origin/scenario/machine verification; local operation journal; no broad deletes; fail closed on mismatch; finite TTL.
- Remaining risk: A fully compromised LAPI can lie consistently and manipulate all CrowdSec state. Crowdshield cannot defend CrowdSec from itself.

### T11: SQLite corruption

- Threat: disk error, abrupt power loss, driver defect, operator file damage.
- Impact: lost feed/ownership state; unsafe reconciliation.
- Mitigations: transactions; WAL; foreign keys; busy timeout; one connection; startup `quick_check`; migration checksums/tests; backup docs; operation journal; fail readiness and refuse mutation on corruption.
- Remaining risk: Without a valid backup, Crowdshield cannot safely prove ownership of orphaned LAPI decisions. They expire naturally by TTL or require manual reviewed cleanup.

### T12: Decision ownership mistake

- Threat: A local bug attributes a behavioral/manual/Console/third-party decision to Crowdshield.
- Impact: deletion of unrelated protection or operator intent.
- Mitigations: multi-factor ownership predicate (local IDs, alert machine, exact origin/scenario/scope/value); exact-ID GET before DELETE; no adoption; no broad deletes; foreign-decision tests; invariant checks in state schema and planner.
- Remaining risk: Credential reuse by another integration with identical origin/scenario and state tampering could defeat predicates. Dedicated machine and protected SQLite are required.

### T13: Deletion of unrelated CrowdSec decisions

- Threat: Filter bug, stale/reused ID, or overly broad prune removes foreign state.
- Impact: security control loss.
- Mitigations: exact-ID only; readback; all ownership fields; prune dry-run by default and `--confirm`; bounded plan output; stop on any mismatch; mock foreign cases; real test before production.
- Remaining risk: LAPI ID/response compromise is outside Crowdshield's proof model.

### T14: SSRF through configuration

- Threat: Feed or ntfy URL points to an internal admin service or cloud metadata endpoint.
- Impact: service probing, data exfiltration.
- Mitigations: feed URL policy described in T04; URLs reviewable in YAML; ntfy URL HTTPS validation and no redirects to unsafe/private destinations unless an explicitly documented local-ntfy mode is later added; no URL in logs.
- Remaining risk: Operators may need local ntfy. Version 1 should require an explicit, narrow configuration opt-in and document that trust expansion rather than silently permit it.

### T15: Notification exfiltration

- Threat: ntfy payload includes indicator, URL, credentials, raw error/body, local path, or IDs.
- Impact: sensitive operational data leaves homelab.
- Mitigations: fixed templates with bounded categories/counts; no arbitrary error strings; token never echoed; TLS; response cap; notification disabled by default; failure does not recurse.
- Remaining risk: Feed names and aggregate failure/count information are intentionally disclosed to the configured ntfy endpoint.

### T16: Log leakage

- Threat: values enter structured attributes, wrapped errors, HTTP server logs, panic stacks, parser/database errors, or test failures.
- Impact: durable indicator/secret exposure in log infrastructure.
- Mitigations: logger accepts closed event structure, not arbitrary strings/errors; sanitized category mapping; no raw payload; custom HTTP ErrorLog; panic without value/stack; canary tests across normal paths; no per-entry logging; entry index only.
- Remaining risk: Go runtime fatal errors outside recoverable boundaries may write runtime diagnostics, though application data should not be embedded in panic values.

### T17: Metrics leakage/cardinality attack

- Threat: remote values/error strings become labels or dynamically create series.
- Impact: indicator leak, Prometheus memory exhaustion.
- Mitigations: fixed descriptors; label-name/value allowlist; only bounded configured feed names and enums; configuration caps number/length of feed names; exposition tests reject forbidden labels.
- Remaining risk: Operator-controlled feed names appear as labels by design.

### T18: Denial of service and retry storm

- Threat: slow feeds/LAPI/ntfy, repeated failures, rapid restarts, scheduler overlap, large syncs.
- Impact: resource exhaustion or upstream hammering.
- Mitigations: all timeouts and response caps; sequential feeds; fixed goroutines; capacity-one sync semaphore; persisted per-feed cadence/backoff; randomized startup/retry jitter; bounded attempts; `Retry-After` cap; batch size; one SQLite connection.
- Remaining risk: A legitimate large LAPI reconciliation may take time; readiness grace and metrics must expose degradation without spawning overlap.

### T19: Scheduler overlap/races

- Threat: ticker, manual command, retry, and shutdown start concurrent jobs or mutate shared health/state unsafely.
- Impact: duplicate decisions, missing counters advanced twice, DB contention.
- Mitigations: one process-wide semaphore; recurrence scheduled after completion; context cancellation; mutex/atomic health state; injected deterministic clock; race detector; non-overlap tests.
- Remaining risk: Two separately launched Crowdshield containers against the same DB/LAPI are not supported in version 1. Compose must run one replica; a future distributed lease would be needed for HA.

### T20: Supply-chain compromise

- Threat: malicious Go module, GitHub Action, base image, scanner, or mutable tag.
- Impact: arbitrary build/runtime compromise.
- Mitigations: two direct runtime dependencies; checksummed Go modules; `go mod verify`; pinned versions; Dependabot/Renovate review; immutable action SHAs; reproducible flags; SBOM; `govulncheck`; container scanner; license inventory; no image publishing; minimal scratch image.
- Remaining risk: Go proxy, source upstream, build host, or pinned dependency can still be compromised. Reproducible independent builds and signature verification improve but do not eliminate this.

### T21: Container escape/host compromise

- Threat: application/library vulnerability gains container execution and attacks host/peers.
- Impact: credential theft, network compromise.
- Mitigations: non-root; scratch/no shell; read-only root; writable `/data` only; capabilities dropped; no-new-privileges; no privileged/host network/Docker socket; only `monitor`; bounded parsers; no command execution in application.
- Remaining risk: Kernel/container-runtime vulnerabilities and broad egress/peer reachability remain host-level concerns.

### T22: Unsafe upgrade or migration

- Threat: new binary/config/schema/API behavior corrupts state or changes ownership semantics.
- Impact: outage, duplicate decisions, foreign deletion.
- Mitigations: versioned checksum migrations in transactions; migration fixtures; backup/restore docs; validate config before upgrade; dry-run; API assumptions document; no automatic downgrade; rollback uses binary+DB backup; CI and release notes.
- Remaining risk: Forward schema migration may not be reversible without backup. Operators must test and retain backups.

### T23: Feed terms/attribution change

- Threat: upstream changes URL, retrieval policy, license, or attribution after release.
- Impact: policy violation or broken feed.
- Mitigations: URLs/attribution in visible YAML; versioned attribution docs; no data redistribution; conservative cadence; dependency/feed review during upgrades; failure preserves LKG.
- Remaining risk: Crowdshield cannot automatically interpret legal term changes. Operator review remains required. The user accepted current Spamhaus terms and FireHOL uncertainty on 2026-07-17, not unknown future revisions.

### T24: Unauthenticated observability endpoint exposure

- Threat: another `monitor` peer or published host port reads metrics/health or floods handlers.
- Impact: operational metadata disclosure or service load.
- Mitigations: concise no-indicator responses; server timeouts/header limits; metrics have counts only; Compose exposure limited for development; no control/write endpoints.
- Remaining risk: Aggregate feed/decision counts and service health are intentionally visible to clients that can reach the listener.

## 7. Abuse cases to test

- Feed redirects to a private literal or resolves to loopback.
- Successful HTTP response contains an HTML login/error page.
- Body ends exactly at configured byte limit without final newline.
- Metadata says more records than present.
- One malformed line stays below threshold; the next crosses it.
- New snapshot grows or shrinks just below/at/above threshold.
- Feed failure occurs after one missing success; counter must remain one.
- Exact host appears in two feeds and inside a CIDR in a third.
- Allowlist contains a host inside a broad imported range; entire range is suppressed.
- LAPI create times out after storing the alert.
- Returned alert includes one expected and one foreign decision.
- Locally recorded decision now has foreign origin/scenario/machine; delete must stop.
- Dry-run is executed against a writable database and mock LAPI; both remain byte/operation unchanged.
- Error values contain indicator, credential, token, URL, and authorization header canaries; output surfaces remain clean.
- Scheduler is triggered concurrently and during cancellation.
- SQLite migration/transaction fails midway and rolls back completely.

## 8. Detection and response

Signals:

- per-feed last-success age/count/failure metrics;
- suspicious-change counters and notifications;
- LAPI failure/auth readiness reasons;
- database corruption/failure counter and unready state;
- ownership-conflict log category and exit code;
- last safe/full synchronization timestamps;
- bounded sync history in SQLite.

Response principles:

1. Disable a suspect feed in YAML and run `validate-config`.
2. Run `sync --dry-run` and inspect aggregate plan/status.
3. Add a narrow CIDR allowlist if mitigating a false positive.
4. Never delete using broad CrowdSec filters.
5. Use `prune` dry-run, back up SQLite, then `prune --confirm` only if ownership proof passes.
6. Rotate the dedicated machine credential if exposure is suspected.
7. Restore a known-good DB backup before attempting orphan recovery.
8. Let finite TTL expire when ownership cannot be proven.

## 9. Security acceptance before production

Development completion is not production approval. Before deployment, the operator should review:

- all enabled feed URLs, current terms, counts, and attribution;
- allowlists for local/public dependencies;
- first dry-run plan and excluded counts;
- LAPI machine scope and credential permissions;
- metrics listener exposure;
- ntfy destination/payload policy;
- SBOM, vulnerability, license, race, lint, and static-analysis results;
- optional controlled real-LAPI test evidence;
- backup, rollback, and uninstall procedures.
