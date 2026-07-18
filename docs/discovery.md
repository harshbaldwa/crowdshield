# Crowdshield Discovery Report

Discovery timestamp: 2026-07-17T17:43:34-05:00

This report records read-only Phase 1 findings. No production configuration, container, Docker network, credential, or CrowdSec decision was changed. Secret values were never printed or copied.

## Scope and evidence

Live inspection covered:

- host and project toolchain availability;
- Docker Engine and the existing `monitor` network;
- installed CrowdSec and `cscli` versions;
- LAPI health and reachability from a peer on `monitor`;
- the existing development machine credential's structure, permissions, and read-only authentication behavior;
- CrowdSec v1.7.8's checked-in Swagger model and implementation source;
- official Spamhaus DROP and FireHOL Level 1 pages and live feed response structure.

Primary CrowdSec sources:

- https://github.com/crowdsecurity/crowdsec/tree/v1.7.8
- https://github.com/crowdsecurity/crowdsec/blob/v1.7.8/pkg/models/localapi_swagger.yaml
- https://github.com/crowdsecurity/crowdsec/blob/v1.7.8/pkg/apiserver/middlewares/v1/jwt.go
- https://github.com/crowdsecurity/crowdsec/blob/v1.7.8/pkg/apiserver/controllers/v1/alerts.go
- https://github.com/crowdsecurity/crowdsec/blob/v1.7.8/pkg/apiserver/controllers/v1/decisions.go
- https://github.com/crowdsecurity/crowdsec/blob/v1.7.8/pkg/database/alerts.go
- https://github.com/crowdsecurity/crowdsec/blob/v1.7.8/pkg/database/decisions.go

Primary feed sources:

- https://www.spamhaus.org/blocklists/do-not-route-or-peer/
- https://www.spamhaus.org/faqs/do-not-route-or-peer-drop/
- https://www.spamhaus.org/blocklists/drop-fair-use-policy/
- https://www.spamhaus.org/drop/drop_v4.json
- https://www.spamhaus.org/drop/drop_v6.json
- https://iplists.firehol.org/?ipset=firehol_level1
- https://iplists.firehol.org/files/firehol_level1.netset
- https://github.com/firehol/blocklist-ipsets

## Host and development tooling

| Item | Observed state |
| --- | --- |
| Host | Linux 6.8.0-124-generic, x86_64 |
| Docker client/server | 29.2.1 / 29.2.1 |
| Docker Buildx | v0.31.1 |
| Git | 2.43.0 |
| Go in host `PATH` | Not installed |
| Cached `golang` container image | None |
| `staticcheck` | Not installed |
| `golangci-lint` | Not installed |
| `govulncheck` | Not installed |
| `syft` | Not installed |
| `trivy` / `grype` | Not installed |
| `sqlite3` CLI | Not installed |

The official Go download API reported Go 1.26.5 as the current stable release. Its official Linux amd64 archive is `go1.26.5.linux-amd64.tar.gz`, size 66,879,095 bytes, SHA-256 `5c2c3b16caefa1d968a94c1daca04a7ca301a496d9b086e17ad77bb81393f053`.

Implementation may use a project-local, ignored Go toolchain and project-local caches under this repository. Nothing should be installed globally without user approval. Missing analysis/scanning tools must likewise be installed project-locally or documented if unavailable.

## Docker `monitor` network

Observed network properties:

- name: `monitor`;
- driver: bridge;
- scope: local;
- subnet: `10.0.2.0/24`;
- internal: false;
- attachable: false;
- IPv6: disabled;
- no custom network options or labels.

The running CrowdSec container:

- is attached to `monitor` with alias `crowdsec`;
- listens on container port 8080;
- publishes no LAPI port to the host;
- is reachable as `http://crowdsec:8080/health` from an existing peer on `monitor` (HTTP 200 observed with one bounded read-only probe).

The production image should therefore join only the external `monitor` network and use `http://crowdsec:8080`. Internal LAPI transport is plaintext HTTP on the Docker bridge, so container/network isolation remains part of the trust boundary.

## Installed CrowdSec

Observed live version:

- image: `crowdsecurity/crowdsec:v1.7.8`;
- CrowdSec: `v1.7.8-63227459`;
- build date: 2026-05-11;
- embedded Go: 1.26.3;
- API constraint: v1.

Read-only observations:

- `cscli lapi status` authenticated successfully using CrowdSec's existing local machine configuration;
- `GET /health` returned 200;
- unauthenticated `GET /v1/heartbeat` returned 401;
- unauthenticated `GET /v1/decisions` returned 403;
- no Swagger document was served at the common `/swagger*.json` paths, so the exact v1.7.8 checked-in Swagger and source were inspected instead.

## Development credential

A credential file already existed at `secrets/lapi-credentials.yaml` before repository initialization. It was not created, copied, or printed.

Safe validation established only that:

- it is a regular file, not a symlink;
- group/other permission bits are clear;
- it contains non-empty `url`, `login`, and `password` fields;
- its login matches the planned `crowdshield-dev` machine;
- its URL uses the expected `crowdsec` host;
- `POST /v1/watchers/login` returned 200;
- the response had a token and expiry in the expected shape;
- a machine-authenticated, scenario-filtered `GET /v1/alerts` returned 200 and no matching development alerts.

No credential value or JWT was emitted. No write endpoint was called.

## Verified CrowdSec LAPI contract (v1.7.8)

### Machine authentication

- Endpoint: `POST /v1/watchers/login`.
- Request fields: `machine_id`, `password`, and optional `scenarios`.
- Response fields: `code`, `expire`, and `token`.
- Authorization for machine routes: `Authorization: Bearer <JWT>`.
- JWT timeout and maximum refresh window are each one hour in v1.7.8.
- The login middleware requires a two-part `<name>/<version>` User-Agent. `crowdshield/<version>` is compatible.
- Crowdshield should re-authenticate before expiry and once after an authentication failure; retries must remain bounded.

### Creating decisions

There is no machine-authenticated `POST /v1/decisions` route.

A machine creates decisions by posting one or more Alert objects to:

- `POST /v1/alerts`.

Each alert includes required alert metadata and an array of Decision objects. A Decision supports and requires:

- `origin`;
- `type`;
- `scope`;
- `value`;
- `duration`;
- `scenario`.

Therefore the requested representation is supported as follows:

- `origin: crowdshield` is stored as a custom origin;
- `scenario: crowdshield/<feed-name>` is stored on each decision;
- `type: ban` is used for enforcement;
- IP entries use scope `ip` (CrowdSec normalizes scope casing);
- CIDRs use scope `range`;
- `duration: 25h` is accepted by CrowdSec's duration parser;
- the human-readable `reason` concept used by `cscli decisions add --reason` maps to the decision's `scenario`; the Alert `message` can carry `External threat feed: <feed-name>` without containing the network value.

The create response contains alert IDs, not decision IDs. `GET /v1/alerts/{alert_id}` returns the alert and associated decision IDs.

### Listing and ownership

Machine JWT routes support:

- `GET /v1/alerts` with filters such as scenario, origin, active-decision state, type, and limit;
- `GET /v1/alerts/{alert_id}`.

Important distinction:

- `GET /v1/decisions` is documented for remediation components and requires a bouncer API key, not the dedicated machine JWT.
- Crowdshield must not require or request a bouncer key.

The alert response exposes `machine_id`, while decisions expose `id`, `origin`, `scenario`, `scope`, `value`, and remaining duration. Safe ownership must require all available evidence:

1. a locally recorded alert/decision ID pair;
2. the alert's `machine_id` matching the credential login;
3. decision origin exactly `crowdshield`;
4. scenario in the `crowdshield/` namespace;
5. scope/value matching the locally normalized enforcement object.

A broad filter alone is insufficient proof of ownership.

### Refreshing decisions

There is no decision update/refresh endpoint in v1.7.8. Re-posting an identical manual decision creates another database row; the decision schema has no uniqueness constraint covering origin/scope/value/scenario.

Safe refresh must therefore use replacement semantics:

1. create a replacement decision with a fresh finite TTL;
2. obtain and verify its alert and decision IDs;
3. atomically record the replacement locally;
4. expire only the previously recorded and re-verified Crowdshield-owned decision ID.

This briefly permits duplicate enforcement in LAPI but avoids an enforcement gap. Recovery logic must detect an interrupted replacement using local state plus ownership checks.

### Deleting decisions

- Endpoint: `DELETE /v1/decisions/{decision_id}` with machine JWT.
- v1.7.8 implements deletion by setting `until` to the current time (expiration), not immediate hard deletion.
- Filter-based bulk delete routes exist but are unsafe for Crowdshield ownership guarantees and must not be used.
- Crowdshield must only delete exact IDs after ownership verification.

### API limitations affecting design

- Alert search has a `limit` but no cursor/page parameter in the v1.7.8 Swagger contract.
- Large operations must be submitted in bounded alert/decision batches.
- Raw API bodies must never be logged because they contain network values.
- LAPI may log invalid values internally; Crowdshield must validate every value locally before submission.
- An upstream v1.7.8 issue reports problematic origin-filtered alert queries. Crowdshield should prefer locally known alert IDs and exact scenario queries, not depend on a broad origin scan in its normal path.

## Spamhaus DROP

### Official endpoints and format

IPv4:

- URL: `https://www.spamhaus.org/drop/drop_v4.json`
- observed content type: `text/json; charset=UTF-8`
- observed format: newline-delimited JSON (NDJSON), not one JSON array;
- first record: metadata with `type`, `timestamp`, `size`, `records`, `copyright`, and `terms`;
- subsequent records: objects with `cidr`, `rir`, and `sblid`;
- observed records: 1,678 IPv4 networks, all syntactically canonical.

IPv6:

- URL: `https://www.spamhaus.org/drop/drop_v6.json`
- same NDJSON structure;
- observed records: 93 IPv6 networks, all syntactically canonical.

IPv4 and IPv6 are delivered separately. The old text files remain for compatibility, but Spamhaus explicitly recommends migrating to the JSON endpoints. The implementation needs a dedicated `spamhaus-drop-jsonl` parser that validates metadata and record counts.

### Retrieval policy

Official guidance says:

- listings are re-evaluated daily;
- once per day is sufficient for most users;
- automated downloads must be at least one hour apart;
- another FAQ passage says not to download more than once per day;
- excessive downloads may be firewalled.

Conservative design decision: add a per-feed persisted minimum retrieval interval and set Spamhaus feeds to 24 hours. The six-hour sync loop may still refresh LAPI decisions from last-known-good local state without downloading Spamhaus again. Restarting the service must not bypass the persisted retrieval interval.

No special mandatory request header was documented. Crowdshield will nevertheless send the identifiable configured User-Agent and normal `Accept` headers.

### Terms and attribution

The live metadata points to `https://www.spamhaus.org/drop/terms/`, which redirects to the DROP Fair Use Policy.

Verified requirements/constraints include:

- use of the DROP lists constitutes agreement to the published Terms;
- the lists are free of charge subject to those Terms;
- content is protected by copyright and database rights;
- the download page asks products to credit The Spamhaus Project and retain the date and copyright text with data;
- the Spamhaus name/data reference must not be used in marketing, promotional, or other commercial material;
- users must keep data current and accept the no-warranty/liability terms.

Crowdshield will not redistribute feed contents. Documentation and local configuration should preserve factual attribution and links without implying endorsement or using Spamhaus branding as marketing.

On 2026-07-17, the user explicitly accepted the current Spamhaus DROP Terms for this project. The IPv4 and IPv6 feeds may therefore be enabled in the default example configuration, with attribution and retrieval limits preserved.

## FireHOL Level 1

### Official endpoint and format

- URL: `https://iplists.firehol.org/files/firehol_level1.netset`
- analysis page: `https://iplists.firehol.org/?ipset=firehol_level1`
- observed content type: `application/octet-stream`;
- format: UTF-8 line-oriented netset text;
- comments use `#` prefixes;
- records are IPv4 networks (CIDRs and a possible host prefix);
- observed body: 72,983 bytes, 33 comment lines, 4,579 valid network records, zero malformed records;
- observed cache policy: `max-age=7200` and a usable `Last-Modified` response header.

The page's generated metadata reported 3,865 entries while the contemporaneous file contained 4,579 parseable records. Crowdshield must validate the downloaded body itself and must not trust the page's summary count.

The list identifies itself as a composition of:

- DShield;
- Feodo Tracker;
- Team Cymru FullBogons;
- Spamhaus DROP.

It is IPv4-only. Direct Spamhaus entries will overlap in provenance; Crowdshield's local deduplication must retain both contributors but emit only one exact enforcement object.

### Retrieval policy

FireHOL's repository and site are explicitly designed for automated updates. The generated list advertises a one-minute upstream update frequency; the site offers direct links and conditional retrieval. A six-hour Crowdshield interval is conservative. Crowdshield should use `If-Modified-Since` when a valid Last-Modified value is available.

No mandatory custom User-Agent was documented; the configured `crowdshield/<version>` identifier will be sent.

### Licensing uncertainty

This is unresolved and material:

- the official per-list metadata says `license=unknown`;
- the generated-data repository has no LICENSE file;
- its README says the lists are freely available but warns that individual sources can have special licenses and tells users to inspect each source;
- FireHOL Level 1 is a derived aggregate of four independently governed sources.

The project can avoid redistributing the data, preserve attribution, and link to all upstream terms, but it cannot truthfully claim that the aggregate has a verified open-data license.

On 2026-07-17, the user explicitly accepted this licensing uncertainty for this project. FireHOL Level 1 may therefore be enabled in the default example configuration. Crowdshield must still avoid redistributing feed contents and must document the unresolved aggregate-license status and upstream attributions.

## Initial conservative validation envelope

These are design inputs, not yet configuration:

| Feed | Parser | Family | Max bytes | Expected entries (initial broad bounds) | Minimum retrieval interval |
| --- | --- | --- | ---: | ---: | --- |
| Spamhaus DROP IPv4 | `spamhaus-drop-jsonl` | IPv4 | 2 MiB | 500–5,000 | 24h |
| Spamhaus DROP IPv6 | `spamhaus-drop-jsonl` | IPv6 | 1 MiB | 20–1,000 | 24h |
| FireHOL Level 1 | `firehol-netset` | IPv4 | 5 MiB | 1,000–20,000 | 6h |

Initial growth/shrink ratios should be conservative and configurable. A first valid retrieval must satisfy absolute bounds; subsequent retrievals must satisfy both absolute bounds and change-ratio checks against last-known-good state.

## Discovery conclusions

Verified:

- the requested local-only architecture is technically viable with the existing CrowdSec v1.7.8 and `monitor` network;
- dedicated machine credentials can authenticate and read machine routes;
- exact origin/scenario/scope/value metadata is supported;
- a bouncer credential, Console enrollment, Central API list, Docker socket, `cscli` subprocess, or direct CrowdSec database access is unnecessary;
- refresh must use create-verify-expire replacement semantics because no update endpoint exists;
- exact decision IDs plus alert machine identity are necessary for safe deletion;
- both Spamhaus feeds and FireHOL have stable HTTPS endpoints and machine-parseable formats.

Feed-terms decision:

- on 2026-07-17, the user accepted Spamhaus's DROP Terms and FireHOL Level 1's explicitly unknown aggregate licensing status for this project;
- all three requested feeds may be enabled by default, with no additional feeds silently enabled.

No real-LAPI write test is authorized or required for implementation. All destructive behavior must be developed against a mock LAPI until the user separately approves the documented real-LAPI test plan.
