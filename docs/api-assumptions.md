# CrowdSec LAPI API Assumptions

Target verified implementation: CrowdSec v1.7.8 (`v1.7.8-63227459`, built 2026-05-11)

This document separates behavior verified from official v1.7.8 source/live read-only probes from behavior that must remain an implementation assumption until an explicitly approved real-LAPI write test.

## 1. Evidence hierarchy

1. Installed version and read-only live responses.
2. CrowdSec's exact v1.7.8 checked-in Swagger and implementation source.
3. Official CrowdSec user documentation.
4. Mock-only expectations, clearly labeled below.

Source references are listed in `docs/discovery.md`.

## 2. Verified live, read-only behavior

- LAPI is healthy at `http://crowdsec:8080` on the `monitor` Docker network.
- `GET /health` returns 200 without authentication.
- `GET /v1/heartbeat` rejects unauthenticated requests with 401.
- `GET /v1/decisions` rejects unauthenticated requests with 403.
- The existing `crowdshield-dev` credential file has the expected CrowdSec `url`, `login`, and `password` shape.
- `POST /v1/watchers/login` with that credential returned 200 and a token/expiry response.
- A machine-JWT `GET /v1/alerts` filtered to a nonexistent Crowdshield scenario returned 200 with no matching alerts.
- LAPI is reachable by the `crowdsec` alias from another container on `monitor`.

No create or delete route was exercised.

## 3. Verified authentication contract

### Request

`POST /v1/watchers/login`

Conceptual JSON shape (no real values):

```json
{
  "machine_id": "<credential login>",
  "password": "<credential password>",
  "scenarios": []
}
```

`machine_id` and `password` are required. `scenarios` is optional.

### Response

```json
{
  "code": 200,
  "expire": "<RFC3339 timestamp>",
  "token": "<JWT>"
}
```

### Middleware behavior

Verified from v1.7.8 source:

- password authentication uses the machine record and bcrypt comparison;
- machine must be validated;
- JWT `Timeout` is one hour;
- JWT `MaxRefresh` is one hour;
- token is accepted as `Authorization: Bearer <token>`;
- the User-Agent is split on `/` and must have exactly two components;
- authentication updates machine metadata such as observed address/version inside CrowdSec.

Client requirements:

- use exactly `crowdshield/<version>` as User-Agent;
- keep token only in memory;
- refresh before expiry;
- retry authentication once after 401, never in an unbounded loop;
- do not surface login, password, token, URL, or raw auth response.

## 4. Verified route authorization split

### Machine JWT routes used by Crowdshield

- `GET /v1/heartbeat`
- `GET /v1/alerts`
- `POST /v1/alerts`
- `GET /v1/alerts/{alert_id}`
- `DELETE /v1/decisions`
- `DELETE /v1/decisions/{decision_id}`

Crowdshield will use only exact-ID delete, not the broad delete route.

### Bouncer-key route not used

- `GET /v1/decisions`

The Swagger security definition associates this route with `APIKeyAuthorizer`, used by remediation components/bouncers. A dedicated machine credential is not a bouncer credential. Crowdshield must not request or depend on a bouncer key.

## 5. Verified decision creation model

There is no `POST /v1/decisions` route in the v1.7.8 Swagger.

Machines create decisions by posting Alerts:

`POST /v1/alerts`

Request body is an array of Alert objects. Relevant required Alert fields include:

- `capacity`
- `decisions`
- `events`
- `events_count`
- `leakspeed`
- `machine_id`
- `message`
- `scenario`
- `scenario_hash`
- `scenario_version`
- `simulated`
- `source`
- `start_at`
- `stop_at`

Relevant Decision fields are all required:

- `duration`
- `origin`
- `scenario`
- `scope`
- `type`
- `value`

Conceptual object (indicator intentionally omitted):

```json
{
  "origin": "crowdshield",
  "scenario": "crowdshield/<feed-name>",
  "scope": "ip-or-range",
  "type": "ban",
  "value": "<normalized indicator>",
  "duration": "25h"
}
```

The Alert uses a non-indicator source:

```json
{
  "scope": "service",
  "value": "crowdshield"
}
```

This prevents an individual feed value from being copied into the Alert source/message.

The controller sets the alert's machine ID from the JWT identity rather than trusting a foreign request identity. Database creation preserves custom decision origin/scenario and calculates `until` from the supplied duration.

## 6. Verified response and ID behavior

Successful `POST /v1/alerts` returns an array of objects with Alert IDs:

```json
[
  {"id": 123}
]
```

It does not directly return decision IDs.

`GET /v1/alerts/{alert_id}` returns the Alert with attached Decisions, including each decision's ID, origin, scenario, scope, value, type, and remaining duration.

Implication: create is not complete from Crowdshield's perspective until every returned alert is read and every expected decision is matched exactly.

## 7. Verified list behavior and limitations

`GET /v1/alerts` supports query filters including:

- `scenario`
- `origin`
- `scope`
- `value`
- `type`
- `since`
- `until`
- `has_active_decision`
- `simulated`
- `limit`

The v1.7.8 contract exposes no cursor or page number. `limit` is not pagination.

An upstream issue for this version reports problematic origin-filtered queries. Normal operation must therefore use locally recorded exact alert IDs. Recovery may use narrow scenario/time-window queries with hard response/record limits, but a broad origin inventory is not a correctness dependency.

## 8. Verified duplicate and refresh behavior

The v1.7.8 decision database schema does not define a uniqueness constraint over origin/scenario/scope/value. Alert creation inserts decisions without searching for an equivalent active manual decision.

There is no update or refresh route for a decision.

Therefore:

- re-posting an equivalent decision can create a duplicate;
- refreshing requires a replacement create followed by exact old-ID expiration;
- duplicate-free steady state is an application responsibility;
- a short replacement overlap is expected and safer than an enforcement gap.

## 9. Verified delete behavior

`DELETE /v1/decisions/{decision_id}` accepts a machine JWT.

The controller/database implementation expires the selected decision by updating its `until` value to the current time. It does not immediately hard-delete the row.

The endpoint itself does not enforce Crowdshield ownership. Any valid machine capable of calling it can target an ID. Crowdshield must therefore verify ownership before every call.

Crowdshield will never call filtered bulk delete, even though the route exists.

## 10. Ownership proof

A decision is safe for Crowdshield to expire only if all conditions are true at the time of deletion:

1. SQLite has an active ownership record for the exact decision ID and alert ID.
2. `GET /v1/alerts/{alert_id}` succeeds or gives an explicitly handled already-gone result.
3. Returned alert machine ID equals the current credential login.
4. The exact decision ID is attached to the alert.
5. Origin equals `crowdshield`.
6. Scenario equals the locally recorded `crowdshield/<feed-name>` value.
7. Scope, type, and normalized value equal local state.
8. The local operation requesting deletion is a valid missing-grace, allowlist, feed-disable, replacement, or confirmed-prune transition.

Machine ID alone is insufficient. Origin/scenario alone are insufficient. A locally recorded ID alone is insufficient when a live object can still be read.

## 11. Alert metadata mapping

Requested concepts map as follows:

| Crowdshield concept | CrowdSec v1.7.8 field |
| --- | --- |
| Stable integration origin | Decision `origin = crowdshield` |
| Per-feed provenance closest representation | Decision/Alert `scenario = crowdshield/<feed-name>` |
| Human reason | Alert `message = External threat feed: <feed-name>`; `cscli` commonly presents scenario as reason |
| Decision action | Decision `type = ban` |
| Individual address | Decision `scope = ip` |
| CIDR | Decision `scope = range` |
| TTL | Decision `duration = 25h` by default |
| Owning machine | Alert `machine_id`, set from JWT |
| Crash-recovery operation token | Alert `scenario_hash` and/or bounded label, subject to mock/real compatibility test |
| Complete provenance for duplicates | SQLite, because one decision has one scenario |

CrowdSec normalizes known scope names. Crowdshield still sends canonical lower-case scope values and accepts equivalent normalized case when reading.

## 12. Mock-required behavior

The mock LAPI must implement the verified contract plus controllable failure modes:

- successful and failed login;
- one-hour token expiry and 401 refresh path;
- malformed login response;
- alert creation and returned alert IDs;
- exact alert retrieval with decision IDs;
- replacement creating a second active decision until old expiration;
- exact decision expiration;
- active/expired filtering;
- machine IDs, foreign origins/scenarios, and foreign decisions;
- equivalent duplicate decisions;
- bounded list semantics and configured limit;
- 429 plus `Retry-After`;
- 500 responses;
- delayed/time-out responses;
- malformed/truncated/oversized JSON;
- ambiguous create timeout after server-side insertion.

The mock must not silently implement an update endpoint or uniqueness guarantee that real v1.7.8 lacks.

## 13. Assumptions not yet proven by a real write

The following are supported by source but intentionally not live-tested:

1. A custom `origin=crowdshield` is accepted in the installed deployment.
2. `scope=ip` and `scope=range` are accepted with canonical values.
3. `duration=25h` is accepted and reflected accurately in returned duration/expiry.
4. Alert source `scope=service`, `value=crowdshield` is accepted.
5. One Alert can safely carry the configured decision batch size.
6. `scenario_hash`/labels are returned unchanged and can identify ambiguous create outcomes.
7. Exact decision delete returns the documented count/ID response and expires only that row.
8. Machine list filters perform adequately at expected Crowdshield volumes.
9. A decision created by the development machine is visible immediately through exact Alert GET.
10. LAPI logs do not unexpectedly emit valid submitted indicators during normal successful requests.

Implementation must not claim these were observed live. The optional real-LAPI plan will test a tiny, short-lived, user-approved documentation-only object and record before/after counts.

## 14. Compatibility checks at runtime

Crowdshield should fail closed or become unready when:

- login response lacks token/expiry;
- token cannot access machine Alert routes;
- create response lacks valid positive Alert IDs;
- exact Alert response lacks expected decisions;
- response exceeds configured limits;
- scope/origin/scenario round-trip differs unexpectedly;
- ownership proof fails;
- delete response is malformed or reports an unexpected target;
- server consistently returns an unsupported API behavior.

It should not print raw payloads while reporting these failures.

## 15. Optional real-LAPI validation boundary

No real write is authorized by this document. The future plan in operations/development documentation must require explicit user approval immediately before execution and must:

- inventory exact before counts;
- use a user-approved documentation-only address/prefix accepted by CrowdSec;
- use a short TTL and unique Crowdshield development scenario;
- create one decision;
- verify exact metadata and ID;
- expire only that exact ID;
- inventory exact after counts;
- confirm unrelated IDs/counts are unchanged;
- include rollback for every step.
