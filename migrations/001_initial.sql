-- Crowdshield schema version 1. Credentials and raw feed payloads are never stored.

CREATE TABLE feeds (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    url_hash TEXT NOT NULL,
    definition_hash TEXT NOT NULL,
    enabled INTEGER NOT NULL CHECK (enabled IN (0, 1)),
    etag TEXT NOT NULL DEFAULT '',
    last_modified TEXT NOT NULL DEFAULT '',
    last_attempt_at INTEGER,
    last_success_at INTEGER,
    last_good_version TEXT NOT NULL DEFAULT '',
    accepted_entries INTEGER NOT NULL DEFAULT 0 CHECK (accepted_entries >= 0),
    rejected_entries INTEGER NOT NULL DEFAULT 0 CHECK (rejected_entries >= 0),
    consecutive_failures INTEGER NOT NULL DEFAULT 0 CHECK (consecutive_failures >= 0),
    next_attempt_at INTEGER,
    last_error_category TEXT NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
) STRICT;

CREATE TABLE feed_entries (
    feed_id INTEGER NOT NULL REFERENCES feeds(id) ON DELETE CASCADE,
    prefix TEXT NOT NULL,
    family INTEGER NOT NULL CHECK (family IN (4, 6)),
    prefix_bits INTEGER NOT NULL CHECK (prefix_bits >= 0 AND prefix_bits <= 128),
    kind INTEGER NOT NULL CHECK (kind IN (1, 2)),
    first_seen_at INTEGER NOT NULL,
    last_seen_at INTEGER NOT NULL,
    missing_runs INTEGER NOT NULL DEFAULT 0 CHECK (missing_runs >= 0),
    active INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0, 1)),
    PRIMARY KEY (feed_id, prefix, kind)
) STRICT;

CREATE INDEX feed_entries_active_idx ON feed_entries(feed_id, active, missing_runs);
CREATE INDEX feed_entries_prefix_idx ON feed_entries(prefix, active);

CREATE TABLE enforcement_objects (
    id INTEGER PRIMARY KEY,
    prefix TEXT NOT NULL UNIQUE,
    family INTEGER NOT NULL CHECK (family IN (4, 6)),
    prefix_bits INTEGER NOT NULL CHECK (prefix_bits >= 0 AND prefix_bits <= 128),
    scope TEXT NOT NULL CHECK (scope IN ('Ip', 'Range')),
    desired INTEGER NOT NULL CHECK (desired IN (0, 1)),
    suppression TEXT NOT NULL DEFAULT '',
    primary_feed_id INTEGER REFERENCES feeds(id) ON DELETE SET NULL,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
) STRICT;

CREATE TABLE enforcement_sources (
    object_id INTEGER NOT NULL REFERENCES enforcement_objects(id) ON DELETE CASCADE,
    feed_id INTEGER NOT NULL REFERENCES feeds(id) ON DELETE CASCADE,
    source_kind INTEGER NOT NULL CHECK (source_kind IN (1, 2)),
    PRIMARY KEY (object_id, feed_id, source_kind)
) STRICT;

CREATE TABLE lapi_alerts (
    id INTEGER PRIMARY KEY,
    alert_id INTEGER NOT NULL UNIQUE,
    operation_token TEXT NOT NULL UNIQUE,
    machine_id TEXT NOT NULL,
    origin TEXT NOT NULL,
    scenario TEXT NOT NULL,
    verified_at INTEGER NOT NULL,
    created_at INTEGER NOT NULL
) STRICT;

CREATE TABLE lapi_decisions (
    id INTEGER PRIMARY KEY,
    object_id INTEGER NOT NULL REFERENCES enforcement_objects(id) ON DELETE RESTRICT,
    alert_row_id INTEGER NOT NULL REFERENCES lapi_alerts(id) ON DELETE RESTRICT,
    decision_id INTEGER NOT NULL UNIQUE,
    origin TEXT NOT NULL,
    scenario TEXT NOT NULL,
    scope TEXT NOT NULL CHECK (scope IN ('Ip', 'Range')),
    value TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    verified_at INTEGER NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('active', 'expiring', 'expired', 'orphaned')),
    replaced_by_id INTEGER REFERENCES lapi_decisions(id) ON DELETE SET NULL
) STRICT;

CREATE INDEX lapi_decisions_object_status_idx ON lapi_decisions(object_id, status, expires_at);

CREATE TABLE lapi_operations (
    token TEXT PRIMARY KEY,
    kind TEXT NOT NULL CHECK (kind IN ('create', 'refresh', 'expire', 'recover')),
    feed_id INTEGER NOT NULL REFERENCES feeds(id) ON DELETE RESTRICT,
    duration_seconds INTEGER NOT NULL CHECK (duration_seconds > 0),
    payload_hash TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('pending', 'verified', 'completed', 'failed', 'ambiguous')),
    started_at INTEGER NOT NULL,
    completed_at INTEGER,
    error_category TEXT NOT NULL DEFAULT ''
) STRICT, WITHOUT ROWID;

CREATE INDEX lapi_operations_status_idx ON lapi_operations(status, started_at);

CREATE TABLE lapi_operation_items (
    operation_token TEXT NOT NULL REFERENCES lapi_operations(token) ON DELETE CASCADE,
    object_id INTEGER NOT NULL REFERENCES enforcement_objects(id) ON DELETE RESTRICT,
    old_decision_row_id INTEGER REFERENCES lapi_decisions(id) ON DELETE RESTRICT,
    PRIMARY KEY (operation_token, object_id)
) STRICT, WITHOUT ROWID;

CREATE TABLE sync_runs (
    id INTEGER PRIMARY KEY,
    started_at INTEGER NOT NULL,
    completed_at INTEGER,
    mode TEXT NOT NULL CHECK (mode IN ('enforce', 'dry-run')),
    requested_feed TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL CHECK (status IN ('running', 'success', 'degraded', 'failed', 'cancelled')),
    feeds_succeeded INTEGER NOT NULL DEFAULT 0 CHECK (feeds_succeeded >= 0),
    feeds_failed INTEGER NOT NULL DEFAULT 0 CHECK (feeds_failed >= 0),
    added INTEGER NOT NULL DEFAULT 0 CHECK (added >= 0),
    refreshed INTEGER NOT NULL DEFAULT 0 CHECK (refreshed >= 0),
    removed INTEGER NOT NULL DEFAULT 0 CHECK (removed >= 0),
    rejected INTEGER NOT NULL DEFAULT 0 CHECK (rejected >= 0),
    skipped INTEGER NOT NULL DEFAULT 0 CHECK (skipped >= 0),
    lapi_requests INTEGER NOT NULL DEFAULT 0 CHECK (lapi_requests >= 0),
    error_category TEXT NOT NULL DEFAULT ''
) STRICT;

CREATE INDEX sync_runs_started_idx ON sync_runs(started_at DESC);

CREATE TABLE feed_run_results (
    sync_run_id INTEGER NOT NULL REFERENCES sync_runs(id) ON DELETE CASCADE,
    feed_id INTEGER NOT NULL REFERENCES feeds(id) ON DELETE CASCADE,
    status TEXT NOT NULL CHECK (status IN ('success', 'not_modified', 'not_due', 'failed', 'suspicious')),
    accepted INTEGER NOT NULL DEFAULT 0 CHECK (accepted >= 0),
    rejected INTEGER NOT NULL DEFAULT 0 CHECK (rejected >= 0),
    error_category TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (sync_run_id, feed_id)
) STRICT;

CREATE TABLE notification_state (
    event_key TEXT PRIMARY KEY,
    consecutive_failures INTEGER NOT NULL DEFAULT 0 CHECK (consecutive_failures >= 0),
    notified INTEGER NOT NULL DEFAULT 0 CHECK (notified IN (0, 1)),
    last_notification_at INTEGER,
    updated_at INTEGER NOT NULL
) STRICT, WITHOUT ROWID;

CREATE TABLE runtime_state (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at INTEGER NOT NULL
) STRICT, WITHOUT ROWID;
