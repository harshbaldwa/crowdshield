-- Crowdshield schema version 2. Stores only closed notification state; never message bodies, URLs, tokens, or arbitrary errors.

CREATE TABLE notification_delivery_state (
    kind TEXT NOT NULL CHECK (kind IN (
        'startup', 'first_success', 'routine_success', 'repeated_failure',
        'recovery', 'suspicious_change', 'stale_sync'
    )),
    key_feed TEXT NOT NULL DEFAULT '',
    failure_category TEXT NOT NULL DEFAULT '' CHECK (failure_category IN (
        '', 'feed_download', 'feed_validation', 'lapi_auth', 'lapi_conflict',
        'lapi_ambiguous', 'lapi', 'database', 'notification', 'configuration',
        'credentials', 'timeout', 'cancelled', 'runtime'
    )),
    state_feed TEXT NOT NULL DEFAULT '',
    consecutive_failures INTEGER NOT NULL DEFAULT 0 CHECK (consecutive_failures BETWEEN 0 AND 100),
    notified INTEGER NOT NULL DEFAULT 0 CHECK (notified IN (0, 1)),
    recovery_pending INTEGER NOT NULL DEFAULT 0 CHECK (recovery_pending IN (0, 1)),
    sent INTEGER NOT NULL DEFAULT 0 CHECK (sent IN (0, 1)),
    last_attempt_at INTEGER CHECK (last_attempt_at IS NULL OR last_attempt_at >= 0),
    updated_at INTEGER NOT NULL CHECK (updated_at > 0),
    PRIMARY KEY (kind, key_feed),
    CHECK (
        (kind = 'suspicious_change' AND length(key_feed) BETWEEN 1 AND 64
         AND key_feed GLOB '[a-z0-9]*' AND key_feed NOT GLOB '*[^a-z0-9-]*'
         AND substr(key_feed, -1, 1) GLOB '[a-z0-9]')
        OR (kind <> 'suspicious_change' AND key_feed = '')
    ),
    CHECK (
        state_feed = '' OR
        (length(state_feed) BETWEEN 1 AND 64
         AND state_feed GLOB '[a-z0-9]*' AND state_feed NOT GLOB '*[^a-z0-9-]*'
         AND substr(state_feed, -1, 1) GLOB '[a-z0-9]')
    ),
    CHECK (
        (consecutive_failures = 0 AND notified = 0 AND recovery_pending = 0)
        OR (kind = 'repeated_failure' AND failure_category <> '')
    ),
    CHECK (
        kind = 'repeated_failure'
        OR (failure_category = '' AND state_feed = '' AND consecutive_failures = 0
            AND notified = 0 AND recovery_pending = 0)
    ),
    CHECK (sent = 0 OR kind IN ('first_success', 'stale_sync'))
) STRICT, WITHOUT ROWID;
