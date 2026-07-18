package state

import (
	"context"
	"database/sql"
	"time"

	"crowdshield/internal/notify"
	"crowdshield/internal/ops"
)

type NotificationStateStore struct {
	store *Store
}

func (s *Store) NotificationStates() *NotificationStateStore {
	return &NotificationStateStore{store: s}
}

func (r *NotificationStateStore) Load(ctx context.Context, key notify.StateKey) (notify.PersistentState, bool, error) {
	if r == nil || r.store == nil || r.store.db == nil || ctx == nil || key.Validate() != nil {
		return notify.PersistentState{}, false, stateError(ErrConstraint, nil)
	}
	var failure, feed string
	var consecutive, notified, recoveryPending, sent int
	var lastAttempt sql.NullInt64
	var updatedAt int64
	err := r.store.db.QueryRowContext(ctx, `
SELECT failure_category, state_feed, consecutive_failures, notified,
       recovery_pending, sent, last_attempt_at, updated_at
FROM notification_delivery_state
WHERE kind=? AND key_feed=?`, string(key.Kind), key.Feed).Scan(
		&failure, &feed, &consecutive, &notified, &recoveryPending,
		&sent, &lastAttempt, &updatedAt,
	)
	if err == sql.ErrNoRows {
		return notify.PersistentState{Key: key}, false, nil
	}
	if err != nil {
		return notify.PersistentState{}, false, stateError(ErrQuery, err)
	}
	if (notified != 0 && notified != 1) || (recoveryPending != 0 && recoveryPending != 1) ||
		(sent != 0 && sent != 1) || updatedAt <= 0 {
		return notify.PersistentState{}, false, stateError(ErrIntegrity, nil)
	}
	state := notify.PersistentState{
		Key: key, Failure: ops.FailureCategory(failure), Feed: feed,
		ConsecutiveFailures: consecutive, Notified: notified == 1,
		RecoveryPending: recoveryPending == 1, Sent: sent == 1,
		UpdatedAt: time.Unix(updatedAt, 0).UTC(),
	}
	if lastAttempt.Valid {
		if lastAttempt.Int64 < 0 {
			return notify.PersistentState{}, false, stateError(ErrIntegrity, nil)
		}
		state.LastAttempt = time.Unix(lastAttempt.Int64, 0).UTC()
	}
	if state.Validate() != nil {
		return notify.PersistentState{}, false, stateError(ErrIntegrity, nil)
	}
	return state, true, nil
}

func (r *NotificationStateStore) Save(ctx context.Context, state notify.PersistentState) error {
	if r == nil || r.store == nil || r.store.db == nil || ctx == nil ||
		state.Validate() != nil || state.UpdatedAt.IsZero() {
		return stateError(ErrConstraint, nil)
	}
	var lastAttempt any
	if !state.LastAttempt.IsZero() {
		lastAttempt = unix(state.LastAttempt)
	}
	result, err := r.store.db.ExecContext(ctx, `
INSERT INTO notification_delivery_state(
    kind, key_feed, failure_category, state_feed, consecutive_failures,
    notified, recovery_pending, sent, last_attempt_at, updated_at
) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(kind, key_feed) DO UPDATE SET
    failure_category=excluded.failure_category,
    state_feed=excluded.state_feed,
    consecutive_failures=excluded.consecutive_failures,
    notified=excluded.notified,
    recovery_pending=excluded.recovery_pending,
    sent=excluded.sent,
    last_attempt_at=excluded.last_attempt_at,
    updated_at=excluded.updated_at`,
		string(state.Key.Kind), state.Key.Feed, string(state.Failure), state.Feed,
		state.ConsecutiveFailures, boolInt(state.Notified), boolInt(state.RecoveryPending),
		boolInt(state.Sent), lastAttempt, unix(state.UpdatedAt),
	)
	if err != nil {
		return stateError(ErrQuery, err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return stateError(ErrQuery, err)
	}
	if rows != 1 {
		return stateError(ErrIntegrity, nil)
	}
	return nil
}
