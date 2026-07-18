package state

import (
	"context"
	"database/sql"
	"time"
)

type PruneResult struct {
	SyncRuns           int64
	Operations         int64
	Decisions          int64
	Alerts             int64
	EnforcementObjects int64
	FeedEntries        int64
}

func pruneExec(ctx context.Context, tx *sql.Tx, query string, args ...any) (int64, error) {
	result, err := tx.ExecContext(ctx, query, args...)
	if err != nil {
		return 0, stateError(ErrQuery, err)
	}
	count, err := result.RowsAffected()
	if err != nil {
		return 0, stateError(ErrQuery, err)
	}
	return count, nil
}

func (s *Store) PruneHistory(ctx context.Context, now time.Time, retention time.Duration) (PruneResult, error) {
	if s == nil || s.db == nil || ctx == nil || now.IsZero() || now.Unix() < 0 ||
		retention < time.Hour || retention > 10*365*24*time.Hour {
		return PruneResult{}, stateError(ErrConstraint, nil)
	}
	cutoff := unix(now.Add(-retention))
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return PruneResult{}, stateError(ErrTransaction, err)
	}
	defer tx.Rollback()
	var result PruneResult
	result.SyncRuns, err = pruneExec(ctx, tx, `
DELETE FROM sync_runs
WHERE completed_at IS NOT NULL AND completed_at < ?
  AND status IN ('success', 'degraded', 'failed', 'cancelled')`, cutoff)
	if err != nil {
		return PruneResult{}, err
	}
	result.Operations, err = pruneExec(ctx, tx, `
DELETE FROM lapi_operations
WHERE completed_at IS NOT NULL AND completed_at < ?
  AND status IN ('completed', 'failed')`, cutoff)
	if err != nil {
		return PruneResult{}, err
	}
	result.Decisions, err = pruneExec(ctx, tx, `
DELETE FROM lapi_decisions
WHERE status IN ('expired', 'orphaned')
  AND verified_at < ? AND expires_at < ?
  AND NOT EXISTS (
      SELECT 1 FROM lapi_operation_items i
      WHERE i.old_decision_row_id = lapi_decisions.id
  )`, cutoff, cutoff)
	if err != nil {
		return PruneResult{}, err
	}
	result.Alerts, err = pruneExec(ctx, tx, `
DELETE FROM lapi_alerts
WHERE created_at < ?
  AND NOT EXISTS (
      SELECT 1 FROM lapi_decisions d WHERE d.alert_row_id = lapi_alerts.id
  )`, cutoff)
	if err != nil {
		return PruneResult{}, err
	}
	result.EnforcementObjects, err = pruneExec(ctx, tx, `
DELETE FROM enforcement_objects
WHERE desired = 0 AND updated_at < ?
  AND NOT EXISTS (
      SELECT 1 FROM lapi_decisions d WHERE d.object_id = enforcement_objects.id
  )
  AND NOT EXISTS (
      SELECT 1 FROM lapi_operation_items i WHERE i.object_id = enforcement_objects.id
  )`, cutoff)
	if err != nil {
		return PruneResult{}, err
	}
	result.FeedEntries, err = pruneExec(ctx, tx, `
DELETE FROM feed_entries
WHERE active = 0 AND last_seen_at < ?`, cutoff)
	if err != nil {
		return PruneResult{}, err
	}
	if err := setRuntimeTimestamp(ctx, tx, RuntimeLastPrune, now); err != nil {
		return PruneResult{}, err
	}
	if err := tx.Commit(); err != nil {
		return PruneResult{}, stateError(ErrTransaction, err)
	}
	return result, nil
}
