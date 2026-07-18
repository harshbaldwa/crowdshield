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

func validPruneOptions(s *Store, ctx context.Context, now time.Time, retention time.Duration, maxHistoryEntries int) bool {
	return s != nil && s.db != nil && ctx != nil && !now.IsZero() && now.Unix() >= 0 &&
		retention >= time.Hour && retention <= 10*365*24*time.Hour &&
		maxHistoryEntries >= 1 && maxHistoryEntries <= 1_000_000
}

func (s *Store) CountAmbiguousOperations(ctx context.Context) (int64, error) {
	if s == nil || s.db == nil || ctx == nil {
		return 0, stateError(ErrConstraint, nil)
	}
	var count int64
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM lapi_operations WHERE status='ambiguous'`).Scan(&count); err != nil || count < 0 || count > 100_000_000 {
		return 0, stateError(ErrQuery, err)
	}
	return count, nil
}

// PlanPruneHistory returns the rows that PruneHistory would remove without
// opening a transaction or modifying database/runtime state.
func (s *Store) PlanPruneHistory(ctx context.Context, now time.Time, retention time.Duration, maxHistoryEntries int) (PruneResult, error) {
	if !validPruneOptions(s, ctx, now, retention, maxHistoryEntries) {
		return PruneResult{}, stateError(ErrConstraint, nil)
	}
	cutoff := unix(now.Add(-retention))
	var result PruneResult
	err := s.db.QueryRowContext(ctx, `
WITH old_sync_runs AS (
    SELECT id FROM sync_runs
    WHERE completed_at IS NOT NULL
      AND status IN ('success', 'degraded', 'failed', 'cancelled')
      AND (
          completed_at < ?
          OR id NOT IN (
              SELECT id FROM sync_runs
              WHERE completed_at IS NOT NULL
                AND status IN ('success', 'degraded', 'failed', 'cancelled')
              ORDER BY started_at DESC, id DESC
              LIMIT ?
          )
      )
),
old_operations AS (
    SELECT token FROM lapi_operations
    WHERE completed_at IS NOT NULL AND completed_at < ?
      AND status IN ('completed', 'failed')
),
old_decisions AS (
    SELECT d.id FROM lapi_decisions d
    WHERE d.status IN ('expired', 'orphaned')
      AND d.verified_at < ? AND d.expires_at < ?
      AND NOT EXISTS (
          SELECT 1 FROM lapi_operation_items i
          WHERE i.old_decision_row_id = d.id
            AND i.operation_token NOT IN (SELECT token FROM old_operations)
      )
),
old_alerts AS (
    SELECT a.id FROM lapi_alerts a
    WHERE a.created_at < ?
      AND NOT EXISTS (
          SELECT 1 FROM lapi_decisions d
          WHERE d.alert_row_id = a.id
            AND d.id NOT IN (SELECT id FROM old_decisions)
      )
),
old_objects AS (
    SELECT e.id FROM enforcement_objects e
    WHERE e.desired = 0 AND e.updated_at < ?
      AND NOT EXISTS (
          SELECT 1 FROM lapi_decisions d
          WHERE d.object_id = e.id
            AND d.id NOT IN (SELECT id FROM old_decisions)
      )
      AND NOT EXISTS (
          SELECT 1 FROM lapi_operation_items i
          WHERE i.object_id = e.id
            AND i.operation_token NOT IN (SELECT token FROM old_operations)
      )
),
old_entries AS (
    SELECT feed_id, prefix, kind FROM feed_entries
    WHERE active = 0 AND last_seen_at < ?
)
SELECT
    (SELECT COUNT(*) FROM old_sync_runs),
    (SELECT COUNT(*) FROM old_operations),
    (SELECT COUNT(*) FROM old_decisions),
    (SELECT COUNT(*) FROM old_alerts),
    (SELECT COUNT(*) FROM old_objects),
    (SELECT COUNT(*) FROM old_entries)`,
		cutoff, maxHistoryEntries, cutoff, cutoff, cutoff, cutoff, cutoff, cutoff,
	).Scan(
		&result.SyncRuns, &result.Operations, &result.Decisions,
		&result.Alerts, &result.EnforcementObjects, &result.FeedEntries,
	)
	if err != nil {
		return PruneResult{}, stateError(ErrQuery, err)
	}
	return result, nil
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

func (s *Store) PruneHistory(ctx context.Context, now time.Time, retention time.Duration, maxHistoryEntries int) (PruneResult, error) {
	if !validPruneOptions(s, ctx, now, retention, maxHistoryEntries) {
		return PruneResult{}, stateError(ErrConstraint, nil)
	}
	cutoff := unix(now.Add(-retention))
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return PruneResult{}, stateError(ErrTransaction, err)
	}
	defer func() { _ = tx.Rollback() }()
	var result PruneResult
	result.SyncRuns, err = pruneExec(ctx, tx, `
DELETE FROM sync_runs
WHERE completed_at IS NOT NULL
  AND status IN ('success', 'degraded', 'failed', 'cancelled')
  AND (
      completed_at < ?
      OR id NOT IN (
          SELECT id FROM sync_runs
          WHERE completed_at IS NOT NULL
            AND status IN ('success', 'degraded', 'failed', 'cancelled')
          ORDER BY started_at DESC, id DESC
          LIMIT ?
      )
  )`, cutoff, maxHistoryEntries)
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
