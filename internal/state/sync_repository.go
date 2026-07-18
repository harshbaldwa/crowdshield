package state

import (
	"context"
	"database/sql"
	"strconv"
	"time"

	"crowdshield/internal/ops"
)

type SyncMode string

type RunStatus string

const (
	SyncModeEnforce SyncMode = "enforce"
	SyncModeDryRun  SyncMode = "dry-run"

	RunStatusRunning   RunStatus = "running"
	RunStatusSuccess   RunStatus = "success"
	RunStatusDegraded  RunStatus = "degraded"
	RunStatusFailed    RunStatus = "failed"
	RunStatusCancelled RunStatus = "cancelled"
)

type SyncRunRecord struct {
	ID            int64
	StartedAt     time.Time
	CompletedAt   *time.Time
	Mode          SyncMode
	RequestedFeed string
	Status        RunStatus
	Failure       ops.FailureCategory
	Counts        ops.Counts
	Feeds         []ops.FeedResult
}

type RuntimeTimestampKey string

const (
	RuntimeLastSafeSync RuntimeTimestampKey = "last_safe_sync"
	RuntimeLastPrune    RuntimeTimestampKey = "last_prune"
)

func validSyncMode(mode SyncMode) bool {
	return mode == SyncModeEnforce || mode == SyncModeDryRun
}

func validRunStatus(status RunStatus) bool {
	switch status {
	case RunStatusRunning, RunStatusSuccess, RunStatusDegraded, RunStatusFailed, RunStatusCancelled:
		return true
	default:
		return false
	}
}

func validRuntimeKey(key RuntimeTimestampKey) bool {
	return key == RuntimeLastSafeSync || key == RuntimeLastPrune
}

func (s *Store) BeginSyncRun(ctx context.Context, mode SyncMode, requestedFeed string, startedAt time.Time) (int64, error) {
	if s == nil || s.db == nil || ctx == nil || !validSyncMode(mode) || startedAt.IsZero() ||
		startedAt.Unix() < 0 || (requestedFeed != "" && !ops.ValidFeedName(requestedFeed)) {
		return 0, stateError(ErrConstraint, nil)
	}
	result, err := s.db.ExecContext(ctx, `
INSERT INTO sync_runs(started_at, mode, requested_feed, status)
VALUES(?, ?, ?, ?)`, unix(startedAt), string(mode), requestedFeed, string(RunStatusRunning))
	if err != nil {
		return 0, stateError(ErrQuery, err)
	}
	id, err := result.LastInsertId()
	if err != nil || id <= 0 {
		return 0, stateError(ErrQuery, err)
	}
	return id, nil
}

func statusForResult(result ops.Result) (RunStatus, bool) {
	switch result.Outcome {
	case ops.OutcomeSuccess:
		return RunStatusSuccess, true
	case ops.OutcomeDegraded:
		return RunStatusDegraded, true
	case ops.OutcomeFailed:
		return RunStatusFailed, true
	case ops.OutcomeCancelled:
		return RunStatusCancelled, true
	default:
		return "", false
	}
}

func feedHistoryStatus(feed ops.FeedResult) (string, bool) {
	switch feed.Outcome {
	case ops.OutcomeSuccess:
		return "success", true
	case ops.OutcomeNotModified:
		return "not_modified", true
	case ops.OutcomeNotDue:
		return "not_due", true
	case ops.OutcomeFailed:
		return "failed", true
	case ops.OutcomeDegraded:
		if feed.Failure == ops.FailureFeedValidation {
			return "suspicious", true
		}
		return "failed", true
	default:
		return "", false
	}
}

func safeSyncResult(result ops.Result) bool {
	return result.Outcome == ops.OutcomeSuccess ||
		(result.Outcome == ops.OutcomeDegraded &&
			(result.Failure == ops.FailureFeedDownload || result.Failure == ops.FailureFeedValidation))
}

type runtimeQueryer interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}

func setRuntimeTimestamp(ctx context.Context, queryer runtimeQueryer, key RuntimeTimestampKey, at time.Time) error {
	if ctx == nil || queryer == nil || !validRuntimeKey(key) || at.IsZero() || at.Unix() < 0 {
		return stateError(ErrConstraint, nil)
	}
	var raw string
	err := queryer.QueryRowContext(ctx, `SELECT value FROM runtime_state WHERE key=?`, string(key)).Scan(&raw)
	if err != nil && err != sql.ErrNoRows {
		return stateError(ErrQuery, err)
	}
	if err == nil {
		seconds, parseErr := strconv.ParseInt(raw, 10, 64)
		if parseErr != nil || seconds < 0 || strconv.FormatInt(seconds, 10) != raw {
			return stateError(ErrIntegrity, parseErr)
		}
		if seconds >= at.UTC().Unix() {
			return nil
		}
	}
	_, err = queryer.ExecContext(ctx, `
INSERT INTO runtime_state(key, value, updated_at) VALUES(?, ?, ?)
ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at`,
		string(key), strconv.FormatInt(at.UTC().Unix(), 10), at.UTC().Unix())
	if err != nil {
		return stateError(ErrQuery, err)
	}
	return nil
}

func (s *Store) SetRuntimeTimestamp(ctx context.Context, key RuntimeTimestampKey, at time.Time) error {
	if s == nil || s.db == nil {
		return stateError(ErrConstraint, nil)
	}
	return setRuntimeTimestamp(ctx, s.db, key, at)
}

func (s *Store) RuntimeTimestamp(ctx context.Context, key RuntimeTimestampKey) (time.Time, bool, error) {
	if s == nil || s.db == nil || ctx == nil || !validRuntimeKey(key) {
		return time.Time{}, false, stateError(ErrConstraint, nil)
	}
	var raw string
	err := s.db.QueryRowContext(ctx, `SELECT value FROM runtime_state WHERE key=?`, string(key)).Scan(&raw)
	if err == sql.ErrNoRows {
		return time.Time{}, false, nil
	}
	if err != nil {
		return time.Time{}, false, stateError(ErrQuery, err)
	}
	seconds, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || seconds < 0 || strconv.FormatInt(seconds, 10) != raw {
		return time.Time{}, false, stateError(ErrIntegrity, err)
	}
	return time.Unix(seconds, 0).UTC(), true, nil
}

func (s *Store) CompleteSyncRun(ctx context.Context, runID int64, result ops.Result) error {
	status, validStatus := statusForResult(result)
	if s == nil || s.db == nil || ctx == nil || runID <= 0 || result.Validate() != nil || !validStatus {
		return stateError(ErrConstraint, nil)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return stateError(ErrTransaction, err)
	}
	defer tx.Rollback()
	var startedAt int64
	var currentStatus string
	if err := tx.QueryRowContext(ctx, `SELECT started_at, status FROM sync_runs WHERE id=?`, runID).Scan(&startedAt, &currentStatus); err != nil {
		if err == sql.ErrNoRows {
			return stateError(ErrNotFound, err)
		}
		return stateError(ErrQuery, err)
	}
	if currentStatus != string(RunStatusRunning) || result.CompletedAt.Unix() < startedAt {
		return stateError(ErrConstraint, nil)
	}
	for _, feed := range result.Feeds {
		historyStatus, ok := feedHistoryStatus(feed)
		if !ok {
			return stateError(ErrConstraint, nil)
		}
		var feedID int64
		if err := tx.QueryRowContext(ctx, `SELECT id FROM feeds WHERE name=?`, feed.Name).Scan(&feedID); err != nil {
			if err == sql.ErrNoRows {
				return stateError(ErrNotFound, err)
			}
			return stateError(ErrQuery, err)
		}
		if _, err := tx.ExecContext(ctx, `
INSERT INTO feed_run_results(sync_run_id, feed_id, status, accepted, rejected, error_category)
VALUES(?, ?, ?, ?, ?, ?)`, runID, feedID, historyStatus, feed.Accepted, feed.Rejected, string(feed.Failure)); err != nil {
			return stateError(ErrQuery, err)
		}
	}
	update, err := tx.ExecContext(ctx, `
UPDATE sync_runs SET
    completed_at=?, status=?, feeds_succeeded=?, feeds_failed=?, added=?, refreshed=?,
    removed=?, rejected=?, skipped=?, lapi_requests=?, error_category=?
WHERE id=? AND status=?`,
		unix(result.CompletedAt), string(status), result.Counts.FeedsSucceeded, result.Counts.FeedsFailed,
		result.Counts.Added, result.Counts.Refreshed, result.Counts.Removed, result.Counts.Rejected,
		result.Counts.Skipped, result.Counts.LAPIRequests, string(result.Failure), runID, string(RunStatusRunning))
	if err != nil {
		return stateError(ErrQuery, err)
	}
	changed, err := update.RowsAffected()
	if err != nil || changed != 1 {
		return stateError(ErrConstraint, err)
	}
	if safeSyncResult(result) {
		if err := setRuntimeTimestamp(ctx, tx, RuntimeLastSafeSync, result.CompletedAt); err != nil {
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		return stateError(ErrTransaction, err)
	}
	return nil
}

func runStatusFromString(value string) (RunStatus, bool) {
	status := RunStatus(value)
	return status, validRunStatus(status)
}

func feedResultFromHistory(name, status, failure string, accepted, rejected int64) (ops.FeedResult, error) {
	result := ops.FeedResult{
		Name: name, Failure: ops.FailureCategory(failure),
		Accepted: accepted, Rejected: rejected,
	}
	switch status {
	case "success":
		result.Outcome = ops.OutcomeSuccess
	case "not_modified":
		result.Outcome = ops.OutcomeNotModified
	case "not_due":
		result.Outcome = ops.OutcomeNotDue
	case "failed":
		result.Outcome = ops.OutcomeFailed
	case "suspicious":
		result.Outcome = ops.OutcomeDegraded
	default:
		return ops.FeedResult{}, stateError(ErrIntegrity, nil)
	}
	if result.Validate() != nil {
		return ops.FeedResult{}, stateError(ErrIntegrity, nil)
	}
	return result, nil
}

func (s *Store) ListSyncRuns(ctx context.Context, limit int) ([]SyncRunRecord, error) {
	if s == nil || s.db == nil || ctx == nil || limit < 1 || limit > 1000 {
		return nil, stateError(ErrConstraint, nil)
	}
	rows, err := s.db.QueryContext(ctx, `
SELECT id, started_at, completed_at, mode, requested_feed, status,
       feeds_succeeded, feeds_failed, added, refreshed, removed, rejected,
       skipped, lapi_requests, error_category
FROM sync_runs ORDER BY started_at DESC, id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, stateError(ErrQuery, err)
	}
	defer rows.Close()
	runs := make([]SyncRunRecord, 0)
	for rows.Next() {
		var run SyncRunRecord
		var started int64
		var completed sql.NullInt64
		var mode, status, failure string
		if err := rows.Scan(
			&run.ID, &started, &completed, &mode, &run.RequestedFeed, &status,
			&run.Counts.FeedsSucceeded, &run.Counts.FeedsFailed, &run.Counts.Added,
			&run.Counts.Refreshed, &run.Counts.Removed, &run.Counts.Rejected,
			&run.Counts.Skipped, &run.Counts.LAPIRequests, &failure,
		); err != nil {
			return nil, stateError(ErrQuery, err)
		}
		run.Mode = SyncMode(mode)
		run.Status, _ = runStatusFromString(status)
		run.Failure = ops.FailureCategory(failure)
		run.StartedAt = time.Unix(started, 0).UTC()
		if completed.Valid {
			value := time.Unix(completed.Int64, 0).UTC()
			run.CompletedAt = &value
		}
		if run.ID <= 0 || !validSyncMode(run.Mode) || !validRunStatus(run.Status) ||
			(run.RequestedFeed != "" && !ops.ValidFeedName(run.RequestedFeed)) || run.Counts.Validate() != nil ||
			(run.Failure != "" && !ops.ValidFailureCategory(run.Failure)) ||
			(run.Status == RunStatusRunning && run.CompletedAt != nil) ||
			(run.Status != RunStatusRunning && run.CompletedAt == nil) {
			return nil, stateError(ErrIntegrity, nil)
		}
		runs = append(runs, run)
	}
	if err := rows.Err(); err != nil {
		return nil, stateError(ErrQuery, err)
	}
	if err := rows.Close(); err != nil {
		return nil, stateError(ErrQuery, err)
	}
	for index := range runs {
		feedRows, err := s.db.QueryContext(ctx, `
SELECT f.name, r.status, r.accepted, r.rejected, r.error_category
FROM feed_run_results r JOIN feeds f ON f.id=r.feed_id
WHERE r.sync_run_id=? ORDER BY f.id`, runs[index].ID)
		if err != nil {
			return nil, stateError(ErrQuery, err)
		}
		for feedRows.Next() {
			var name, status, failure string
			var accepted, rejected int64
			if err := feedRows.Scan(&name, &status, &accepted, &rejected, &failure); err != nil {
				feedRows.Close()
				return nil, stateError(ErrQuery, err)
			}
			feed, err := feedResultFromHistory(name, status, failure, accepted, rejected)
			if err != nil {
				feedRows.Close()
				return nil, err
			}
			runs[index].Feeds = append(runs[index].Feeds, feed)
		}
		if err := feedRows.Err(); err != nil {
			feedRows.Close()
			return nil, stateError(ErrQuery, err)
		}
		if err := feedRows.Close(); err != nil {
			return nil, stateError(ErrQuery, err)
		}
	}
	return runs, nil
}

func (s *Store) RecoverInterruptedSyncRuns(ctx context.Context, now time.Time) (int64, error) {
	if s == nil || s.db == nil || ctx == nil || now.IsZero() || now.Unix() < 0 {
		return 0, stateError(ErrConstraint, nil)
	}
	result, err := s.db.ExecContext(ctx, `
UPDATE sync_runs SET completed_at=?, status=?, error_category=?
WHERE status=?`, unix(now), string(RunStatusFailed), string(ops.FailureRuntime), string(RunStatusRunning))
	if err != nil {
		return 0, stateError(ErrQuery, err)
	}
	count, err := result.RowsAffected()
	if err != nil {
		return 0, stateError(ErrQuery, err)
	}
	return count, nil
}
