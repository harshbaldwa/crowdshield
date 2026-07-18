package state

import (
	"context"
	"testing"
	"time"

	"crowdshield/internal/notify"
	"crowdshield/internal/ops"
)

func TestPruneHistoryDeletesOnlyExpiredTerminalOwnedHistory(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC)
	old := now.Add(-60 * 24 * time.Hour)
	recent := now.Add(-24 * time.Hour)
	feeds, err := store.EnsureFeeds(ctx, testDefinitions()[:1], old.Add(-time.Hour))
	if err != nil {
		t.Fatal("prune feed fixture failed")
	}
	feedID := feeds[0].ID

	completeRun := func(start time.Time) int64 {
		t.Helper()
		id, err := store.BeginSyncRun(ctx, SyncModeEnforce, "", start)
		if err != nil {
			t.Fatal("prune sync fixture did not begin")
		}
		if err := store.CompleteSyncRun(ctx, id, ops.Result{
			Outcome: ops.OutcomeSuccess, StartedAt: start, CompletedAt: start.Add(time.Second),
		}); err != nil {
			t.Fatal("prune sync fixture did not complete")
		}
		return id
	}
	oldRunID := completeRun(old)
	recentRunID := completeRun(recent)
	openRunID, err := store.BeginSyncRun(ctx, SyncModeEnforce, "", old.Add(time.Minute))
	if err != nil {
		t.Fatal("open sync fixture did not begin")
	}

	for _, fixture := range []struct {
		prefix   string
		lastSeen time.Time
		active   int
	}{
		{prefix: "8.8.8.0/24", lastSeen: old, active: 0},
		{prefix: "9.9.9.0/24", lastSeen: old, active: 1},
		{prefix: "1.1.1.0/24", lastSeen: recent, active: 0},
	} {
		if _, err := store.db.ExecContext(ctx, `
INSERT INTO feed_entries(feed_id, prefix, family, prefix_bits, kind, first_seen_at, last_seen_at, missing_runs, active)
VALUES(?, ?, 4, 24, 2, ?, ?, 0, ?)`, feedID, fixture.prefix, unix(fixture.lastSeen), unix(fixture.lastSeen), fixture.active); err != nil {
			t.Fatal("prune feed-entry fixture failed")
		}
	}

	insertObject := func(prefix string, desired int, updated time.Time) int64 {
		t.Helper()
		result, err := store.db.ExecContext(ctx, `
INSERT INTO enforcement_objects(prefix, family, prefix_bits, scope, desired, primary_feed_id, created_at, updated_at)
VALUES(?, 4, 24, 'Range', ?, ?, ?, ?)`, prefix, desired, feedID, unix(updated), unix(updated))
		if err != nil {
			t.Fatal("prune enforcement fixture failed")
		}
		id, _ := result.LastInsertId()
		return id
	}
	staleObjectID := insertObject("8.8.4.0/24", 0, old)
	desiredObjectID := insertObject("9.9.8.0/24", 1, old)
	openObjectID := insertObject("1.0.0.0/24", 0, old)

	insertOperation := func(token string, objectID int64, status OperationStatus, started time.Time, completed *time.Time) {
		t.Helper()
		var completedAt any
		if completed != nil {
			completedAt = unix(*completed)
		}
		_, err := store.db.ExecContext(ctx, `
INSERT INTO lapi_operations(token, kind, feed_id, duration_seconds, payload_hash, status, started_at, completed_at)
VALUES(?, 'create', ?, 3600, ?, ?, ?, ?)`, token, feedID, stringsOf('f', 64), string(status), unix(started), completedAt)
		if err != nil {
			t.Fatal("prune operation fixture failed")
		}
		if _, err := store.db.ExecContext(ctx, `
INSERT INTO lapi_operation_items(operation_token, object_id) VALUES(?, ?)`, token, objectID); err != nil {
			t.Fatal("prune operation-item fixture failed")
		}
	}
	oldCompletedToken := stringsOf('a', 32)
	oldFailedToken := stringsOf('b', 32)
	openToken := stringsOf('c', 32)
	ambiguousToken := stringsOf('d', 32)
	recentCompletedToken := stringsOf('e', 32)
	oldCompletedAt := old.Add(time.Minute)
	recentCompletedAt := recent.Add(time.Minute)
	insertOperation(oldCompletedToken, staleObjectID, OperationCompleted, old, &oldCompletedAt)
	insertOperation(oldFailedToken, staleObjectID, OperationFailed, old, &oldCompletedAt)
	insertOperation(openToken, openObjectID, OperationPending, old, nil)
	insertOperation(ambiguousToken, openObjectID, OperationAmbiguous, old, nil)
	insertOperation(recentCompletedToken, desiredObjectID, OperationCompleted, recent, &recentCompletedAt)

	insertAlertDecision := func(token string, objectID, alertID, decisionID int64, status DecisionStatus, created, expires time.Time) {
		t.Helper()
		result, err := store.db.ExecContext(ctx, `
INSERT INTO lapi_alerts(alert_id, operation_token, machine_id, origin, scenario, verified_at, created_at)
VALUES(?, ?, 'crowdshield-test', 'crowdshield', 'crowdshield/feed-one', ?, ?)`, alertID, token, unix(created), unix(created))
		if err != nil {
			t.Fatal("prune alert fixture failed")
		}
		alertRowID, _ := result.LastInsertId()
		if _, err := store.db.ExecContext(ctx, `
INSERT INTO lapi_decisions(object_id, alert_row_id, decision_id, origin, scenario, scope, value,
                           created_at, expires_at, verified_at, status)
VALUES(?, ?, ?, 'crowdshield', 'crowdshield/feed-one', 'Range', 'bounded-test-value', ?, ?, ?, ?)`,
			objectID, alertRowID, decisionID, unix(created), unix(expires), unix(created), string(status)); err != nil {
			t.Fatal("prune decision fixture failed")
		}
	}
	insertAlertDecision(oldCompletedToken, staleObjectID, 101, 201, DecisionExpired, old, old.Add(time.Hour))
	insertAlertDecision(recentCompletedToken, desiredObjectID, 102, 202, DecisionActive, old, now.Add(time.Hour))

	if err := store.NotificationStates().Save(ctx, notify.PersistentState{
		Key: notify.StateKey{Kind: notify.KindFirstSuccess}, Sent: true,
		LastAttempt: old, UpdatedAt: old,
	}); err != nil {
		t.Fatal("notification retention fixture failed")
	}

	planned, err := store.PlanPruneHistory(ctx, now, 30*24*time.Hour, 1000)
	if err != nil || planned.SyncRuns != 1 || planned.Operations != 2 || planned.Decisions != 1 ||
		planned.Alerts != 1 || planned.EnforcementObjects != 1 || planned.FeedEntries != 1 {
		t.Fatal("read-only prune plan did not match eligible rows")
	}
	conflicts, err := store.CountAmbiguousOperations(ctx)
	if err != nil || conflicts != 1 {
		t.Fatal("ambiguous ownership operation count was inaccurate")
	}
	var oldRunBefore int
	if err := store.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM sync_runs WHERE id=?`, oldRunID).Scan(&oldRunBefore); err != nil || oldRunBefore != 1 {
		t.Fatal("read-only prune plan mutated history")
	}
	if _, found, err := store.RuntimeTimestamp(ctx, RuntimeLastPrune); err != nil || found {
		t.Fatal("read-only prune plan changed runtime state")
	}

	pruned, err := store.PruneHistory(ctx, now, 30*24*time.Hour, 1000)
	if err != nil {
		t.Fatal("bounded history pruning failed")
	}
	if pruned.SyncRuns != 1 || pruned.Operations != 2 || pruned.Decisions != 1 ||
		pruned.Alerts != 1 || pruned.EnforcementObjects != 1 || pruned.FeedEntries != 1 {
		t.Fatal("pruning deleted an inaccurate set of rows")
	}

	assertCount := func(query string, expected int, args ...any) {
		t.Helper()
		var count int
		if err := store.db.QueryRowContext(ctx, query, args...).Scan(&count); err != nil || count != expected {
			t.Fatal("post-prune ownership invariant failed")
		}
	}
	assertCount(`SELECT COUNT(*) FROM sync_runs WHERE id=?`, 0, oldRunID)
	assertCount(`SELECT COUNT(*) FROM sync_runs WHERE id IN (?, ?)`, 2, recentRunID, openRunID)
	assertCount(`SELECT COUNT(*) FROM lapi_operations WHERE status IN ('pending', 'ambiguous')`, 2)
	assertCount(`SELECT COUNT(*) FROM lapi_operations WHERE token=?`, 1, recentCompletedToken)
	assertCount(`SELECT COUNT(*) FROM lapi_decisions WHERE status='active'`, 1)
	assertCount(`SELECT COUNT(*) FROM enforcement_objects WHERE id IN (?, ?)`, 2, desiredObjectID, openObjectID)
	assertCount(`SELECT COUNT(*) FROM feed_entries WHERE active=1`, 1)
	assertCount(`SELECT COUNT(*) FROM feed_entries WHERE last_seen_at=? AND active=0`, 1, unix(recent))
	assertCount(`SELECT COUNT(*) FROM notification_delivery_state`, 1)

	lastPrune, found, err := store.RuntimeTimestamp(ctx, RuntimeLastPrune)
	if err != nil || !found || !lastPrune.Equal(now) {
		t.Fatal("last-prune runtime timestamp was not committed")
	}
	again, err := store.PruneHistory(ctx, now.Add(time.Hour), 30*24*time.Hour, 1000)
	if err != nil || again != (PruneResult{}) {
		t.Fatal("history pruning was not idempotent")
	}
}

func TestPruneHistoryRejectsUnsafeRetentionBounds(t *testing.T) {
	store := openTestStore(t)
	now := time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC)
	for _, retention := range []time.Duration{0, -time.Hour, 11 * 365 * 24 * time.Hour} {
		if _, err := store.PruneHistory(context.Background(), now, retention, 1000); err == nil || !IsCategory(err, ErrConstraint) {
			t.Fatal("unsafe history retention accepted")
		}
	}
}

func TestPruneHistoryEnforcesTerminalSyncRunCountLimit(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 7, 18, 12, 0, 0, 0, time.UTC)
	for index := 0; index < 3; index++ {
		started := now.Add(time.Duration(index-3) * time.Hour)
		runID, err := store.BeginSyncRun(ctx, SyncModeEnforce, "", started)
		if err != nil {
			t.Fatal("begin count-limit sync fixture")
		}
		if err := store.CompleteSyncRun(ctx, runID, ops.Result{
			Outcome: ops.OutcomeSuccess, StartedAt: started, CompletedAt: started.Add(time.Minute),
		}); err != nil {
			t.Fatal("complete count-limit sync fixture")
		}
	}
	if _, err := store.BeginSyncRun(ctx, SyncModeEnforce, "", now.Add(-4*time.Hour)); err != nil {
		t.Fatal("begin open sync fixture")
	}

	result, err := store.PruneHistory(ctx, now, 30*24*time.Hour, 2)
	if err != nil || result.SyncRuns != 1 {
		t.Fatal("history count limit did not prune exactly one terminal run")
	}
	runs, err := store.ListSyncRuns(ctx, 10)
	if err != nil || len(runs) != 3 || runs[0].Status != RunStatusSuccess ||
		runs[1].Status != RunStatusSuccess || runs[2].Status != RunStatusRunning {
		t.Fatal("history count limit did not preserve newest terminal and running runs")
	}
}
