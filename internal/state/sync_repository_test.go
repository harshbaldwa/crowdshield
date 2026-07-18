package state

import (
	"context"
	"strings"
	"testing"
	"time"

	"crowdshield/internal/ops"
)

func TestSyncRunLifecyclePersistsBoundedAggregatesAndFeedResults(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()
	started := time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC)
	if _, err := store.EnsureFeeds(ctx, testDefinitions(), started.Add(-time.Minute)); err != nil {
		t.Fatal("sync history feeds were not registered")
	}
	runID, err := store.BeginSyncRun(ctx, SyncModeEnforce, "", started)
	if err != nil || runID <= 0 {
		t.Fatal("sync run did not begin")
	}
	completed := started.Add(2 * time.Second)
	result := ops.Result{
		Outcome: ops.OutcomeSuccess, StartedAt: started, CompletedAt: completed,
		Counts: ops.Counts{
			FeedsSucceeded: 2, Added: 4, Refreshed: 3, Removed: 2,
			Rejected: 1, Skipped: 5, LAPIRequests: 6, ActiveDecisions: 7,
		},
		Feeds: []ops.FeedResult{
			{Name: "feed-one", Outcome: ops.OutcomeSuccess, Accepted: 100, Rejected: 1},
			{Name: "feed-two", Outcome: ops.OutcomeNotModified, Accepted: 80},
		},
	}
	if err := store.CompleteSyncRun(ctx, runID, result); err != nil {
		t.Fatal("sync run did not complete")
	}
	runs, err := store.ListSyncRuns(ctx, 10)
	if err != nil || len(runs) != 1 {
		t.Fatal("sync history listing failed")
	}
	run := runs[0]
	if run.ID != runID || run.Mode != SyncModeEnforce || run.Status != RunStatusSuccess ||
		run.CompletedAt == nil || !run.CompletedAt.Equal(completed) || run.Failure != "" ||
		run.Counts.Added != 4 || run.Counts.Refreshed != 3 || run.Counts.ActiveDecisions != 0 || len(run.Feeds) != 2 {
		t.Fatal("sync history aggregate was inaccurate")
	}
	if run.Feeds[0].Name != "feed-one" || run.Feeds[0].Outcome != ops.OutcomeSuccess ||
		run.Feeds[1].Name != "feed-two" || run.Feeds[1].Outcome != ops.OutcomeNotModified {
		t.Fatal("per-feed sync history was inaccurate")
	}
	lastSafe, found, err := store.RuntimeTimestamp(ctx, RuntimeLastSafeSync)
	if err != nil || !found || !lastSafe.Equal(completed) {
		t.Fatal("safe synchronization timestamp was not persisted transactionally")
	}
	if err := store.CompleteSyncRun(ctx, runID, result); err == nil || !IsCategory(err, ErrConstraint) {
		t.Fatal("completed sync run accepted a second completion")
	}
}

func TestFailedSyncHistoryDoesNotAdvanceLastSafeTimestamp(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()
	started := time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC)
	firstID, err := store.BeginSyncRun(ctx, SyncModeEnforce, "", started)
	if err != nil {
		t.Fatal("safe sync run did not begin")
	}
	safe := ops.Result{Outcome: ops.OutcomeSuccess, StartedAt: started, CompletedAt: started.Add(time.Second)}
	if err := store.CompleteSyncRun(ctx, firstID, safe); err != nil {
		t.Fatal("safe sync run did not complete")
	}
	failedStart := started.Add(time.Hour)
	failedID, err := store.BeginSyncRun(ctx, SyncModeEnforce, "", failedStart)
	if err != nil {
		t.Fatal("failed sync run did not begin")
	}
	failed := ops.Result{
		Outcome: ops.OutcomeFailed, Failure: ops.FailureLAPI, Retryable: true,
		StartedAt: failedStart, CompletedAt: failedStart.Add(time.Second),
	}
	if err := store.CompleteSyncRun(ctx, failedID, failed); err != nil {
		t.Fatal("failed sync run was not recorded")
	}
	lastSafe, found, err := store.RuntimeTimestamp(ctx, RuntimeLastSafeSync)
	if err != nil || !found || !lastSafe.Equal(safe.CompletedAt) {
		t.Fatal("failed synchronization advanced the last-safe timestamp")
	}
	runs, err := store.ListSyncRuns(ctx, 1)
	if err != nil || len(runs) != 1 || runs[0].Status != RunStatusFailed || runs[0].Failure != ops.FailureLAPI {
		t.Fatal("failed sync history category was inaccurate")
	}
}

func TestRecoverInterruptedSyncRunsTouchesOnlyRunningRows(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC)
	interruptedID, err := store.BeginSyncRun(ctx, SyncModeEnforce, "", now.Add(-time.Hour))
	if err != nil {
		t.Fatal("interrupted sync fixture did not begin")
	}
	completeID, err := store.BeginSyncRun(ctx, SyncModeEnforce, "", now.Add(-2*time.Hour))
	if err != nil {
		t.Fatal("completed sync fixture did not begin")
	}
	completed := ops.Result{Outcome: ops.OutcomeSuccess, StartedAt: now.Add(-2 * time.Hour), CompletedAt: now.Add(-2*time.Hour + time.Second)}
	if err := store.CompleteSyncRun(ctx, completeID, completed); err != nil {
		t.Fatal("completed sync fixture did not complete")
	}
	count, err := store.RecoverInterruptedSyncRuns(ctx, now)
	if err != nil || count != 1 {
		t.Fatal("interrupted sync recovery count was inaccurate")
	}
	runs, err := store.ListSyncRuns(ctx, 10)
	if err != nil || len(runs) != 2 {
		t.Fatal("recovered sync history listing failed")
	}
	for _, run := range runs {
		if run.ID == interruptedID && (run.Status != RunStatusFailed || run.Failure != ops.FailureRuntime || run.CompletedAt == nil || !run.CompletedAt.Equal(now)) {
			t.Fatal("interrupted sync was not categorized as a runtime failure")
		}
		if run.ID == completeID && run.Status != RunStatusSuccess {
			t.Fatal("interrupted sync recovery modified a completed run")
		}
	}
}

func TestRuntimeTimestampIsMonotonicAndFailsClosedOnCorruption(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC)
	if err := store.SetRuntimeTimestamp(ctx, RuntimeLastPrune, now); err != nil {
		t.Fatal("valid runtime timestamp was not stored")
	}
	if err := store.SetRuntimeTimestamp(ctx, RuntimeLastPrune, now.Add(-time.Hour)); err != nil {
		t.Fatal("older runtime timestamp was not handled")
	}
	loaded, found, err := store.RuntimeTimestamp(ctx, RuntimeLastPrune)
	if err != nil || !found || !loaded.Equal(now) {
		t.Fatal("runtime timestamp regressed")
	}
	const canary = "password-canary-do-not-emit"
	if _, err := store.db.ExecContext(ctx, `UPDATE runtime_state SET value=? WHERE key=?`, canary, string(RuntimeLastPrune)); err != nil {
		t.Fatal("unable to create runtime corruption fixture")
	}
	_, _, err = store.RuntimeTimestamp(ctx, RuntimeLastPrune)
	if err == nil || !IsCategory(err, ErrIntegrity) || strings.Contains(err.Error(), canary) {
		t.Fatal("corrupt runtime timestamp did not fail closed and redacted")
	}
	if err := store.SetRuntimeTimestamp(ctx, RuntimeLastPrune, now.Add(time.Hour)); err == nil || !IsCategory(err, ErrIntegrity) || strings.Contains(err.Error(), canary) {
		t.Fatal("runtime timestamp setter overwrote corrupt state")
	}
}

func TestSyncHistoryRejectsUnsafeRequestedFeedAndInvalidRuntimeKeys(t *testing.T) {
	store := openTestStore(t)
	now := time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC)
	for _, requested := range []string{"198.51.100.23", "2001:db8::23", "https://feed.example.invalid/private"} {
		if _, err := store.BeginSyncRun(context.Background(), SyncModeEnforce, requested, now); err == nil || !IsCategory(err, ErrConstraint) {
			t.Fatal("unsafe requested-feed history accepted")
		}
	}
	if err := store.SetRuntimeTimestamp(context.Background(), RuntimeTimestampKey("password-canary"), now); err == nil || !IsCategory(err, ErrConstraint) {
		t.Fatal("arbitrary runtime state key accepted")
	}
	if _, _, err := store.RuntimeTimestamp(context.Background(), RuntimeTimestampKey("198.51.100.23")); err == nil || !IsCategory(err, ErrConstraint) {
		t.Fatal("indicator-bearing runtime state key accepted")
	}
}
