package syncer

import (
	"context"
	"errors"
	"testing"
	"time"

	"crowdshield/internal/feed"
)

func TestRunContinuesOtherFeedsAndRecordsBackoffAfterFailure(t *testing.T) {
	now := time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC)
	cfg := testConfig()
	second := cfg.Feeds[0]
	second.Name = "feed-two"
	second.URL = "https://example.invalid/feed-two.txt"
	cfg.Feeds = append(cfg.Feeds, second)
	fetcher := &fakeFetcher{
		results: map[string]feed.FetchResult{second.URL: {Body: []byte("9.9.9.0/24\n")}},
		errors:  map[string]error{cfg.Feeds[0].URL: errors.New("synthetic request failure")},
	}
	reconciler := &fakeReconciler{}
	engine, err := New(Options{
		Config: cfg, Store: openSyncStore(t), Fetcher: fetcher, Reconciler: reconciler,
		Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal("unable to construct sync engine")
	}
	report, err := engine.Run(context.Background(), RunOptions{})
	if err == nil || !IsCategory(err, ErrDegraded) || report.FeedsFailed != 1 || report.FeedsSucceeded != 1 {
		t.Fatal("partial feed failure result was incorrect")
	}
	failed, stateErr := engine.store.FeedByName(context.Background(), "feed-one")
	if stateErr != nil || failed.ConsecutiveFailures != 1 || failed.LastErrorCategory != "request" || failed.NextAttempt == nil || !failed.NextAttempt.Equal(now.Add(cfg.Schedule.Retry.InitialBackoff.Duration())) {
		t.Fatal("failed feed backoff state was incorrect")
	}
	entries, stateErr := engine.store.ListActiveEntries(context.Background())
	if stateErr != nil || len(entries) != 1 || entries[0].FeedName != "feed-two" || len(reconciler.calls) != 1 {
		t.Fatal("independent successful feed or reconciliation was blocked")
	}
}
