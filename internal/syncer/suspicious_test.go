package syncer

import (
	"context"
	"testing"
	"time"

	"crowdshield/internal/feed"
)

func TestSuspiciousChangePreservesLastKnownGoodSnapshot(t *testing.T) {
	now := time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC)
	cfg := testConfig()
	cfg.Feeds[0].ExpectedMaxEntries = 10
	cfg.Feeds[0].MaxShrinkRatio = 0.75
	fetcher := &fakeFetcher{results: map[string]feed.FetchResult{
		cfg.Feeds[0].URL: {Body: []byte("8.8.8.0/24\n9.9.9.0/24\n")},
	}, errors: map[string]error{}}
	reconciler := &fakeReconciler{}
	engine, err := New(Options{
		Config: cfg, Store: openSyncStore(t), Fetcher: fetcher, Reconciler: reconciler,
		Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal("unable to construct sync engine")
	}
	if _, err := engine.Run(context.Background(), RunOptions{}); err != nil {
		t.Fatal("initial feed run failed")
	}
	before, _ := engine.store.FeedByName(context.Background(), "feed-one")
	now = now.Add(time.Hour)
	fetcher.results[cfg.Feeds[0].URL] = feed.FetchResult{Body: []byte("8.8.8.0/24\n")}
	report, err := engine.Run(context.Background(), RunOptions{})
	if err == nil || !IsCategory(err, ErrDegraded) || report.SuspiciousChanges != 1 {
		t.Fatal("suspicious change was not classified")
	}
	after, stateErr := engine.store.FeedByName(context.Background(), "feed-one")
	if stateErr != nil || after.LastGoodVersion != before.LastGoodVersion || after.AcceptedEntries != 2 || after.LastErrorCategory != string(feed.ErrSuspiciousChange) {
		t.Fatal("suspicious change replaced last-known-good feed state")
	}
	entries, stateErr := engine.store.ListActiveEntries(context.Background())
	if stateErr != nil || len(entries) != 2 || entries[0].MissingRuns != 0 || entries[1].MissingRuns != 0 || len(reconciler.calls) != 2 {
		t.Fatal("suspicious change altered active entries or blocked reconciliation")
	}
}
