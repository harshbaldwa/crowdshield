package syncer

import (
	"context"
	"testing"
	"time"

	"crowdshield/internal/feed"
	"crowdshield/internal/reconcile"
)

func TestDryRunUsesEphemeralSnapshotWithoutPersistentChanges(t *testing.T) {
	now := time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC)
	cfg := testConfig()
	store := openSyncStore(t)
	fetcher := &fakeFetcher{results: map[string]feed.FetchResult{
		cfg.Feeds[0].URL: {Body: []byte("8.8.8.0/24\n")},
	}, errors: map[string]error{}}
	reconciler := &fakeReconciler{reports: []reconcile.Report{{Added: 1}}}
	engine, err := New(Options{
		Config: cfg, Store: store, Fetcher: fetcher, Reconciler: reconciler,
		Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal("unable to construct sync engine")
	}
	report, err := engine.Run(context.Background(), RunOptions{DryRun: true})
	if err != nil || report.FeedsSucceeded != 1 || report.Reconcile.Added != 1 {
		t.Fatal("dry-run feed plan failed")
	}
	feeds, stateErr := store.ListFeeds(context.Background())
	entries, entriesErr := store.ListActiveEntries(context.Background())
	if stateErr != nil || entriesErr != nil || len(feeds) != 0 || len(entries) != 0 {
		t.Fatal("dry-run changed persistent feed state")
	}
	if len(reconciler.calls) != 1 || !reconciler.calls[0].DryRun || !reconciler.calls[0].OverrideEntries || len(reconciler.calls[0].Entries) != 1 {
		t.Fatal("dry-run did not reconcile ephemeral entries")
	}
}
