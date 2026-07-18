package syncer

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"crowdshield/internal/config"
	"crowdshield/internal/feed"
	"crowdshield/internal/reconcile"
	"crowdshield/internal/state"
)

type fakeFetcher struct {
	results map[string]feed.FetchResult
	errors  map[string]error
	calls   []feed.FetchRequest
}

func (f *fakeFetcher) Fetch(_ context.Context, request feed.FetchRequest) (feed.FetchResult, error) {
	f.calls = append(f.calls, request)
	if err := f.errors[request.URL]; err != nil {
		return feed.FetchResult{}, err
	}
	result := f.results[request.URL]
	result.Body = append([]byte(nil), result.Body...)
	return result, nil
}

type fakeReconciler struct {
	calls   []reconcile.RunOptions
	reports []reconcile.Report
	errors  []error
}

func (r *fakeReconciler) Run(_ context.Context, options reconcile.RunOptions) (reconcile.Report, error) {
	r.calls = append(r.calls, options)
	index := len(r.calls) - 1
	var report reconcile.Report
	if index < len(r.reports) {
		report = r.reports[index]
	}
	if index < len(r.errors) {
		return report, r.errors[index]
	}
	return report, nil
}

func testConfig() config.Config {
	cfg := config.Defaults("test")
	cfg.Feeds = []config.FeedConfig{{
		Name: "feed-one", Enabled: true, URL: "https://example.invalid/feed-one.txt",
		Format: "plain", Family: "ipv4", Timeout: config.Duration(5 * time.Second),
		MaxDownloadBytes: 1 << 20, ExpectedMinEntries: 1, ExpectedMaxEntries: 10,
		MaxGrowthRatio: 2, MaxShrinkRatio: 0.5, Attribution: "Test fixture",
		MinUpdateInterval: config.Duration(time.Hour), ContentTypes: []string{"text/plain"},
		RequireFinalNewline: true, MaxMalformedLines: 1, MaxMalformedRatio: 0.1,
	}}
	return cfg
}

func openSyncStore(t *testing.T) *state.Store {
	t.Helper()
	store, err := state.Open(context.Background(), state.Options{
		Path: filepath.Join(t.TempDir(), "state.db"), BusyTimeout: time.Second, IntegrityCheck: true,
	})
	if err != nil {
		t.Fatal("unable to open sync state")
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}

func TestRunHandlesNotModifiedWithoutReplacingSnapshot(t *testing.T) {
	now := time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC)
	cfg := testConfig()
	fetcher := &fakeFetcher{results: map[string]feed.FetchResult{
		cfg.Feeds[0].URL: {Body: []byte("8.8.8.0/24\n"), ETag: `"one"`, LastModified: "Wed, 15 Jul 2026 12:00:00 GMT"},
	}, errors: map[string]error{}}
	engine, err := New(Options{
		Config: cfg, Store: openSyncStore(t), Fetcher: fetcher, Reconciler: &fakeReconciler{},
		Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal("unable to construct sync engine")
	}
	if _, err := engine.Run(context.Background(), RunOptions{}); err != nil {
		t.Fatal("initial feed run failed")
	}
	before, err := engine.store.FeedByName(context.Background(), "feed-one")
	if err != nil {
		t.Fatal("initial feed state missing")
	}
	now = now.Add(time.Hour)
	fetcher.results[cfg.Feeds[0].URL] = feed.FetchResult{NotModified: true, ETag: `"two"`}
	report, err := engine.Run(context.Background(), RunOptions{})
	if err != nil || report.FeedsUnchanged != 1 {
		t.Fatal("not-modified feed run failed")
	}
	if len(fetcher.calls) != 2 || fetcher.calls[1].ETag != `"one"` || fetcher.calls[1].LastModified != before.LastModified {
		t.Fatal("conditional validators were not sent")
	}
	after, err := engine.store.FeedByName(context.Background(), "feed-one")
	if err != nil || after.LastGoodVersion != before.LastGoodVersion || after.ETag != `"two"` || after.LastModified != before.LastModified || after.LastSuccess == nil || !after.LastSuccess.Equal(now) {
		t.Fatal("not-modified health update was incorrect")
	}
	entries, err := engine.store.ListActiveEntries(context.Background())
	if err != nil || len(entries) != 1 {
		t.Fatal("not-modified response replaced the last-known-good snapshot")
	}
}

func TestRunHonorsMinimumUpdateInterval(t *testing.T) {
	now := time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC)
	cfg := testConfig()
	fetcher := &fakeFetcher{results: map[string]feed.FetchResult{
		cfg.Feeds[0].URL: {Body: []byte("8.8.8.0/24\n")},
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
	now = now.Add(30 * time.Minute)
	report, err := engine.Run(context.Background(), RunOptions{})
	if err != nil || report.FeedsNotDue != 1 {
		t.Fatal("not-due feed run failed")
	}
	if len(fetcher.calls) != 1 || len(reconciler.calls) != 2 {
		t.Fatal("minimum update interval skipped incorrectly")
	}
}

func TestRunFetchesValidatesPersistsAndReconciles(t *testing.T) {
	now := time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC)
	cfg := testConfig()
	fetcher := &fakeFetcher{results: map[string]feed.FetchResult{
		cfg.Feeds[0].URL: {Body: []byte("8.8.8.0/24\n"), ETag: `"one"`, LastModified: "Wed, 15 Jul 2026 12:00:00 GMT"},
	}, errors: map[string]error{}}
	reconciler := &fakeReconciler{}
	engine, err := New(Options{
		Config: cfg, Store: openSyncStore(t), Fetcher: fetcher, Reconciler: reconciler,
		Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal("unable to construct sync engine")
	}
	report, err := engine.Run(context.Background(), RunOptions{})
	if err != nil || report.FeedsSucceeded != 1 || report.FeedsFailed != 0 {
		t.Fatal("successful feed run failed")
	}
	if len(fetcher.calls) != 1 || fetcher.calls[0].ETag != "" || fetcher.calls[0].LastModified != "" {
		t.Fatal("initial fetch request was incorrect")
	}
	entries, stateErr := engine.store.ListActiveEntries(context.Background())
	if stateErr != nil || len(entries) != 1 || entries[0].FeedName != "feed-one" || entries[0].Entry.Prefix.String() != "8.8.8.0/24" {
		t.Fatal("validated snapshot was not persisted")
	}
	if len(reconciler.calls) != 1 || reconciler.calls[0].DryRun || reconciler.calls[0].OverrideEntries {
		t.Fatal("persistent reconciliation was not invoked")
	}
}
