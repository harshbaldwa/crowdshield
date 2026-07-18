package syncer

import (
	"context"
	"testing"
	"time"

	"crowdshield/internal/config"
	"crowdshield/internal/feed"
)

func TestDryRunPreviewsChangedDefinitionWithoutPersistingIt(t *testing.T) {
	now := time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC)
	cfg := testConfig()
	store := openSyncStore(t)
	initialFetcher := &fakeFetcher{results: map[string]feed.FetchResult{
		cfg.Feeds[0].URL: {Body: []byte("8.8.8.0/24\n"), ETag: `"old"`},
	}, errors: map[string]error{}}
	initial, err := New(Options{Config: cfg, Store: store, Fetcher: initialFetcher, Reconciler: &fakeReconciler{}, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal("unable to construct initial engine")
	}
	if _, err := initial.Run(context.Background(), RunOptions{}); err != nil {
		t.Fatal("initial feed run failed")
	}
	before, _ := store.FeedByName(context.Background(), "feed-one")

	now = now.Add(30 * time.Minute)
	changed := cfg
	changed.Feeds = append([]config.FeedConfig(nil), cfg.Feeds...)
	changed.Feeds[0].URL = "https://example.invalid/replacement.txt"
	fetcher := &fakeFetcher{results: map[string]feed.FetchResult{
		changed.Feeds[0].URL: {Body: []byte("9.9.9.0/24\n")},
	}, errors: map[string]error{}}
	reconciler := &fakeReconciler{}
	engine, err := New(Options{Config: changed, Store: store, Fetcher: fetcher, Reconciler: reconciler, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal("unable to construct changed engine")
	}
	report, err := engine.Run(context.Background(), RunOptions{DryRun: true})
	if err != nil || report.FeedsSucceeded != 1 || len(fetcher.calls) != 1 || fetcher.calls[0].ETag != "" || fetcher.calls[0].LastModified != "" {
		t.Fatal("dry-run did not fetch the changed definition")
	}
	if len(reconciler.calls) != 1 || len(reconciler.calls[0].Entries) != 1 || reconciler.calls[0].Entries[0].Entry.Prefix.String() != "9.9.9.0/24" {
		t.Fatal("dry-run did not plan from replacement snapshot")
	}
	after, stateErr := store.FeedByName(context.Background(), "feed-one")
	if stateErr != nil || after.URLHash != before.URLHash || after.DefinitionHash != before.DefinitionHash || after.LastGoodVersion != before.LastGoodVersion {
		t.Fatal("dry-run persisted changed definition or snapshot")
	}
}

func TestUnsolicitedNotModifiedAfterDefinitionChangeIsRejected(t *testing.T) {
	now := time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC)
	cfg := testConfig()
	store := openSyncStore(t)
	initialFetcher := &fakeFetcher{results: map[string]feed.FetchResult{
		cfg.Feeds[0].URL: {Body: []byte("8.8.8.0/24\n"), ETag: `"old"`},
	}, errors: map[string]error{}}
	initial, err := New(Options{Config: cfg, Store: store, Fetcher: initialFetcher, Reconciler: &fakeReconciler{}, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal("unable to construct initial sync engine")
	}
	if _, err := initial.Run(context.Background(), RunOptions{}); err != nil {
		t.Fatal("initial feed run failed")
	}
	before, _ := store.FeedByName(context.Background(), "feed-one")

	now = now.Add(30 * time.Minute)
	changed := cfg
	changed.Feeds = append([]config.FeedConfig(nil), cfg.Feeds...)
	changed.Feeds[0].URL = "https://example.invalid/replacement.txt"
	fetcher := &fakeFetcher{results: map[string]feed.FetchResult{
		changed.Feeds[0].URL: {NotModified: true},
	}, errors: map[string]error{}}
	engine, err := New(Options{Config: changed, Store: store, Fetcher: fetcher, Reconciler: &fakeReconciler{}, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal("unable to construct changed sync engine")
	}
	report, err := engine.Run(context.Background(), RunOptions{})
	if err == nil || !IsCategory(err, ErrDegraded) || report.FeedsFailed != 1 || len(fetcher.calls) != 1 || fetcher.calls[0].ETag != "" || fetcher.calls[0].LastModified != "" {
		t.Fatal("unsolicited not-modified response was accepted")
	}
	after, stateErr := store.FeedByName(context.Background(), "feed-one")
	if stateErr != nil || after.LastGoodVersion != before.LastGoodVersion || after.LastSuccess == nil || !after.LastSuccess.Equal(*before.LastSuccess) || after.LastErrorCategory != "request" {
		t.Fatal("unsolicited not-modified response changed last-known-good health")
	}
}

func TestDefinitionChangeBypassesPreviousMinimumUpdateInterval(t *testing.T) {
	now := time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC)
	cfg := testConfig()
	store := openSyncStore(t)
	firstFetcher := &fakeFetcher{results: map[string]feed.FetchResult{
		cfg.Feeds[0].URL: {Body: []byte("8.8.8.0/24\n")},
	}, errors: map[string]error{}}
	first, err := New(Options{
		Config: cfg, Store: store, Fetcher: firstFetcher, Reconciler: &fakeReconciler{},
		Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal("unable to construct initial sync engine")
	}
	if _, err := first.Run(context.Background(), RunOptions{}); err != nil {
		t.Fatal("initial feed run failed")
	}

	now = now.Add(30 * time.Minute)
	changed := cfg
	changed.Feeds = append([]config.FeedConfig(nil), cfg.Feeds...)
	changed.Feeds[0].URL = "https://example.invalid/replacement.txt"
	secondFetcher := &fakeFetcher{results: map[string]feed.FetchResult{
		changed.Feeds[0].URL: {Body: []byte("9.9.9.0/24\n")},
	}, errors: map[string]error{}}
	second, err := New(Options{
		Config: changed, Store: store, Fetcher: secondFetcher, Reconciler: &fakeReconciler{},
		Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal("unable to construct replacement sync engine")
	}
	report, err := second.Run(context.Background(), RunOptions{})
	if err != nil || report.FeedsSucceeded != 1 || len(secondFetcher.calls) != 1 {
		t.Fatal("changed definition remained blocked by old minimum interval")
	}
	entries, stateErr := store.ListActiveEntries(context.Background())
	if stateErr != nil || len(entries) != 2 {
		t.Fatal("replacement snapshot did not enter missing-grace transition")
	}
}
