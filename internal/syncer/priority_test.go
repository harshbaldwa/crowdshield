package syncer

import (
	"context"
	"testing"
	"time"

	"crowdshield/internal/config"
	"crowdshield/internal/feed"
)

func TestFeedPriorityFollowsCurrentConfigurationOrder(t *testing.T) {
	now := time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC)
	cfg := testConfig()
	second := cfg.Feeds[0]
	second.Name = "feed-two"
	second.URL = "https://example.invalid/feed-two.txt"
	cfg.Feeds = append(cfg.Feeds, second)
	store := openSyncStore(t)
	definitions, err := feedDefinitions(cfg.Feeds)
	if err != nil {
		t.Fatal("unable to build feed definitions")
	}
	registered, err := store.EnsureFeeds(context.Background(), definitions, now.Add(-time.Hour))
	if err != nil || len(registered) != 2 {
		t.Fatal("unable to pre-register feeds")
	}
	ids := map[string]int64{registered[0].Name: registered[0].ID, registered[1].Name: registered[1].ID}

	reversed := cfg
	reversed.Feeds = []config.FeedConfig{cfg.Feeds[1], cfg.Feeds[0]}
	fetcher := &fakeFetcher{results: map[string]feed.FetchResult{
		cfg.Feeds[0].URL: {Body: []byte("8.8.8.0/24\n")},
		cfg.Feeds[1].URL: {Body: []byte("9.9.9.0/24\n")},
	}, errors: map[string]error{}}
	reconciler := &fakeReconciler{}
	engine, err := New(Options{
		Config: reversed, Store: store, Fetcher: fetcher, Reconciler: reconciler,
		Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal("unable to construct reordered sync engine")
	}
	if _, err := engine.Run(context.Background(), RunOptions{}); err != nil {
		t.Fatal("reordered feed run failed")
	}
	if len(reconciler.calls) != 1 || reconciler.calls[0].FeedOrder[ids["feed-two"]] != 0 || reconciler.calls[0].FeedOrder[ids["feed-one"]] != 1 {
		t.Fatal("feed priority followed historical database order")
	}
}
