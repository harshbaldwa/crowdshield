package state

import (
	"context"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"crowdshield/internal/feed"
	"crowdshield/internal/network"
)

func testDefinitions() []FeedDefinition {
	return []FeedDefinition{
		{Name: "feed-one", URLHash: stringsOf('a', 64), DefinitionHash: stringsOf('b', 64), Enabled: true},
		{Name: "feed-two", URLHash: stringsOf('c', 64), DefinitionHash: stringsOf('d', 64), Enabled: false},
	}
}

func stringsOf(value byte, count int) string {
	body := make([]byte, count)
	for i := range body {
		body[i] = value
	}
	return string(body)
}

func storedEntry(raw string, kind network.Kind) feed.Entry {
	prefix, err := network.NormalizePrefix(raw)
	if err != nil {
		panic("invalid static state fixture")
	}
	return feed.Entry{Prefix: prefix, Kind: kind}
}

func TestStoredEntryRejectsOverflowedKind(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC)
	if _, err := store.EnsureFeeds(ctx, testDefinitions(), now); err != nil {
		t.Fatal("unable to seed feed")
	}
	if _, err := store.ApplyFeedSnapshot(ctx, "feed-one", FeedSnapshot{
		Version: stringsOf('e', 64), Entries: []feed.Entry{storedEntry("8.8.8.8/32", network.KindIP)},
	}, 2, now); err != nil {
		t.Fatal("unable to seed feed entry")
	}
	if _, err := store.db.ExecContext(ctx, `PRAGMA ignore_check_constraints=ON`); err != nil {
		t.Fatal("unable to prepare corruption fixture")
	}
	if _, err := store.db.ExecContext(ctx, `UPDATE feed_entries SET kind=257`); err != nil {
		t.Fatal("unable to corrupt feed kind")
	}
	if _, err := store.ListActiveEntries(ctx); err == nil || !IsCategory(err, ErrIntegrity) {
		t.Fatal("overflowed feed kind was accepted")
	}
}

func TestEnsureFeedsKeepsStableIDsAndUpdatesDefinition(t *testing.T) {
	store := openTestStore(t)
	now := time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC)
	first, err := store.EnsureFeeds(context.Background(), testDefinitions(), now)
	if err != nil || len(first) != 2 || first[0].ID == first[1].ID {
		t.Fatal("feed registration failed")
	}
	updated := testDefinitions()
	updated[0].DefinitionHash = stringsOf('e', 64)
	updated[0].Enabled = false
	second, err := store.EnsureFeeds(context.Background(), updated, now.Add(time.Minute))
	if err != nil || second[0].ID != first[0].ID || second[0].DefinitionHash != updated[0].DefinitionHash || second[0].Enabled {
		t.Fatal("feed identity was not stable across definition update")
	}
	var rawURLs int
	if err := store.db.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM feeds WHERE url_hash LIKE 'http%'`).Scan(&rawURLs); err != nil || rawURLs != 0 {
		t.Fatal("raw URL stored instead of hash")
	}
}

func TestEnsureFeedsDisablesDefinitionsRemovedFromConfiguration(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC)
	definitions := testDefinitions()
	definitions[1].Enabled = true
	if _, err := store.EnsureFeeds(ctx, definitions, now); err != nil {
		t.Fatal("initial feed registration failed")
	}
	if _, err := store.EnsureFeeds(ctx, definitions[:1], now.Add(time.Minute)); err != nil {
		t.Fatal("authoritative feed update failed")
	}
	listed, err := store.ListFeeds(ctx)
	if err != nil || len(listed) != 2 || listed[0].Name != "feed-one" || !listed[0].Enabled || listed[1].Name != "feed-two" || listed[1].Enabled {
		t.Fatal("removed feed remained enabled")
	}
}

func TestSuccessfulSnapshotsApplyMissingGraceTransactionally(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC)
	if _, err := store.EnsureFeeds(ctx, testDefinitions()[:1], now); err != nil {
		t.Fatal("feed registration failed")
	}
	first := FeedSnapshot{
		Version: stringsOf('1', 64), ETag: `"first"`, LastModified: "Wed, 15 Jul 2026 12:00:00 GMT",
		Entries: []feed.Entry{
			storedEntry("8.8.8.0/24", network.KindRange),
			storedEntry("9.9.9.9/32", network.KindIP),
		},
		Rejected: 1,
	}
	result, err := store.ApplyFeedSnapshot(ctx, "feed-one", first, 2, now.Add(time.Minute))
	if err != nil || result.Added != 2 || result.Deactivated != 0 {
		t.Fatal("initial snapshot failed")
	}
	second := first
	second.Version = stringsOf('2', 64)
	second.Entries = second.Entries[:1]
	result, err = store.ApplyFeedSnapshot(ctx, "feed-one", second, 2, now.Add(2*time.Minute))
	if err != nil || result.Missing != 1 || result.Deactivated != 0 {
		t.Fatal("first successful miss did not retain entry")
	}
	if err := store.RecordFeedFailure(ctx, "feed-one", "request", now.Add(3*time.Minute), now.Add(4*time.Minute)); err != nil {
		t.Fatal("feed failure recording failed")
	}
	entries, err := store.ListFeedEntries(ctx, "feed-one", true)
	if err != nil || len(entries) != 2 {
		t.Fatal("failed retrieval changed last-known-good entries")
	}
	result, err = store.ApplyFeedSnapshot(ctx, "feed-one", second, 2, now.Add(5*time.Minute))
	if err != nil || result.Deactivated != 1 {
		t.Fatal("missing grace did not deactivate on second successful miss")
	}
	active, err := store.ListFeedEntries(ctx, "feed-one", false)
	if err != nil || len(active) != 1 {
		t.Fatal("inactive entry remained in active view")
	}
	state, err := store.FeedByName(ctx, "feed-one")
	if err != nil || state.LastGoodVersion != second.Version || state.AcceptedEntries != 1 || state.ConsecutiveFailures != 0 || state.RejectedEntries != 1 {
		t.Fatal("feed success state not persisted")
	}
}

func TestFailedSnapshotRollsBackLastKnownGood(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC)
	if _, err := store.EnsureFeeds(ctx, testDefinitions()[:1], now); err != nil {
		t.Fatal("feed registration failed")
	}
	valid := FeedSnapshot{Version: stringsOf('1', 64), Entries: []feed.Entry{storedEntry("8.8.8.0/24", network.KindRange)}}
	if _, err := store.ApplyFeedSnapshot(ctx, "feed-one", valid, 2, now.Add(time.Minute)); err != nil {
		t.Fatal("valid snapshot failed")
	}
	invalid := FeedSnapshot{Version: stringsOf('2', 64), Entries: []feed.Entry{{Prefix: netip.Prefix{}, Kind: network.KindRange}}}
	if _, err := store.ApplyFeedSnapshot(ctx, "feed-one", invalid, 2, now.Add(2*time.Minute)); err == nil {
		t.Fatal("invalid snapshot accepted")
	}
	state, err := store.FeedByName(ctx, "feed-one")
	if err != nil || state.LastGoodVersion != valid.Version || state.AcceptedEntries != 1 {
		t.Fatal("failed transaction replaced last-known-good state")
	}
}

func TestListFeedsReturnsRegisteredFeedsInStableIDOrder(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC)
	registered, err := store.EnsureFeeds(ctx, testDefinitions(), now)
	if err != nil {
		t.Fatal("feed registration failed")
	}
	listed, err := store.ListFeeds(ctx)
	if err != nil || len(listed) != len(registered) {
		t.Fatal("registered feed enumeration failed")
	}
	for index := range registered {
		if listed[index].ID != registered[index].ID || listed[index].Name != registered[index].Name || listed[index].Enabled != registered[index].Enabled {
			t.Fatal("feed enumeration order or state changed")
		}
	}
}

func TestNotModifiedRefreshesFeedHealthWithoutAdvancingMissingGrace(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC)
	if _, err := store.EnsureFeeds(ctx, testDefinitions()[:1], now); err != nil {
		t.Fatal("feed registration failed")
	}
	first := FeedSnapshot{
		Version: stringsOf('1', 64), ETag: `"first"`, LastModified: "Wed, 15 Jul 2026 12:00:00 GMT",
		Entries: []feed.Entry{
			storedEntry("8.8.8.0/24", network.KindRange),
			storedEntry("9.9.9.9/32", network.KindIP),
		},
	}
	if _, err := store.ApplyFeedSnapshot(ctx, "feed-one", first, 2, now.Add(time.Minute)); err != nil {
		t.Fatal("initial snapshot failed")
	}
	second := first
	second.Version = stringsOf('2', 64)
	second.Entries = second.Entries[:1]
	if _, err := store.ApplyFeedSnapshot(ctx, "feed-one", second, 2, now.Add(2*time.Minute)); err != nil {
		t.Fatal("first successful missing run failed")
	}
	if err := store.RecordFeedFailure(ctx, "feed-one", "request", now.Add(3*time.Minute), now.Add(4*time.Minute)); err != nil {
		t.Fatal("feed failure recording failed")
	}
	if err := store.RecordFeedNotModified(ctx, "feed-one", `"second"`, "", now.Add(5*time.Minute)); err != nil {
		t.Fatal("not-modified state update failed")
	}
	entries, err := store.ListFeedEntries(ctx, "feed-one", true)
	if err != nil || len(entries) != 2 || entries[1].MissingRuns != 1 || !entries[1].Active {
		t.Fatal("not-modified response advanced missing grace")
	}
	record, err := store.FeedByName(ctx, "feed-one")
	if err != nil || record.ETag != `"second"` || record.LastModified != first.LastModified || record.LastGoodVersion != second.Version || record.ConsecutiveFailures != 0 || record.NextAttempt != nil || record.LastSuccess == nil || !record.LastSuccess.Equal(now.Add(5*time.Minute)) {
		t.Fatal("not-modified response did not refresh feed health")
	}
}

func TestFeedStateSurvivesReopen(t *testing.T) {
	ctx := context.Background()
	options := Options{Path: filepath.Join(t.TempDir(), "persistent.db"), BusyTimeout: time.Second, IntegrityCheck: true}
	store, err := Open(ctx, options)
	if err != nil {
		t.Fatal("unable to open store")
	}
	now := time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC)
	if _, err := store.EnsureFeeds(ctx, testDefinitions()[:1], now); err != nil {
		t.Fatal("feed registration failed")
	}
	snapshot := FeedSnapshot{Version: stringsOf('1', 64), Entries: []feed.Entry{storedEntry("8.8.8.0/24", network.KindRange)}}
	if _, err := store.ApplyFeedSnapshot(ctx, "feed-one", snapshot, 2, now.Add(time.Minute)); err != nil {
		t.Fatal("snapshot failed")
	}
	if err := store.Close(); err != nil {
		t.Fatal("close failed")
	}
	store, err = Open(ctx, options)
	if err != nil {
		t.Fatal("reopen failed")
	}
	defer func() {
		if err := store.Close(); err != nil {
			t.Error("store close failed")
		}
	}()
	entries, err := store.ListActiveEntries(ctx)
	if err != nil || len(entries) != 1 || entries[0].FeedName != "feed-one" {
		t.Fatal("durable feed state missing after reopen")
	}
}
