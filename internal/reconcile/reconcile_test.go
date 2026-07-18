package reconcile

import (
	"context"
	"net/netip"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"crowdshield/internal/credentials"
	"crowdshield/internal/feed"
	"crowdshield/internal/lapi"
	lapimock "crowdshield/internal/lapi/mock"
	"crowdshield/internal/network"
	"crowdshield/internal/state"
)

type harness struct {
	store  *state.Store
	server *lapimock.Server
	client *lapi.Client
	now    time.Time
	feeds  []state.FeedRecord
	tokens int
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	h := &harness{now: time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC)}
	var err error
	h.store, err = state.Open(context.Background(), state.Options{
		Path: filepath.Join(t.TempDir(), "state.db"), BusyTimeout: time.Second, IntegrityCheck: true,
	})
	if err != nil {
		t.Fatal("unable to open state")
	}
	t.Cleanup(func() { _ = h.store.Close() })
	h.server = lapimock.New(lapimock.Config{MachineID: "crowdshield-test", Password: "mock-password", Now: func() time.Time { return h.now }})
	t.Cleanup(h.server.Close)
	credentialPath, err := h.server.WriteCredentials(t.TempDir())
	if err != nil {
		t.Fatal("unable to write mock credentials")
	}
	creds, err := (credentials.Loader{MaxBytes: credentials.DefaultMaxBytes, StrictPermissions: true, AllowedHTTPHosts: []string{"127.0.0.1"}}).Load(credentialPath)
	if err != nil {
		t.Fatal("unable to load mock credentials")
	}
	t.Cleanup(creds.Destroy)
	h.client, err = lapi.New(lapi.Options{
		Credentials: creds, UserAgent: "crowdshield/test", RequestTimeout: time.Second,
		ConnectTimeout: time.Second, MaxResponseBytes: 1 << 20, AuthRefreshBefore: time.Minute,
		HTTPClient: h.server.Client(), Now: func() time.Time { return h.now },
	})
	if err != nil {
		t.Fatal("unable to construct client")
	}
	t.Cleanup(h.client.CloseIdleConnections)
	definitions := []state.FeedDefinition{
		{Name: "feed-one", URLHash: strings.Repeat("a", 64), DefinitionHash: strings.Repeat("b", 64), Enabled: true},
		{Name: "feed-two", URLHash: strings.Repeat("c", 64), DefinitionHash: strings.Repeat("d", 64), Enabled: true},
	}
	h.feeds, err = h.store.EnsureFeeds(context.Background(), definitions, h.now)
	if err != nil {
		t.Fatal("unable to register feeds")
	}
	return h
}

func entry(raw string, kind network.Kind) feed.Entry {
	prefix, err := network.NormalizePrefix(raw)
	if err != nil {
		panic("invalid static reconcile fixture")
	}
	return feed.Entry{Prefix: prefix, Kind: kind}
}

func (h *harness) snapshot(t *testing.T, feedName string, entries []feed.Entry) {
	t.Helper()
	versionByte := "1"
	if feedName == "feed-two" {
		versionByte = "2"
	}
	_, err := h.store.ApplyFeedSnapshot(context.Background(), feedName, state.FeedSnapshot{
		Version: strings.Repeat(versionByte, 64), Entries: entries,
	}, 2, h.now)
	if err != nil {
		t.Fatal("unable to seed feed snapshot")
	}
}

func (h *harness) reconciler(t *testing.T, batchSize int) *Reconciler {
	t.Helper()
	result, err := New(Options{
		Store: h.store, LAPI: h.client, MachineID: "crowdshield-test", Duration: 25 * time.Hour,
		RefreshBefore: 12 * time.Hour, BatchSize: batchSize, Now: func() time.Time { return h.now },
		Token: func() (string, error) {
			h.tokens++
			return strings.Repeat(strconv.FormatInt(int64((h.tokens%9)+1), 10), 32), nil
		},
	})
	if err != nil {
		t.Fatal("unable to construct reconciler")
	}
	return result
}

func feedOrder(h *harness) map[int64]int {
	return map[int64]int{h.feeds[0].ID: 0, h.feeds[1].ID: 1}
}

func TestInitialReconcileDeduplicatesAndSecondRunIsIdempotent(t *testing.T) {
	h := newHarness(t)
	h.snapshot(t, "feed-one", []feed.Entry{
		entry("8.8.8.0/24", network.KindRange),
		entry("8.8.8.8/32", network.KindIP),
	})
	h.snapshot(t, "feed-two", []feed.Entry{entry("8.8.8.0/24", network.KindRange)})
	reconciler := h.reconciler(t, 100)
	report, err := reconciler.Run(context.Background(), RunOptions{FeedOrder: feedOrder(h)})
	if err != nil || report.Added != 1 || report.Refreshed != 0 || report.Removed != 0 {
		t.Fatal("initial reconciliation failed")
	}
	alerts := h.server.Alerts()
	if len(alerts) != 1 || len(alerts[0].Decisions) != 1 {
		t.Fatal("deduplicated plan created unexpected decisions")
	}
	active, err := h.store.ListActiveDecisions(context.Background())
	if err != nil || len(active) != 1 {
		t.Fatal("owned decision state missing")
	}
	posts := h.server.RequestCount("POST", "/v1/alerts")
	report, err = reconciler.Run(context.Background(), RunOptions{FeedOrder: feedOrder(h)})
	if err != nil || report.Added != 0 || report.Refreshed != 0 || report.Removed != 0 || h.server.RequestCount("POST", "/v1/alerts") != posts {
		t.Fatal("idempotent run created duplicate decisions")
	}
}

func TestAllowlistRemovesOnlyVerifiedOwnedDecision(t *testing.T) {
	h := newHarness(t)
	h.snapshot(t, "feed-one", []feed.Entry{entry("8.8.8.0/24", network.KindRange)})
	reconciler := h.reconciler(t, 100)
	if _, err := reconciler.Run(context.Background(), RunOptions{FeedOrder: feedOrder(h)}); err != nil {
		t.Fatal("initial reconcile failed")
	}
	owned, _ := h.store.ListActiveDecisions(context.Background())
	if len(owned) != 1 {
		t.Fatal("owned decision missing")
	}
	h.server.AddForeignAlert(lapi.Alert{
		ID: 900, MachineID: "foreign", Scenario: "foreign/scenario",
		Decisions: []lapi.Decision{{ID: 901, Origin: "foreign", Scope: "Ip", Value: "9.9.9.9"}},
	})
	allowlist := []netip.Prefix{netip.MustParsePrefix("8.8.8.8/32")}
	report, err := reconciler.Run(context.Background(), RunOptions{FeedOrder: feedOrder(h), Allowlists: allowlist})
	if err != nil || report.Removed != 1 || !h.server.WasExpired(owned[0].DecisionID) || h.server.WasExpired(901) {
		t.Fatal("allowlist removal was not ownership-safe")
	}
	active, _ := h.store.ListActiveDecisions(context.Background())
	if len(active) != 0 {
		t.Fatal("removed decision remained active locally")
	}
}

func TestRefreshCreatesAndRecordsReplacementBeforeDeletingOld(t *testing.T) {
	h := newHarness(t)
	h.snapshot(t, "feed-one", []feed.Entry{entry("8.8.8.0/24", network.KindRange)})
	reconciler := h.reconciler(t, 100)
	if _, err := reconciler.Run(context.Background(), RunOptions{FeedOrder: feedOrder(h)}); err != nil {
		t.Fatal("initial reconcile failed")
	}
	old, _ := h.store.ListActiveDecisions(context.Background())
	if len(old) != 1 {
		t.Fatal("old decision missing")
	}
	logStart := len(h.server.RequestLog())
	h.now = h.now.Add(14 * time.Hour)
	report, err := reconciler.Run(context.Background(), RunOptions{FeedOrder: feedOrder(h)})
	if err != nil || report.Refreshed != 1 || !h.server.WasExpired(old[0].DecisionID) {
		t.Fatal("TTL refresh failed")
	}
	requestLog := h.server.RequestLog()[logStart:]
	postIndex, deleteIndex := -1, -1
	for index, request := range requestLog {
		if request == "POST /v1/alerts" && postIndex < 0 {
			postIndex = index
		}
		if strings.HasPrefix(request, "DELETE /v1/decisions/") && deleteIndex < 0 {
			deleteIndex = index
		}
	}
	if postIndex < 0 || deleteIndex < 0 || postIndex >= deleteIndex {
		t.Fatal("old decision was deleted before replacement creation")
	}
	active, _ := h.store.ListActiveDecisions(context.Background())
	if len(active) != 1 || active[0].DecisionID == old[0].DecisionID {
		t.Fatal("replacement is not the sole active decision")
	}
}

func TestDryRunHasNoPersistentOrLAPISideEffects(t *testing.T) {
	h := newHarness(t)
	h.snapshot(t, "feed-one", []feed.Entry{entry("8.8.8.0/24", network.KindRange)})
	reconciler := h.reconciler(t, 100)
	report, err := reconciler.Run(context.Background(), RunOptions{FeedOrder: feedOrder(h), DryRun: true})
	if err != nil || report.Added != 1 {
		t.Fatal("dry-run plan failed")
	}
	objects, _ := h.store.ListEnforcementObjects(context.Background())
	if len(objects) != 0 || len(h.server.Alerts()) != 0 || h.server.RequestCount("POST", "/v1/watchers/login") != 0 {
		t.Fatal("dry-run mutated state or contacted LAPI")
	}
}

func TestDryRunCanPlanFromEphemeralEntriesWithoutPersistingFeedState(t *testing.T) {
	h := newHarness(t)
	reconciler := h.reconciler(t, 100)
	report, err := reconciler.Run(context.Background(), RunOptions{
		FeedOrder:       feedOrder(h),
		DryRun:          true,
		OverrideEntries: true,
		Entries: []state.StoredEntry{{
			FeedID: h.feeds[0].ID, FeedName: "feed-one",
			Entry: entry("8.8.8.0/24", network.KindRange), Active: true,
		}},
	})
	if err != nil || report.Added != 1 {
		t.Fatal("ephemeral dry-run plan failed")
	}
	persisted, stateErr := h.store.ListActiveEntries(context.Background())
	if stateErr != nil || len(persisted) != 0 || len(h.server.Alerts()) != 0 {
		t.Fatal("ephemeral dry-run changed persistent state")
	}
	if _, err := reconciler.Run(context.Background(), RunOptions{OverrideEntries: true}); err == nil || !IsCategory(err, ErrContract) {
		t.Fatal("enforcing from ephemeral entries was accepted")
	}
}

func TestPendingOperationRecoversWithoutDuplicatePost(t *testing.T) {
	h := newHarness(t)
	h.snapshot(t, "feed-one", []feed.Entry{entry("8.8.8.0/24", network.KindRange)})
	stored, err := h.store.ListActiveEntries(context.Background())
	if err != nil || len(stored) != 1 {
		t.Fatal("feed state missing")
	}
	objects, _ := network.BuildDesired([]network.Candidate{{
		Prefix: stored[0].Entry.Prefix, Kind: stored[0].Entry.Kind, FeedID: stored[0].FeedID, FeedName: stored[0].FeedName,
	}}, nil)
	records, err := h.store.ApplyEnforcementPlan(context.Background(), objects, h.now)
	if err != nil || len(records) != 1 {
		t.Fatal("unable to seed enforcement plan")
	}
	token := "0123456789abcdef0123456789abcdef"
	operation := state.Operation{
		Token: token, Kind: state.OperationCreate, FeedID: h.feeds[0].ID, Duration: 25 * time.Hour,
		PayloadHash: strings.Repeat("a", 64), Items: []state.OperationItem{{ObjectID: records[0].ID}}, StartedAt: h.now,
	}
	if err := h.store.BeginOperation(context.Background(), operation); err != nil {
		t.Fatal("unable to seed pending operation")
	}
	if _, err := h.client.CreateAlert(context.Background(), lapi.CreateRequest{
		FeedName: "feed-one", OperationToken: token, Duration: 25 * time.Hour,
		Decisions: []lapi.DecisionInput{{Scope: "Range", Value: "8.8.8.0/24"}},
	}); err != nil {
		t.Fatal("unable to seed uncertain remote alert")
	}
	reconciler := h.reconciler(t, 100)
	report, err := reconciler.Run(context.Background(), RunOptions{FeedOrder: feedOrder(h)})
	if err != nil || report.Recovered != 1 || h.server.RequestCount("POST", "/v1/alerts") != 1 {
		t.Fatal("pending operation was not recovered idempotently")
	}
	active, _ := h.store.ListActiveDecisions(context.Background())
	open, _ := h.store.OpenOperations(context.Background())
	if len(active) != 1 || len(open) != 0 {
		t.Fatal("recovered operation state is incomplete")
	}
}

func TestOwnershipDriftBlocksDeletion(t *testing.T) {
	h := newHarness(t)
	h.snapshot(t, "feed-one", []feed.Entry{entry("8.8.8.0/24", network.KindRange)})
	reconciler := h.reconciler(t, 100)
	if _, err := reconciler.Run(context.Background(), RunOptions{FeedOrder: feedOrder(h)}); err != nil {
		t.Fatal("initial reconcile failed")
	}
	owned, _ := h.store.ListActiveDecisions(context.Background())
	alert, err := h.client.GetAlert(context.Background(), owned[0].AlertID)
	if err != nil {
		t.Fatal("unable to read seeded alert")
	}
	alert.MachineID = "foreign-machine"
	h.server.AddForeignAlert(alert)
	_, err = reconciler.Run(context.Background(), RunOptions{
		FeedOrder: feedOrder(h), Allowlists: []netip.Prefix{netip.MustParsePrefix("8.8.8.8/32")},
	})
	if err == nil || !IsCategory(err, ErrOwnership) || h.server.WasExpired(owned[0].DecisionID) {
		t.Fatal("ownership drift did not block deletion")
	}
	active, _ := h.store.ListActiveDecisions(context.Background())
	if len(active) != 1 {
		t.Fatal("ownership mismatch changed local active state")
	}
}

func TestReconcileBatchesLargeChanges(t *testing.T) {
	h := newHarness(t)
	entries := make([]feed.Entry, 0, 205)
	for index := 0; index < 205; index++ {
		address := netip.AddrFrom4([4]byte{11, 22, byte(index / 256), byte(index % 256)})
		entries = append(entries, feed.Entry{Prefix: netip.PrefixFrom(address, 32), Kind: network.KindIP})
	}
	h.snapshot(t, "feed-one", entries)
	reconciler := h.reconciler(t, 100)
	report, err := reconciler.Run(context.Background(), RunOptions{FeedOrder: feedOrder(h)})
	if err != nil || report.Added != 205 || h.server.RequestCount("POST", "/v1/alerts") != 3 {
		t.Fatal("large change was not processed in bounded batches")
	}
	for _, alert := range h.server.Alerts() {
		if len(alert.Decisions) > 100 {
			t.Fatal("batch size cap exceeded")
		}
	}
}
