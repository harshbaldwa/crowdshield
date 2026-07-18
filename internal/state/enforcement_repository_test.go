package state

import (
	"context"
	"testing"
	"time"

	"crowdshield/internal/network"
)

func seedEnforcementPlan(t *testing.T, store *Store) ([]EnforcementRecord, []FeedRecord, time.Time) {
	t.Helper()
	ctx := context.Background()
	now := time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC)
	feeds, err := store.EnsureFeeds(ctx, testDefinitions(), now)
	if err != nil {
		t.Fatal("unable to seed feeds")
	}
	objects, _ := network.BuildDesired([]network.Candidate{
		{Prefix: storedEntry("8.8.8.0/24", network.KindRange).Prefix, Kind: network.KindRange, FeedID: feeds[0].ID, FeedName: feeds[0].Name, FeedOrder: 0},
		{Prefix: storedEntry("8.8.8.0/24", network.KindRange).Prefix, Kind: network.KindRange, FeedID: feeds[1].ID, FeedName: feeds[1].Name, FeedOrder: 1},
		{Prefix: storedEntry("9.9.9.9/32", network.KindIP).Prefix, Kind: network.KindIP, FeedID: feeds[0].ID, FeedName: feeds[0].Name, FeedOrder: 0},
	}, nil)
	records, err := store.ApplyEnforcementPlan(ctx, objects, now.Add(time.Minute))
	if err != nil {
		t.Fatal("unable to apply enforcement plan")
	}
	return records, feeds, now
}

func TestApplyEnforcementPlanPreservesSourcesAndMarksStale(t *testing.T) {
	store := openTestStore(t)
	records, _, now := seedEnforcementPlan(t, store)
	if len(records) != 2 {
		t.Fatal("unexpected enforcement object count")
	}
	var rangeRecord EnforcementRecord
	for _, record := range records {
		if record.Scope == network.ScopeRange {
			rangeRecord = record
		}
	}
	if rangeRecord.ID == 0 || len(rangeRecord.Sources) != 2 || !rangeRecord.Desired || rangeRecord.PrimaryFeedID == nil {
		t.Fatal("deduplicated provenance not persisted")
	}
	kept := []network.Object{{
		Prefix: records[0].Prefix, Scope: records[0].Scope, Desired: false, Suppression: network.SuppressedAllowlist,
		Primary: records[0].Sources[0], Contributors: records[0].Sources,
	}}
	updated, err := store.ApplyEnforcementPlan(context.Background(), kept, now.Add(2*time.Minute))
	if err != nil || len(updated) != 2 {
		t.Fatal("enforcement update failed")
	}
	var stale, allowlisted int
	for _, record := range updated {
		switch record.Suppression {
		case SuppressionStale:
			stale++
		case network.SuppressedAllowlist:
			allowlisted++
		}
	}
	if stale != 1 || allowlisted != 1 {
		t.Fatal("stale or allowlist state not persisted")
	}
}

func TestOperationJournalRecordsVerifiedOwnedDecisions(t *testing.T) {
	store := openTestStore(t)
	records, feeds, now := seedEnforcementPlan(t, store)
	items := make([]OperationItem, 0, len(records))
	for _, record := range records {
		items = append(items, OperationItem{ObjectID: record.ID})
	}
	operation := Operation{
		Token: stringsOf('a', 32), Kind: OperationCreate, FeedID: feeds[0].ID,
		Duration: 25 * time.Hour, PayloadHash: stringsOf('b', 64), Items: items, StartedAt: now.Add(2 * time.Minute),
	}
	if err := store.BeginOperation(context.Background(), operation); err != nil {
		t.Fatal("unable to begin operation")
	}
	pending, err := store.OpenOperations(context.Background())
	if err != nil || len(pending) != 1 || len(pending[0].Items) != len(items) {
		t.Fatal("pending operation is not recoverable")
	}
	verified := VerifiedAlert{
		AlertID: 42, MachineID: "crowdshield-test", Origin: "crowdshield", Scenario: "crowdshield/feed-one",
		Decisions: make([]VerifiedDecision, 0, len(records)),
	}
	for index, record := range records {
		value := record.Prefix.String()
		if record.Scope == network.ScopeIP {
			value = record.Prefix.Addr().String()
		}
		verified.Decisions = append(verified.Decisions, VerifiedDecision{
			ObjectID: record.ID, DecisionID: int64(100 + index), Origin: "crowdshield", Scenario: "crowdshield/feed-one",
			Scope: record.Scope, Value: value, ExpiresAt: now.Add(25 * time.Hour),
		})
	}
	decisions, err := store.RecordVerifiedOperation(context.Background(), operation.Token, verified, now.Add(3*time.Minute))
	if err != nil || len(decisions) != len(records) {
		t.Fatal("verified decisions not recorded")
	}
	if err := store.CompleteOperation(context.Background(), operation.Token, now.Add(4*time.Minute)); err != nil {
		t.Fatal("operation completion failed")
	}
	active, err := store.ListActiveDecisions(context.Background())
	if err != nil || len(active) != len(records) {
		t.Fatal("active owned decisions unavailable")
	}
	open, err := store.OpenOperations(context.Background())
	if err != nil || len(open) != 0 {
		t.Fatal("completed operation remained open")
	}
	again, err := store.RecordVerifiedOperation(context.Background(), operation.Token, verified, now.Add(5*time.Minute))
	if err != nil || len(again) != len(decisions) {
		t.Fatal("verified operation recording is not idempotent")
	}
}

func TestVerificationMismatchRollsBackWithoutAdoptingForeignDecision(t *testing.T) {
	store := openTestStore(t)
	records, feeds, now := seedEnforcementPlan(t, store)
	operation := Operation{
		Token: stringsOf('a', 32), Kind: OperationCreate, FeedID: feeds[0].ID, Duration: time.Hour,
		PayloadHash: stringsOf('b', 64), Items: []OperationItem{{ObjectID: records[0].ID}}, StartedAt: now,
	}
	if err := store.BeginOperation(context.Background(), operation); err != nil {
		t.Fatal("operation begin failed")
	}
	mismatch := VerifiedAlert{
		AlertID: 42, MachineID: "foreign-machine", Origin: "crowdshield", Scenario: "crowdshield/feed-one",
		Decisions: []VerifiedDecision{{
			ObjectID: records[0].ID, DecisionID: 100, Origin: "foreign", Scenario: "crowdshield/feed-one",
			Scope: records[0].Scope, Value: records[0].Prefix.String(), ExpiresAt: now.Add(time.Hour),
		}},
	}
	if _, err := store.RecordVerifiedOperation(context.Background(), operation.Token, mismatch, now.Add(time.Minute)); err == nil {
		t.Fatal("foreign ownership mismatch accepted")
	}
	active, err := store.ListActiveDecisions(context.Background())
	if err != nil || len(active) != 0 {
		t.Fatal("foreign decision was adopted after failed transaction")
	}
}

func TestRefreshLinksReplacementBeforeOldDecisionExpires(t *testing.T) {
	store := openTestStore(t)
	records, feeds, now := seedEnforcementPlan(t, store)
	object := records[0]
	create := Operation{Token: stringsOf('a', 32), Kind: OperationCreate, FeedID: feeds[0].ID, Duration: time.Hour, PayloadHash: stringsOf('b', 64), Items: []OperationItem{{ObjectID: object.ID}}, StartedAt: now}
	if err := store.BeginOperation(context.Background(), create); err != nil {
		t.Fatal("create begin failed")
	}
	value := object.Prefix.String()
	if object.Scope == network.ScopeIP {
		value = object.Prefix.Addr().String()
	}
	first, err := store.RecordVerifiedOperation(context.Background(), create.Token, VerifiedAlert{
		AlertID: 1, MachineID: "crowdshield-test", Origin: "crowdshield", Scenario: "crowdshield/feed-one",
		Decisions: []VerifiedDecision{{ObjectID: object.ID, DecisionID: 10, Origin: "crowdshield", Scenario: "crowdshield/feed-one", Scope: object.Scope, Value: value, ExpiresAt: now.Add(time.Hour)}},
	}, now.Add(time.Minute))
	if err != nil || len(first) != 1 {
		t.Fatal("initial decision recording failed")
	}
	if err := store.CompleteOperation(context.Background(), create.Token, now.Add(2*time.Minute)); err != nil {
		t.Fatal("create completion failed")
	}
	oldRow := first[0].ID
	refresh := Operation{Token: stringsOf('c', 32), Kind: OperationRefresh, FeedID: feeds[0].ID, Duration: 25 * time.Hour, PayloadHash: stringsOf('d', 64), Items: []OperationItem{{ObjectID: object.ID, OldDecisionRowID: &oldRow}}, StartedAt: now.Add(3 * time.Minute)}
	if err := store.BeginOperation(context.Background(), refresh); err != nil {
		t.Fatal("refresh begin failed")
	}
	second, err := store.RecordVerifiedOperation(context.Background(), refresh.Token, VerifiedAlert{
		AlertID: 2, MachineID: "crowdshield-test", Origin: "crowdshield", Scenario: "crowdshield/feed-one",
		Decisions: []VerifiedDecision{{ObjectID: object.ID, DecisionID: 11, Origin: "crowdshield", Scenario: "crowdshield/feed-one", Scope: object.Scope, Value: value, ExpiresAt: now.Add(25 * time.Hour)}},
	}, now.Add(4*time.Minute))
	if err != nil || len(second) != 1 {
		t.Fatal("replacement decision recording failed")
	}
	old, err := store.DecisionByRowID(context.Background(), oldRow)
	if err != nil || old.ReplacedByID == nil || *old.ReplacedByID != second[0].ID || old.Status != DecisionExpiring {
		t.Fatal("old decision was not linked after replacement verification")
	}
	if err := store.MarkDecisionExpired(context.Background(), oldRow, now.Add(5*time.Minute)); err != nil {
		t.Fatal("old decision expiration state failed")
	}
	old, _ = store.DecisionByRowID(context.Background(), oldRow)
	if old.Status != DecisionExpired {
		t.Fatal("old decision did not become expired")
	}
}
