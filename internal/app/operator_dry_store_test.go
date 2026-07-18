package app

import (
	"context"
	"errors"
	"testing"
	"time"

	"crowdshield/internal/network"
	"crowdshield/internal/state"
)

func TestEmptyOperatorStoreRejectsEveryMutator(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC)
	store := &emptyOperatorStore{}
	mutators := []struct {
		name string
		run  func() error
	}{
		{name: "ensure feeds", run: func() error { _, err := store.EnsureFeeds(ctx, nil, now); return err }},
		{name: "apply snapshot", run: func() error {
			_, err := store.ApplyFeedSnapshot(ctx, "feed-one", state.FeedSnapshot{}, 1, now)
			return err
		}},
		{name: "not modified", run: func() error { return store.RecordFeedNotModified(ctx, "feed-one", "", "", now) }},
		{name: "feed failure", run: func() error { return store.RecordFeedFailure(ctx, "feed-one", "", now, now) }},
		{name: "enforcement plan", run: func() error { _, err := store.ApplyEnforcementPlan(ctx, []network.Object{}, now); return err }},
		{name: "expire decision", run: func() error { return store.MarkDecisionExpired(ctx, 1, now) }},
		{name: "begin operation", run: func() error { return store.BeginOperation(ctx, state.Operation{}) }},
		{name: "record verified operation", run: func() error {
			_, err := store.RecordVerifiedOperation(ctx, "token", state.VerifiedAlert{}, now)
			return err
		}},
		{name: "complete operation", run: func() error { return store.CompleteOperation(ctx, "token", now) }},
		{name: "set operation status", run: func() error {
			return store.SetOperationStatus(ctx, "token", state.OperationAmbiguous, "category", now)
		}},
	}
	for _, tc := range mutators {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.run(); !errors.Is(err, errOperatorReadOnly) {
				t.Fatal("dry-run mutator was not blocked")
			}
		})
	}
}
